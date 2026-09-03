//! Native runtime. One task owns the WireGuard peers and userspace TCP stack.
//! Application streams are bounded duplex pipes; TCP FIN is propagated independently
//! in each direction, and drain waits for outstanding packets before shutdown.
use crate::{
    derp,
    protocol::{self, ConnInfo, PrivateKey, Region},
};
use anyhow::{Context as _, Result, anyhow, bail};
use boringtun::noise::{Tunn, TunnResult};
use crypto_box::{
    PublicKey as BoxPublic, SalsaBox, SecretKey as BoxSecret,
    aead::{Aead, AeadCore, OsRng},
};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{self, State},
    time::Instant as SmolInstant,
    wire::{
        HardwareAddress, IpCidr, IpEndpoint, IpProtocol, Ipv6Packet, TcpControl, TcpPacket, TcpRepr,
    },
};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    net::UdpSocket,
    sync::{mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;

pub type TcpHandler =
    Arc<dyn Fn(DuplexStream) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;
type PortHandler = Arc<dyn Fn(u16) -> Option<TcpHandler> + Send + Sync>;
type ForwardHandler = Arc<dyn Fn(SocketAddr) -> Option<TcpHandler> + Send + Sync>;
const BUFFER_SIZE: usize = 256 * 1024;
// A TCP window can arrive as a burst of encrypted UDP packets. Small socket
// defaults drop these bursts before the actor can receive them.
const UDP_RECEIVE_BUFFER_SIZE: usize = 512 * 1024;
const MAX_PEERS: usize = 1024;
// Each stream has two TCP buffers and two bounded application buffers (1 MiB).
// Include half-open connections in this budget so SYN floods cannot allocate GiB.
const MAX_CONNECTIONS: usize = 256;
const MAX_CANDIDATES: usize = 32;
const MAX_PENDING_PINGS: usize = 128;
const DISCO_MAGIC: &[u8] = b"TS\xf0\x9f\x92\xac";

#[derive(Default, Clone)]
pub struct ServerConfig {
    pub key: Option<PrivateKey>,
    pub region: Option<Region>,
    pub region_id: i64,
    pub derp_map_url: Option<String>,
    pub allowed_clients: Vec<[u8; 32]>,
    pub on_tcp: Option<PortHandler>,
    pub on_tcp_forward: Option<ForwardHandler>,
    pub served_tcp_ports: Option<Vec<(u16, u16)>>,
}

#[derive(Debug, Clone)]
pub struct PingResult {
    pub latency: Duration,
    pub endpoint: Option<SocketAddr>,
    pub derp_region_id: i64,
}

/// A consistent snapshot taken by the task that owns the network stack.
#[derive(Debug, Clone)]
pub struct RuntimeStatus {
    pub address: Ipv6Addr,
    pub public_key: [u8; 32],
    pub derp_region_id: i64,
    pub active_tcp_connections: usize,
    pub peers: Vec<PeerStatus>,
}

#[derive(Debug, Clone)]
pub struct PeerStatus {
    pub public_key: [u8; 32],
    pub address: Ipv6Addr,
    pub direct_endpoint: Option<SocketAddr>,
    pub handshake_age: Option<Duration>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

struct Handle {
    commands: mpsc::Sender<Command>,
    cancel: CancellationToken,
}
impl Handle {
    async fn status(&self) -> Result<RuntimeStatus> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Status(tx))
            .await
            .map_err(|_| anyhow!("tailcat is closed"))?;
        rx.await.context("tailcat closed before providing status")
    }
    async fn drain(&self, timeout: Duration) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Drain(tx))
            .await
            .map_err(|_| anyhow!("tailcat is closed"))?;
        tokio::time::timeout(timeout, rx)
            .await
            .context("timed out draining TCP")??;
        // Let the final FIN acknowledgement reach the relay writer.
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(())
    }
    async fn close(&self) {
        self.cancel.cancel();
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub struct Server {
    handle: Handle,
    info: ConnInfo,
}
impl Server {
    pub async fn start(mut config: ServerConfig) -> Result<Self> {
        let key = config.key.clone().unwrap_or_default();
        let mut info = ConnInfo {
            server_public: key.public(),
            server_disco_public: Some(key.disco_public()),
            region: config.region.clone().into_iter().collect(),
            region_id: if config.region_id == 0 {
                -1
            } else {
                config.region_id
            },
        };
        info.expand(config.derp_map_url.as_deref(), true).await?;
        let region = info
            .region
            .first()
            .context("server has no DERP region")?
            .clone();
        config.region = Some(region.clone());
        let handle = Actor::start(key, region, Some(config), None).await?;
        Ok(Self { handle, info })
    }
    pub fn tailcat_addr(&self) -> String {
        self.info.addr().expect("server connection info is valid")
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.info.server_public
    }
    pub fn addr(&self) -> Ipv6Addr {
        protocol::tc_addr_for_key(&self.info.server_public)
    }
    pub fn region(&self) -> &Region {
        &self.info.region[0]
    }
    pub async fn status(&self) -> Result<RuntimeStatus> {
        self.handle.status().await
    }
    pub async fn drain_tcp(&self, timeout: Duration) -> Result<()> {
        self.handle.drain(timeout).await
    }
    pub async fn close(&self) {
        self.handle.close().await;
    }
    pub async fn add_allowed_client(&self, key: [u8; 32]) -> Result<()> {
        self.handle
            .commands
            .send(Command::Allow(key))
            .await
            .map_err(|_| anyhow!("server is closed"))
    }
}

pub struct Client {
    handle: Handle,
    public_key: [u8; 32],
    server_addr: Ipv6Addr,
}
impl Client {
    pub async fn connect(
        addr: &str,
        key: Option<PrivateKey>,
        derp_map_url: Option<&str>,
    ) -> Result<Self> {
        let mut info = protocol::parse_addr(addr)?;
        if info.server_disco_public.is_none_or(|k| k == [0; 32]) {
            bail!(
                "legacy tailcat address lacks a separate disco key; generate a new address with an updated tailcat server"
            );
        }
        info.expand(derp_map_url, false).await?;
        if info.region.len() != 1 {
            bail!("tailcat address must specify exactly one DERP region");
        }
        if info.server_public == [0; 32] {
            bail!("tailcat address has a zero server public key");
        }
        let key = key.unwrap_or_default();
        let public_key = key.public();
        let server_addr = protocol::tc_addr_for_key(&info.server_public);
        let handle = Actor::start(key, info.region[0].clone(), None, Some(info)).await?;
        let client = Self {
            handle,
            public_key,
            server_addr,
        };
        client.ping().await?;
        Ok(client)
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
    pub fn server_addr(&self) -> Ipv6Addr {
        self.server_addr
    }
    pub async fn status(&self) -> Result<RuntimeStatus> {
        self.handle.status().await
    }
    pub async fn ping(&self) -> Result<Duration> {
        Ok(self.do_ping(false).await?.latency)
    }
    pub async fn disco_ping(&self) -> Result<PingResult> {
        self.do_ping(true).await
    }
    async fn do_ping(&self, disco: bool) -> Result<PingResult> {
        let (tx, rx) = oneshot::channel();
        self.handle
            .commands
            .send(Command::Ping { disco, result: tx })
            .await
            .map_err(|_| anyhow!("client is closed"))?;
        tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .context("ping timed out")??
    }
    pub async fn dial_tcp_port(&self, port: u16) -> Result<DuplexStream> {
        self.dial_tcp(SocketAddr::new(self.server_addr.into(), port))
            .await
    }
    pub async fn dial_tcp(&self, addr: SocketAddr) -> Result<DuplexStream> {
        let (tx, rx) = oneshot::channel();
        self.handle
            .commands
            .send(Command::Dial {
                target: to_ipv6(addr),
                result: tx,
            })
            .await
            .map_err(|_| anyhow!("client is closed"))?;
        tokio::time::timeout(Duration::from_secs(20), rx)
            .await
            .context("TCP connection timed out")??
    }
    pub async fn drain_tcp(&self, timeout: Duration) -> Result<()> {
        self.handle.drain(timeout).await
    }
    pub async fn close(&self) {
        self.handle.close().await;
    }
}

fn to_ipv6(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(_) => addr,
        IpAddr::V4(ip) => {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&[0, 0x64, 0xff, 0x9b]);
            bytes[12..].copy_from_slice(&ip.octets());
            SocketAddr::new(Ipv6Addr::from(bytes).into(), addr.port())
        }
    }
}
fn from_ipv6(addr: SocketAddr) -> SocketAddr {
    if let IpAddr::V6(ip) = addr.ip() {
        let bytes = ip.octets();
        if bytes[..12] == [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0] {
            return SocketAddr::new(
                Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]).into(),
                addr.port(),
            );
        }
    }
    addr
}

enum Command {
    Status(oneshot::Sender<RuntimeStatus>),
    Dial {
        target: SocketAddr,
        result: oneshot::Sender<Result<DuplexStream>>,
    },
    Ping {
        disco: bool,
        result: oneshot::Sender<Result<PingResult>>,
    },
    Drain(oneshot::Sender<()>),
    Allow([u8; 32]),
}
struct Link {
    socket: SocketHandle,
    // A listening smoltcp socket has no remote endpoint until it accepts its
    // SYN. Remember the intended flow now to deduplicate retransmissions.
    flow: (IpEndpoint, IpEndpoint),
    pipe: DuplexStream,
    app: Option<DuplexStream>,
    connected: Option<oneshot::Sender<Result<DuplexStream>>>,
    handler: Option<TcpHandler>,
    write_closed: bool,
    read_closed: bool,
    started: Instant,
}
struct Peer {
    key: [u8; 32],
    disco_key: [u8; 32],
    tunnel: Tunn,
    direct: Option<(SocketAddr, Instant)>,
    candidates: Vec<SocketAddr>,
}
struct PendingPing {
    started: Instant,
    sent: Instant,
    disco: bool,
    txid: [u8; 12],
    result: oneshot::Sender<Result<PingResult>>,
}

struct Actor {
    key: PrivateKey,
    local: Ipv6Addr,
    region: Region,
    config: Option<ServerConfig>,
    server: Option<[u8; 32]>,
    peers: HashMap<[u8; 32], Peer>,
    device: PacketDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    links: Vec<Link>,
    commands: mpsc::Receiver<Command>,
    cancel: CancellationToken,
    relay: derp::DerpConnection,
    udp: Arc<UdpSocket>,
    udp6: Option<Arc<UdpSocket>>,
    endpoints: Vec<SocketAddr>,
    next_port: u16,
    start: Instant,
    last_timers: Instant,
    last_advertise: Instant,
    pings: Vec<PendingPing>,
    // Transactions bind a direct-path candidate to an authenticated pong.
    probes: HashMap<[u8; 12], ([u8; 32], SocketAddr, Instant)>,
    drains: Vec<oneshot::Sender<()>>,
    stun_txid: [u8; 12],
}
impl Actor {
    async fn start(
        key: PrivateKey,
        region: Region,
        config: Option<ServerConfig>,
        server: Option<ConnInfo>,
    ) -> Result<Handle> {
        let (mut actor, handle) = Self::new(key, region, config, server).await?;
        actor.send_stun().await;
        tokio::spawn(async move {
            actor.run().await;
        });
        Ok(handle)
    }

    async fn new(
        key: PrivateKey,
        region: Region,
        config: Option<ServerConfig>,
        server: Option<ConnInfo>,
    ) -> Result<(Self, Handle)> {
        let relay = derp::connect(&key, &region, config.is_some()).await?;
        let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        configure_udp_receive_buffer(&udp).context("configure IPv4 UDP receive buffer")?;
        let port = udp.local_addr()?.port();
        let udp6 = bind_udp6(port).ok().map(Arc::new);
        if let Some(socket) = &udp6 {
            configure_udp_receive_buffer(socket).context("configure IPv6 UDP receive buffer")?;
        }
        let mut endpoints = Vec::new();
        if let Ok(interfaces) = if_addrs::get_if_addrs() {
            for iface in interfaces {
                let ip = iface.ip();
                if !ip.is_unspecified()
                    && !ip.is_multicast()
                    && match ip {
                        IpAddr::V4(_) => true,
                        IpAddr::V6(ip) => udp6.is_some() && !ip.is_unicast_link_local(),
                    }
                {
                    remember_endpoint(&mut endpoints, SocketAddr::new(ip, port));
                }
            }
        }
        let local = protocol::tc_addr_for_key(&key.public());
        let mut device = PacketDevice::default();
        let mut iface_config = Config::new(HardwareAddress::Ip);
        iface_config.random_seed = rand::random();
        let mut iface = Interface::new(iface_config, &mut device, SmolInstant::from_millis(0));
        iface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new(local.into(), 128)).unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv6_route(local)
            .map_err(|e| anyhow!("route: {e:?}"))?;
        iface.set_any_ip(config.is_some());
        let (tx, commands) = mpsc::channel(128);
        let cancel = CancellationToken::new();
        let mut actor = Self {
            key,
            local,
            region,
            config,
            server: server.as_ref().map(|s| s.server_public),
            peers: HashMap::new(),
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            links: vec![],
            commands,
            cancel: cancel.clone(),
            relay,
            udp,
            udp6,
            endpoints,
            next_port: 32768,
            start: Instant::now(),
            last_timers: Instant::now(),
            last_advertise: Instant::now() - Duration::from_secs(60),
            pings: vec![],
            probes: HashMap::new(),
            drains: vec![],
            stun_txid: rand::random(),
        };
        if let Some(info) = server {
            actor.add_peer(info.server_public, info.server_disco_public.unwrap());
        }
        Ok((
            actor,
            Handle {
                commands: tx,
                cancel,
            },
        ))
    }
    fn add_peer(&mut self, key: [u8; 32], disco_key: [u8; 32]) {
        if self.peers.contains_key(&key)
            || self.peers.len() >= MAX_PEERS
            || key == [0; 32]
            || disco_key == [0; 32]
        {
            return;
        }
        let index = (self.peers.len() + 1) as u32;
        let tunnel = Tunn::new(self.key.0.into(), key.into(), None, Some(25), index, None);
        self.peers.insert(
            key,
            Peer {
                key,
                disco_key,
                tunnel,
                direct: None,
                candidates: vec![],
            },
        );
    }
    async fn run(&mut self) {
        let mut interval = tokio::time::interval(Duration::from_millis(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut udp_buf = vec![0; 65536];
        let mut udp6_buf = vec![0; 65536];
        let udp6 = self.udp6.clone();
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                Some(command) = self.commands.recv() => self.command(command).await,
                packet = self.relay.incoming.recv() => {
                    match packet { Some((key,data)) => self.incoming(key, data, None).await, None => break }
                }
                packet = self.udp.recv_from(&mut udp_buf) => {
                    if let Ok((n,source)) = packet { self.udp_packet(&udp_buf[..n],source).await; }
                }
                packet = async { match &udp6 {Some(socket)=>socket.recv_from(&mut udp6_buf).await,None=>std::future::pending().await} } => {
                    if let Ok((n,source)) = packet { self.udp_packet(&udp6_buf[..n],source).await; }
                }
                _ = interval.tick() => {}
            }
            self.tick().await;
        }
    }
    async fn command(&mut self, command: Command) {
        match command {
            Command::Status(result) => {
                let _ = result.send(self.status());
            }
            Command::Dial { target, result } => {
                if result.is_closed() {
                    return;
                }
                if self.links.len() >= MAX_CONNECTIONS {
                    let _ = result.send(Err(anyhow!("too many connections")));
                    return;
                }
                let mut socket = new_socket();
                let port = self.next_port;
                self.next_port = if port == u16::MAX { 32768 } else { port + 1 };
                let target =
                    IpEndpoint::new(protocol::nat64_addr(target.ip()).into(), target.port());
                if let Err(e) = socket.connect(
                    self.iface.context(),
                    target,
                    IpEndpoint::new(self.local.into(), port),
                ) {
                    let _ = result.send(Err(anyhow!("TCP connect: {e:?}")));
                    return;
                }
                let (app, pipe) = tokio::io::duplex(BUFFER_SIZE);
                let socket = self.sockets.add(socket);
                self.links.push(Link {
                    socket,
                    flow: (IpEndpoint::new(self.local.into(), port), target),
                    pipe,
                    app: Some(app),
                    connected: Some(result),
                    handler: None,
                    write_closed: false,
                    read_closed: false,
                    started: Instant::now(),
                });
                self.advertise().await;
            }
            Command::Ping { disco, result } => {
                if result.is_closed() {
                    return;
                }
                self.pings.retain(|ping| !ping.result.is_closed());
                if self.pings.len() >= MAX_PENDING_PINGS {
                    let _ = result.send(Err(anyhow!("too many pending pings")));
                    return;
                }
                let mut p = PendingPing {
                    started: Instant::now(),
                    sent: Instant::now(),
                    disco,
                    txid: rand::random(),
                    result,
                };
                self.send_ping(&mut p).await;
                self.pings.push(p);
                if disco {
                    self.advertise().await;
                }
            }
            Command::Drain(tx) => self.drains.push(tx),
            Command::Allow(key) => {
                if let Some(c) = &mut self.config
                    && !c.allowed_clients.contains(&key)
                {
                    c.allowed_clients.push(key);
                }
            }
        }
    }
    fn status(&self) -> RuntimeStatus {
        let mut peers = self
            .peers
            .values()
            .map(|peer| {
                let (handshake_age, tx_bytes, rx_bytes, _, _) = peer.tunnel.stats();
                PeerStatus {
                    public_key: peer.key,
                    address: protocol::tc_addr_for_key(&peer.key),
                    direct_endpoint: peer
                        .direct
                        .filter(|(_, when)| when.elapsed() < Duration::from_secs(15))
                        .map(|(endpoint, _)| endpoint),
                    handshake_age,
                    tx_bytes: tx_bytes as u64,
                    rx_bytes: rx_bytes as u64,
                }
            })
            .collect::<Vec<_>>();
        peers.sort_by_key(|peer| peer.public_key);
        RuntimeStatus {
            address: self.local,
            public_key: self.key.public(),
            derp_region_id: self.region.region_id,
            active_tcp_connections: self
                .links
                .iter()
                .filter(|link| {
                    !matches!(
                        self.sockets.get::<tcp::Socket>(link.socket).state(),
                        State::Closed | State::TimeWait
                    )
                })
                .count(),
            peers,
        }
    }
    async fn send_ping(&mut self, ping: &mut PendingPing) {
        let Some(key) = self.server else {
            return;
        };
        ping.sent = Instant::now();
        if ping.disco {
            let mut data = vec![1, 0];
            data.extend_from_slice(&ping.txid);
            data.extend_from_slice(&self.key.public());
            if let Some(peer) = self.peers.get(&key)
                && let Ok(frame) = seal_disco(&self.key, &peer.disco_key, &data)
            {
                self.send_packet(key, frame).await;
            }
        } else {
            let mut data = b"meow\x01".to_vec();
            data.extend_from_slice(&self.key.public());
            data.extend_from_slice(&self.key.disco_public());
            let _ = self.relay.outgoing.try_send((key, data));
        }
    }
    async fn incoming(&mut self, key: [u8; 32], data: Vec<u8>, source: Option<SocketAddr>) {
        if data.starts_with(b"meow") {
            if source.is_some() {
                return;
            }
            if let Some(config) = &self.config {
                if data.len() >= 69
                    && data[4] == 1
                    && data[5..37] == key
                    && data[37..69] != [0; 32]
                    && (config.allowed_clients.is_empty() || config.allowed_clients.contains(&key))
                {
                    let disco = data[37..69].try_into().unwrap();
                    self.add_peer(key, disco);
                    if self.peers.contains_key(&key) {
                        let _ = self.relay.outgoing.try_send((key, b"meow\x02".to_vec()));
                        self.advertise().await;
                    }
                }
            } else if Some(key) == self.server && data.len() >= 5 && data[4] == 2 {
                let mut i = 0;
                while i < self.pings.len() {
                    if !self.pings[i].disco {
                        let p = self.pings.remove(i);
                        let _ = p.result.send(Ok(PingResult {
                            latency: p.started.elapsed(),
                            endpoint: None,
                            derp_region_id: self.region.region_id,
                        }));
                    } else {
                        i += 1;
                    }
                }
            }
            return;
        }
        if data.starts_with(DISCO_MAGIC) {
            self.disco_packet(key, &data, source).await;
            return;
        }
        if !self.peers.contains_key(&key) {
            return;
        }
        let mut buf = vec![0; 65536];
        let mut packet = data.as_slice();
        loop {
            let result = self.peers.get_mut(&key).unwrap().tunnel.decapsulate(
                source.map(|s| s.ip()),
                packet,
                &mut buf,
            );
            match result {
                TunnResult::WriteToNetwork(b) => {
                    let out = b.to_vec();
                    self.send_packet(key, out).await;
                }
                TunnResult::WriteToTunnelV6(b, _) => {
                    let b = b.to_vec();
                    if b.len() >= 40
                        && (self.config.is_none()
                            || b[8..24] == protocol::tc_addr_for_key(&key).octets())
                    {
                        self.receive_ip(b);
                    }
                }
                TunnResult::Err(e) => {
                    tracing::trace!(?e, "WireGuard packet rejected");
                    break;
                }
                _ => break,
            }
            packet = &[];
        }
    }
    fn receive_ip(&mut self, packet: Vec<u8>) {
        let Ok(ip) = Ipv6Packet::new_checked(packet.as_slice()) else {
            return;
        };
        if ip.version() != 6 {
            return;
        }
        if let Some(config) = &self.config {
            let dest = ip.dst_addr();
            if ip.next_header() == IpProtocol::Tcp {
                let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else {
                    return;
                };
                // Parse with the same validation as the network stack before
                // allocating buffers or invoking user-supplied port handlers.
                // This checks lengths, flags, options, ports, and checksum.
                let Ok(tcp) = TcpRepr::parse(
                    &tcp,
                    &ip.src_addr().into(),
                    &dest.into(),
                    &ChecksumCapabilities::default(),
                ) else {
                    return;
                };
                let sport = tcp.src_port;
                let port = tcp.dst_port;
                if dest == self.local
                    && config
                        .served_tcp_ports
                        .as_ref()
                        .is_some_and(|ports| !ports.iter().any(|(a, b)| *a <= port && port <= *b))
                {
                    return;
                }
                if tcp.control == TcpControl::Syn && tcp.ack_number.is_none() {
                    let flow = (
                        IpEndpoint::new(dest.into(), port),
                        IpEndpoint::new(ip.src_addr().into(), sport),
                    );
                    let duplicate = self.links.iter().any(|link| link.flow == flow);
                    if !duplicate && self.links.len() < MAX_CONNECTIONS {
                        let handler = if dest == self.local {
                            config.on_tcp.as_ref().and_then(|f| f(port))
                        } else {
                            config
                                .on_tcp_forward
                                .as_ref()
                                .and_then(|f| f(from_ipv6(SocketAddr::new(dest.into(), port))))
                        };
                        if let Some(handler) = handler {
                            let mut socket = new_socket();
                            if socket.listen(IpEndpoint::new(dest.into(), port)).is_ok() {
                                let (app, pipe) = tokio::io::duplex(BUFFER_SIZE);
                                let socket = self.sockets.add(socket);
                                self.links.push(Link {
                                    socket,
                                    flow,
                                    pipe,
                                    app: Some(app),
                                    connected: None,
                                    handler: Some(handler),
                                    write_closed: false,
                                    read_closed: false,
                                    started: Instant::now(),
                                });
                            }
                        }
                    }
                }
            } else if dest != self.local {
                return;
            }
        }
        self.device.incoming.push_back(packet);
    }
    async fn send_packet(&self, key: [u8; 32], packet: Vec<u8>) {
        if let Some((endpoint, when)) = self.peers.get(&key).and_then(|p| p.direct)
            && when.elapsed() < Duration::from_secs(15)
            && self.send_udp(&packet, endpoint).await.is_ok()
        {
            return;
        }
        // DERP is best effort. Never block the actor on a congested relay queue;
        // TCP/WireGuard retransmit dropped packets.
        let _ = self.relay.outgoing.try_send((key, packet));
    }
    async fn tick(&mut self) {
        let now = SmolInstant::from_millis(self.start.elapsed().as_millis() as i64);
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.poll_links();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        while let Some(packet) = self.device.outgoing.pop_front() {
            if packet.len() < 40 {
                continue;
            }
            let target = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
            let key = self.server.or_else(|| {
                self.peers
                    .keys()
                    .find(|k| protocol::tc_addr_for_key(k) == target)
                    .copied()
            });
            if let Some(key) = key {
                let mut buf = vec![0; 65536];
                if let TunnResult::WriteToNetwork(b) = self
                    .peers
                    .get_mut(&key)
                    .unwrap()
                    .tunnel
                    .encapsulate(&packet, &mut buf)
                {
                    self.send_packet(key, b.to_vec()).await;
                }
            }
        }
        if self.last_timers.elapsed() >= Duration::from_millis(250) {
            self.last_timers = Instant::now();
            for key in self.peers.keys().copied().collect::<Vec<_>>() {
                let mut buf = vec![0; 65536];
                if let TunnResult::WriteToNetwork(b) = self
                    .peers
                    .get_mut(&key)
                    .unwrap()
                    .tunnel
                    .update_timers(&mut buf)
                {
                    self.send_packet(key, b.to_vec()).await;
                }
            }
            let mut pending = std::mem::take(&mut self.pings);
            for mut p in pending.drain(..) {
                if p.result.is_closed() {
                    continue;
                }
                if p.started.elapsed() > Duration::from_secs(10) {
                    let _ = p.result.send(Err(anyhow!("ping timed out")));
                    continue;
                }
                if p.sent.elapsed() >= Duration::from_secs(1) {
                    self.send_ping(&mut p).await;
                }
                self.pings.push(p);
            }
            self.probes
                .retain(|_, (_, _, t)| t.elapsed() < Duration::from_secs(10));
        }
        if self.last_advertise.elapsed() > Duration::from_secs(5) {
            self.advertise().await;
            self.send_stun().await;
        }
        if !self.drains.is_empty()
            && self.links.iter().all(|l| {
                matches!(
                    self.sockets.get::<tcp::Socket>(l.socket).state(),
                    State::Closed | State::TimeWait | State::FinWait2
                )
            })
            && self.device.outgoing.is_empty()
        {
            for tx in self.drains.drain(..) {
                let _ = tx.send(());
            }
        }
    }
    fn poll_links(&mut self) {
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        let mut remove = Vec::new();
        for (index, link) in self.links.iter_mut().enumerate() {
            let socket = self.sockets.get_mut::<tcp::Socket>(link.socket);
            if matches!(socket.state(), State::Established | State::CloseWait)
                && let Some(app) = link.app.take()
            {
                if let Some(result) = link.connected.take() {
                    if result.send(Ok(app)).is_err() {
                        socket.abort();
                    }
                } else if let Some(handler) = link.handler.take() {
                    tokio::spawn(handler(app));
                }
            }
            if link.connected.as_ref().is_some_and(|r| r.is_closed()) {
                socket.abort();
            }
            if link.app.is_some() && link.started.elapsed() > Duration::from_secs(20) {
                socket.abort();
            }
            if socket.can_send() && !link.write_closed && link.app.is_none() {
                let available = (socket.send_capacity() - socket.send_queue()).min(16384);
                let mut data = vec![0; available];
                let mut buf = ReadBuf::new(&mut data);
                match Pin::new(&mut link.pipe).poll_read(&mut cx, &mut buf) {
                    Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                        link.write_closed = true;
                        socket.close();
                    }
                    Poll::Ready(Ok(())) => {
                        let _ = socket.send_slice(buf.filled());
                    }
                    Poll::Ready(Err(_)) => {
                        socket.abort();
                    }
                    Poll::Pending => {}
                }
            }
            if socket.can_recv() && link.app.is_none() {
                let _ =
                    socket.recv(
                        |data| match Pin::new(&mut link.pipe).poll_write(&mut cx, data) {
                            Poll::Ready(Ok(n)) => (n, ()),
                            Poll::Ready(Err(_)) => {
                                link.read_closed = true;
                                (data.len(), ())
                            }
                            Poll::Pending => (0, ()),
                        },
                    );
            }
            if !socket.may_recv()
                && !link.read_closed
                && link.app.is_none()
                && Pin::new(&mut link.pipe).poll_shutdown(&mut cx).is_ready()
            {
                link.read_closed = true;
            }
            // The TCP close handshake can finish while received bytes are
            // still queued behind a full application pipe. Preserve them until
            // the application drains them (or drops its read side).
            if socket.state() == State::Closed && (!socket.can_recv() || link.read_closed) {
                if let Some(result) = link.connected.take() {
                    let _ = result.send(Err(anyhow!("TCP connection refused or closed")));
                }
                remove.push(index);
            }
        }
        for index in remove.into_iter().rev() {
            let link = self.links.swap_remove(index);
            self.sockets.remove(link.socket);
        }
    }
    async fn advertise(&mut self) {
        self.last_advertise = Instant::now();
        let mut payload = vec![3, 0];
        for endpoint in &self.endpoints {
            payload.extend_from_slice(&ip16(endpoint.ip()));
            payload.extend_from_slice(&endpoint.port().to_be_bytes());
        }
        let keys = self.peers.keys().copied().collect::<Vec<_>>();
        for key in keys {
            let peer = &self.peers[&key];
            if let Ok(packet) = seal_disco(&self.key, &peer.disco_key, &payload) {
                let _ = self.relay.outgoing.try_send((key, packet));
            }
            let candidates = peer.candidates.clone();
            for endpoint in candidates {
                self.probe(key, endpoint).await;
            }
        }
    }
    async fn probe(&mut self, key: [u8; 32], endpoint: SocketAddr) {
        if !usable_endpoint(endpoint) {
            return;
        }
        let txid: [u8; 12] = rand::random();
        let mut data = vec![1, 0];
        data.extend_from_slice(&txid);
        data.extend_from_slice(&self.key.public());
        if let Some(peer) = self.peers.get(&key)
            && let Ok(packet) = seal_disco(&self.key, &peer.disco_key, &data)
            && self.probes.len() < 4096
        {
            self.probes.insert(txid, (key, endpoint, Instant::now()));
            let _ = self.send_udp(&packet, endpoint).await;
        }
    }
    async fn disco_packet(&mut self, key: [u8; 32], packet: &[u8], source: Option<SocketAddr>) {
        let Some(peer) = self.peers.get(&key) else {
            return;
        };
        if packet.len() < 78 || packet[6..38] != peer.disco_key {
            return;
        }
        let Ok(data) = open_disco(&self.key, &peer.disco_key, packet) else {
            return;
        };
        if data.len() < 2 || data[1] != 0 || source.is_some_and(|s| !usable_endpoint(s)) {
            return;
        }
        match data[0] {
            1 if data.len() >= 14 => {
                let mut pong = vec![2, 0];
                pong.extend_from_slice(&data[2..14]);
                let endpoint =
                    source.unwrap_or_else(|| SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0));
                pong.extend_from_slice(&ip16(endpoint.ip()));
                pong.extend_from_slice(&endpoint.port().to_be_bytes());
                if let Ok(frame) = seal_disco(&self.key, &peer.disco_key, &pong) {
                    if let Some(src) = source {
                        let _ = self.send_udp(&frame, src).await;
                    } else {
                        let _ = self.relay.outgoing.try_send((key, frame));
                    }
                }
                // Responding to a ping is not enough to trust its source. Probe it
                // ourselves to establish bidirectional reachability.
                if let Some(src) = source
                    && remember_endpoint(&mut self.peers.get_mut(&key).unwrap().candidates, src)
                {
                    self.probe(key, src).await;
                }
            }
            2 if data.len() >= 32 => {
                let txid: [u8; 12] = data[2..14].try_into().unwrap();
                if let Some((expected, endpoint, sent)) = self.probes.get(&txid)
                    && *expected == key
                    && source == Some(*endpoint)
                    && sent.elapsed() < Duration::from_secs(10)
                {
                    let endpoint = *endpoint;
                    self.probes.remove(&txid);
                    self.peers.get_mut(&key).unwrap().direct = Some((endpoint, Instant::now()));
                }
                if let Some(index) = self.pings.iter().position(|p| p.disco && p.txid == txid) {
                    let p = self.pings.remove(index);
                    let _ = p.result.send(Ok(PingResult {
                        latency: p.started.elapsed(),
                        endpoint: source,
                        derp_region_id: self.region.region_id,
                    }));
                }
            }
            3 if source.is_none() && (data.len() - 2).is_multiple_of(18) => {
                let announced = data[2..].chunks_exact(18).map(|p| {
                    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&p[..16]).unwrap());
                    SocketAddr::new(
                        ip.to_ipv4_mapped()
                            .map(IpAddr::V4)
                            .unwrap_or(IpAddr::V6(ip)),
                        u16::from_be_bytes([p[16], p[17]]),
                    )
                });
                let mut endpoints = Vec::new();
                for endpoint in announced.take(MAX_CANDIDATES) {
                    remember_endpoint(&mut endpoints, endpoint);
                }
                self.peers.get_mut(&key).unwrap().candidates = endpoints.clone();
                for endpoint in endpoints {
                    self.probe(key, endpoint).await;
                }
            }
            _ => {}
        }
    }
    async fn udp_packet(&mut self, data: &[u8], source: SocketAddr) {
        if data.len() >= 20
            && data[0..2] == [1, 1]
            && data[4..8] == [0x21, 0x12, 0xa4, 0x42]
            && data[8..20] == self.stun_txid
        {
            if let Some(endpoint) = parse_stun(data)
                && remember_endpoint(&mut self.endpoints, endpoint)
            {
                self.last_advertise = Instant::now() - Duration::from_secs(60);
            }
            return;
        }
        if data.starts_with(DISCO_MAGIC) && data.len() >= 38 {
            if let Some(key) = self
                .peers
                .values()
                .find(|p| p.disco_key == data[6..38])
                .map(|p| p.key)
            {
                self.incoming(key, data.to_vec(), Some(source)).await;
            }
        } else {
            let keys = self
                .peers
                .iter()
                .filter(|(_, p)| {
                    p.direct.is_some_and(|(ep, _)| ep == source) || p.candidates.contains(&source)
                })
                .map(|(k, _)| *k)
                .collect::<Vec<_>>();
            // DERP-authenticated registration bounds this trial set. BoringTun
            // verifies the WireGuard MAC and peer identity before yielding IP.
            for key in keys {
                self.incoming(key, data.to_vec(), Some(source)).await;
            }
        }
    }
    async fn send_stun(&self) {
        let mut packet = vec![0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42];
        packet.extend_from_slice(&self.stun_txid);
        for node in self.region.nodes.iter().take(3) {
            if node.stun_port < 0 {
                continue;
            }
            let port = if node.stun_port == 0 {
                3478
            } else {
                node.stun_port as u16
            };
            let host = if !node.ipv4.is_empty() && node.ipv4 != "none" {
                node.ipv4.as_str()
            } else {
                node.host_name.as_str()
            };
            // Only known relay nodes are queried; DNS resolution occurs outside
            // the packet actor and never involves the secret tailcat address.
            let udp = self.udp.clone();
            let host = host.to_string();
            let packet = packet.clone();
            tokio::spawn(async move {
                if let Ok(Ok(mut ips)) = tokio::time::timeout(
                    Duration::from_secs(2),
                    tokio::net::lookup_host((host.as_str(), port)),
                )
                .await
                    && let Some(addr) = ips.find(SocketAddr::is_ipv4)
                {
                    let _ = udp.send_to(&packet, addr).await;
                }
            });
        }
    }

    async fn send_udp(&self, data: &[u8], endpoint: SocketAddr) -> std::io::Result<usize> {
        if endpoint.is_ipv4() {
            self.udp.send_to(data, endpoint).await
        } else if let Some(socket) = &self.udp6 {
            socket.send_to(data, endpoint).await
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "IPv6 is unavailable",
            ))
        }
    }
}

fn usable_endpoint(endpoint: SocketAddr) -> bool {
    let ip = match endpoint.ip() {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    };
    endpoint.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != IpAddr::V4(Ipv4Addr::BROADCAST)
}

/// Retain recent authenticated endpoint candidates, including NAT rebinding,
/// without letting an untrusted peer grow a per-peer vector without limit.
fn remember_endpoint(endpoints: &mut Vec<SocketAddr>, endpoint: SocketAddr) -> bool {
    if !usable_endpoint(endpoint) || endpoints.contains(&endpoint) {
        return false;
    }
    if endpoints.len() == MAX_CANDIDATES {
        endpoints.remove(0);
    }
    endpoints.push(endpoint);
    true
}

fn configure_udp_receive_buffer(socket: &UdpSocket) -> std::io::Result<()> {
    let socket = socket2::SockRef::from(socket);
    // Preserve larger defaults. The OS may clamp this request or account for
    // buffer space differently, so do not require an exact reported size.
    if socket.recv_buffer_size()? < UDP_RECEIVE_BUFFER_SIZE {
        socket.set_recv_buffer_size(UDP_RECEIVE_BUFFER_SIZE)?;
    }
    Ok(())
}

fn bind_udp6(port: u16) -> std::io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_only_v6(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port).into())?;
    UdpSocket::from_std(socket.into())
}

fn new_socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; BUFFER_SIZE]),
        tcp::SocketBuffer::new(vec![0; BUFFER_SIZE]),
    );
    socket.set_nagle_enabled(false);
    socket.set_ack_delay(None);
    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(60)));
    socket
}
fn ip16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => ip.octets(),
    }
}
fn seal_disco(key: &PrivateKey, peer: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = SalsaBox::new(
        &BoxPublic::from(*peer),
        &BoxSecret::from(key.disco_private()),
    );
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let encrypted = cipher
        .encrypt(&nonce, data)
        .map_err(|_| anyhow!("disco encryption failed"))?;
    let mut out = DISCO_MAGIC.to_vec();
    out.extend_from_slice(&key.disco_public());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&encrypted);
    Ok(out)
}
fn open_disco(key: &PrivateKey, peer: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 78 {
        bail!("short disco packet");
    }
    let cipher = SalsaBox::new(
        &BoxPublic::from(*peer),
        &BoxSecret::from(key.disco_private()),
    );
    cipher
        .decrypt(data[38..62].into(), &data[62..])
        .map_err(|_| anyhow!("invalid disco authentication"))
}
fn parse_stun(data: &[u8]) -> Option<SocketAddr> {
    let mut offset = 20;
    let length = 20 + u16::from_be_bytes([*data.get(2)?, *data.get(3)?]) as usize;
    if length > data.len() {
        return None;
    }
    while offset + 4 <= length {
        let kind = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let size = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        let b = data.get(offset..offset + size)?;
        if kind == 0x20 && size >= 8 && b[1] == 1 {
            let port = u16::from_be_bytes([b[2], b[3]]) ^ 0x2112;
            let ip = Ipv4Addr::new(b[4] ^ 0x21, b[5] ^ 0x12, b[6] ^ 0xa4, b[7] ^ 0x42);
            return Some(SocketAddr::new(ip.into(), port));
        }
        offset += (size + 3) & !3;
    }
    None
}

#[derive(Default)]
struct PacketDevice {
    incoming: VecDeque<Vec<u8>>,
    outgoing: VecDeque<Vec<u8>>,
}
struct ReceiveToken(Vec<u8>);
struct TransmitToken<'a>(&'a mut VecDeque<Vec<u8>>);
impl RxToken for ReceiveToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for TransmitToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0; len];
        let result = f(&mut buf);
        self.0.push_back(buf);
        result
    }
}
impl Device for PacketDevice {
    type RxToken<'a> = ReceiveToken;
    type TxToken<'a> = TransmitToken<'a>;
    fn receive(&mut self, _: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.incoming
            .pop_front()
            .map(|p| (ReceiveToken(p), TransmitToken(&mut self.outgoing)))
    }
    fn transmit(&mut self, _: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TransmitToken(&mut self.outgoing))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = 1280;
        c.max_burst_size = Some(64);
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn syn_packet(source: Ipv6Addr, destination: Ipv6Addr, source_port: u16) -> Vec<u8> {
        let mut bytes = vec![0; 60];
        let mut ip = Ipv6Packet::new_unchecked(bytes.as_mut_slice());
        ip.set_version(6);
        ip.set_payload_len(20);
        ip.set_next_header(IpProtocol::Tcp);
        ip.set_hop_limit(64);
        ip.set_src_addr(source);
        ip.set_dst_addr(destination);
        let mut tcp = TcpPacket::new_unchecked(&mut bytes[40..]);
        tcp.set_src_port(source_port);
        tcp.set_dst_port(1234);
        tcp.set_header_len(20);
        tcp.set_syn(true);
        tcp.set_window_len(65535);
        tcp.fill_checksum(&source.into(), &destination.into());
        bytes
    }

    #[tokio::test]
    async fn invalid_syns_allocate_nothing_and_pending_flows_are_deduplicated() {
        let (region, _relay) = derp::start_local_relay().await.unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let called = calls.clone();
        let config = ServerConfig {
            on_tcp: Some(Arc::new(move |_| {
                called.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Some(
                    Arc::new(|_| Box::pin(async {}) as Pin<Box<dyn Future<Output = ()> + Send>>)
                        as TcpHandler,
                )
            })),
            ..Default::default()
        };
        let (mut actor, _handle) = Actor::new(PrivateKey::new(), region, Some(config), None)
            .await
            .unwrap();
        let source = protocol::tc_addr_for_key(&PrivateKey::new().public());
        let valid = syn_packet(source, actor.local, 4321);
        let mut checksum = valid.clone();
        checksum[56] ^= 1;
        let mut header = valid.clone();
        header[52] = 0;
        let mut payload = valid.clone();
        payload[5] = 40;
        let mut flags = valid.clone();
        flags[53] |= 4;
        TcpPacket::new_unchecked(&mut flags[40..])
            .fill_checksum(&source.into(), &actor.local.into());
        let mut options = valid.clone();
        options.resize(64, 0);
        options[5] = 24;
        options[52] = 0x60;
        options[60..].copy_from_slice(&[2, 1, 0, 0]);
        TcpPacket::new_unchecked(&mut options[40..])
            .fill_checksum(&source.into(), &actor.local.into());
        for malformed in [
            checksum,
            header,
            payload,
            flags,
            options,
            vec![],
            valid[..30].to_vec(),
        ] {
            actor.receive_ip(malformed);
            assert!(actor.links.is_empty());
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
        for _ in 0..10 {
            actor.receive_ip(valid.clone());
        }
        assert_eq!(actor.links.len(), 1);
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        actor.receive_ip(syn_packet(source, actor.local, 4322));
        assert_eq!(actor.links.len(), 2);
    }

    #[test]
    fn endpoint_learning_is_bounded_and_rejects_invalid_destinations() {
        let mut endpoints = Vec::new();
        for port in 1..=200 {
            assert!(remember_endpoint(
                &mut endpoints,
                SocketAddr::from(([127, 0, 0, 1], port))
            ));
        }
        assert_eq!(endpoints.len(), MAX_CANDIDATES);
        assert_eq!(endpoints.last().unwrap().port(), 200);
        let latest = *endpoints.last().unwrap();
        assert!(!remember_endpoint(&mut endpoints, latest));
        for invalid in [
            "0.0.0.0:1",
            "255.255.255.255:1",
            "224.0.0.1:1",
            "127.0.0.1:0",
            "[::]:1",
            "[ff02::1]:1",
            "[::ffff:255.255.255.255]:1",
        ] {
            assert!(
                !remember_endpoint(&mut endpoints, invalid.parse().unwrap()),
                "{invalid}"
            );
        }
        assert_eq!(endpoints.len(), MAX_CANDIDATES);
    }

    #[tokio::test]
    async fn full_relay_queue_cannot_stall_meow_or_close() {
        let (region, _relay) = derp::start_local_relay().await.unwrap();
        let (mut actor, _handle) = Actor::new(
            PrivateKey::new(),
            region,
            Some(ServerConfig::default()),
            None,
        )
        .await
        .unwrap();
        let peer = PrivateKey::new();
        actor.add_peer(peer.public(), peer.disco_public());
        actor.server = Some(peer.public());
        let (outgoing, _receiver) = mpsc::channel(1);
        outgoing.try_send((peer.public(), vec![])).unwrap();
        actor.relay.outgoing = outgoing;
        let (result, _received) = oneshot::channel();
        let mut ping = PendingPing {
            started: Instant::now(),
            sent: Instant::now(),
            disco: false,
            txid: [0; 12],
            result,
        };
        tokio::time::timeout(Duration::from_millis(200), actor.send_ping(&mut ping))
            .await
            .expect("full relay queue stalled ping");
        let mut meow = b"meow\x01".to_vec();
        meow.extend_from_slice(&peer.public());
        meow.extend_from_slice(&peer.disco_public());
        tokio::time::timeout(
            Duration::from_millis(200),
            actor.incoming(peer.public(), meow, None),
        )
        .await
        .expect("full relay queue stalled peer registration");
        actor.cancel.cancel();
        tokio::time::timeout(Duration::from_millis(200), actor.run())
            .await
            .expect("actor failed to close");
    }

    #[tokio::test]
    async fn pending_pings_are_bounded_and_cancellation_reclaims_capacity() {
        let (region, _relay) = derp::start_local_relay().await.unwrap();
        let (mut actor, _handle) = Actor::new(PrivateKey::new(), region, None, None)
            .await
            .unwrap();
        let mut receivers = Vec::new();
        for _ in 0..MAX_PENDING_PINGS {
            let (result, received) = oneshot::channel();
            actor
                .command(Command::Ping {
                    disco: false,
                    result,
                })
                .await;
            receivers.push(received);
        }
        assert_eq!(actor.pings.len(), MAX_PENDING_PINGS);
        let (result, received) = oneshot::channel();
        actor
            .command(Command::Ping {
                disco: false,
                result,
            })
            .await;
        assert!(
            received
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("too many")
        );
        receivers.clear();
        let (result, received) = oneshot::channel();
        actor
            .command(Command::Ping {
                disco: false,
                result,
            })
            .await;
        assert_eq!(actor.pings.len(), 1);
        drop(received);
        actor.last_timers = Instant::now() - Duration::from_millis(251);
        actor.tick().await;
        assert!(actor.pings.is_empty());
        let (result, received) = oneshot::channel();
        drop(received);
        actor
            .command(Command::Ping {
                disco: false,
                result,
            })
            .await;
        assert!(actor.pings.is_empty());
    }

    #[tokio::test]
    async fn direct_path_requires_authenticated_pong_from_probed_endpoint() {
        let (region, _relay) = derp::start_local_relay().await.unwrap();
        let (mut actor, _handle) = Actor::new(
            PrivateKey::new(),
            region,
            Some(ServerConfig::default()),
            None,
        )
        .await
        .unwrap();
        let peer = PrivateKey::new();
        actor.add_peer(peer.public(), peer.disco_public());
        let endpoint: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let txid = [42; 12];
        actor
            .probes
            .insert(txid, (peer.public(), endpoint, Instant::now()));
        let mut pong = vec![2, 0];
        pong.extend_from_slice(&txid);
        pong.extend_from_slice(&[0; 18]);
        let encrypted = seal_disco(&peer, &actor.key.disco_public(), &pong).unwrap();
        actor
            .disco_packet(
                peer.public(),
                &encrypted,
                Some("127.0.0.1:12346".parse().unwrap()),
            )
            .await;
        assert!(actor.peers[&peer.public()].direct.is_none());
        assert!(actor.probes.contains_key(&txid));
        actor
            .disco_packet(peer.public(), &encrypted, Some(endpoint))
            .await;
        assert_eq!(actor.peers[&peer.public()].direct.unwrap().0, endpoint);
    }

    #[test]
    fn nat64_roundtrip() {
        let addr: SocketAddr = "192.0.2.20:8080".parse().unwrap();
        assert_eq!(to_ipv6(addr).to_string(), "[64:ff9b::c000:214]:8080");
        assert_eq!(from_ipv6(to_ipv6(addr)), addr);
    }

    #[test]
    fn disco_authentication_and_key_separation() {
        let alice = PrivateKey::new();
        let bob = PrivateKey::new();
        assert_ne!(alice.public(), alice.disco_public());
        let mut packet = seal_disco(&alice, &bob.disco_public(), b"hello").unwrap();
        assert_eq!(
            open_disco(&bob, &alice.disco_public(), &packet).unwrap(),
            b"hello"
        );
        *packet.last_mut().unwrap() ^= 1;
        assert!(open_disco(&bob, &alice.disco_public(), &packet).is_err());
    }

    #[tokio::test]
    async fn native_transfer_preserves_half_close_and_discovers_direct_path() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (region, _relay) = derp::start_local_relay().await.unwrap();
            let server = Server::start(ServerConfig {
                region: Some(region),
                on_tcp: Some(Arc::new(|port| {
                    (port == 1234).then(|| {
                        Arc::new(|mut stream: DuplexStream| {
                            Box::pin(async move {
                                let mut request = Vec::new();
                                stream.read_to_end(&mut request).await.unwrap();
                                stream.write_all(&request).await.unwrap();
                                stream.shutdown().await.unwrap();
                            })
                                as Pin<Box<dyn Future<Output = ()> + Send>>
                        }) as TcpHandler
                    })
                })),
                ..Default::default()
            })
            .await
            .unwrap();
            let client = Client::connect(&server.tailcat_addr(), None, None)
                .await
                .unwrap();
            let mut stream = client.dial_tcp_port(1234).await.unwrap();
            let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, payload);
            client.drain_tcp(Duration::from_secs(3)).await.unwrap();
            let mut direct = false;
            for _ in 0..20 {
                if client.disco_ping().await.unwrap().endpoint.is_some() {
                    direct = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(direct, "localhost peers should establish a direct UDP path");
            let status = client.status().await.unwrap();
            assert_eq!(status.public_key, client.public_key());
            assert_eq!(status.peers.len(), 1);
            assert_eq!(status.peers[0].public_key, server.public_key());
            assert!(status.peers[0].tx_bytes > 0 && status.peers[0].rx_bytes > 0);
            assert!(status.peers[0].handshake_age.is_some());
            assert!(status.peers[0].direct_endpoint.is_some());
            let status = server.status().await.unwrap();
            assert_eq!(status.address, server.addr());
            assert!(status.peers[0].tx_bytes > 0 && status.peers[0].rx_bytes > 0);
            client.close().await;
            server.close().await;
        })
        .await
        .expect("native transfer timed out");
    }

    #[tokio::test]
    async fn closed_tcp_retains_received_data_until_application_reads() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let (region, _relay) = derp::start_local_relay().await.unwrap();
            let (close_tx, close_rx) = oneshot::channel();
            let (read_tx, read_rx) = oneshot::channel();
            let (result_tx, result_rx) = oneshot::channel();
            let controls = Arc::new(std::sync::Mutex::new(Some((close_rx, read_rx, result_tx))));
            let handler: TcpHandler = Arc::new(move |mut stream| {
                let (close, read, result) = controls.lock().unwrap().take().unwrap();
                Box::pin(async move {
                    close.await.unwrap();
                    stream.shutdown().await.unwrap();
                    read.await.unwrap();
                    let mut data = Vec::new();
                    stream.read_to_end(&mut data).await.unwrap();
                    let _ = result.send(data);
                })
            });
            let server = Server::start(ServerConfig {
                region: Some(region),
                on_tcp: Some(Arc::new(move |_| Some(handler.clone()))),
                ..Default::default()
            })
            .await
            .unwrap();
            let client = Client::connect(&server.tailcat_addr(), None, None)
                .await
                .unwrap();
            let mut stream = client.dial_tcp_port(1234).await.unwrap();
            // More than one application buffer, so unread bytes remain in the
            // TCP receive queue until after its close handshake completes.
            let payload = vec![37; BUFFER_SIZE + BUFFER_SIZE / 2];
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            client.drain_tcp(Duration::from_secs(5)).await.unwrap();
            close_tx.send(()).unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            client.drain_tcp(Duration::from_secs(5)).await.unwrap();
            read_tx.send(()).unwrap();
            let received = result_rx.await.unwrap();
            assert_eq!(received.len(), payload.len(), "received data was truncated");
            assert!(received == payload, "received data was corrupted");
            client.close().await;
            server.close().await;
        })
        .await
        .expect("deferred-read half-close test timed out");
    }

    #[tokio::test]
    async fn allowlist_rejects_unknown_identity() {
        let (region, _relay) = derp::start_local_relay().await.unwrap();
        let allowed = PrivateKey::new();
        let server = Server::start(ServerConfig {
            region: Some(region),
            allowed_clients: vec![allowed.public()],
            ..Default::default()
        })
        .await
        .unwrap();
        let rejected = tokio::time::timeout(
            Duration::from_millis(500),
            Client::connect(&server.tailcat_addr(), None, None),
        )
        .await;
        assert!(
            rejected.is_err(),
            "unauthorized peer received meow acknowledgement"
        );
        let client = Client::connect(&server.tailcat_addr(), Some(allowed), None)
            .await
            .unwrap();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn incomplete_address_is_an_error_without_network_access() {
        let info = ConnInfo::for_key(&PrivateKey::new());
        assert!(
            Client::connect(&info.addr().unwrap(), None, Some("none"))
                .await
                .is_err()
        );
    }
}
