use super::*;
use smoltcp::wire::{UdpPacket, UdpRepr};

type Flow = (SocketAddr, SocketAddr);
pub type UdpHandler =
    Arc<dyn Fn(DatagramStream) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;
pub type UdpPortHandler = Arc<dyn Fn(u16) -> Option<UdpHandler> + Send + Sync>;
pub type UdpForwardHandler = Arc<dyn Fn(SocketAddr) -> Option<UdpHandler> + Send + Sync>;

/// A bounded, connected datagram flow. Each receive returns one complete packet.
pub struct DatagramStream {
    flow: Flow,
    incoming: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    commands: mpsc::Sender<Command>,
    closed: CancellationToken,
}
impl DatagramStream {
    pub fn local_addr(&self) -> SocketAddr {
        from_ipv6(self.flow.0)
    }
    pub fn peer_addr(&self) -> SocketAddr {
        from_ipv6(self.flow.1)
    }
    pub async fn send(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > 65507 {
            bail!("UDP datagram is too large");
        }
        if self.closed.is_cancelled() {
            bail!("UDP flow is closed");
        }
        let (result, done) = oneshot::channel();
        self.commands
            .send(Command::SendUdp {
                flow: self.flow,
                bytes: bytes.to_vec(),
                generation: self.closed.clone(),
                result,
            })
            .await
            .map_err(|_| anyhow!("tailcat is closed"))?;
        done.await.map_err(|_| anyhow!("tailcat is closed"))
    }
    pub async fn recv(&self) -> Result<Vec<u8>> {
        let mut incoming = self.incoming.lock().await;
        tokio::select! {
            _ = self.closed.cancelled() => bail!("UDP flow is closed"),
            packet = incoming.recv() => packet.ok_or_else(|| anyhow!("UDP flow is closed")),
        }
    }
}
impl Drop for DatagramStream {
    fn drop(&mut self) {
        self.closed.cancel();
    }
}

pub enum AcceptedConnection {
    Tcp(DuplexStream),
    Udp(DatagramStream),
}
/// A runtime port claim. Dropping it releases the claim; existing flows stay open.
pub struct Listener {
    pub(super) port: u16,
    pub(super) incoming: mpsc::Receiver<AcceptedConnection>,
}
impl Listener {
    pub fn port(&self) -> u16 {
        self.port
    }
    pub async fn accept(&mut self) -> Result<AcceptedConnection> {
        self.incoming
            .recv()
            .await
            .ok_or_else(|| anyhow!("listener is closed"))
    }
}

pub(super) struct UdpFlow {
    tx: mpsc::Sender<Vec<u8>>,
    closed: CancellationToken,
    touched: Instant,
}
impl Drop for UdpFlow {
    fn drop(&mut self) {
        self.closed.cancel();
    }
}

impl Actor {
    pub(super) fn new_udp_flow(&mut self, flow: Flow) -> DatagramStream {
        let (tx, incoming) = mpsc::channel(32);
        let closed = CancellationToken::new();
        self.udp_flows.insert(
            flow,
            UdpFlow {
                tx,
                closed: closed.clone(),
                touched: Instant::now(),
            },
        );
        DatagramStream {
            flow,
            incoming: tokio::sync::Mutex::new(incoming),
            commands: self.command_tx.clone(),
            closed,
        }
    }
    pub(super) fn udp_input(&mut self, ip: &Ipv6Packet<&[u8]>) {
        let Ok(packet) = UdpPacket::new_checked(ip.payload()) else {
            return;
        };
        let Ok(repr) = UdpRepr::parse(
            &packet,
            &ip.src_addr().into(),
            &ip.dst_addr().into(),
            &ChecksumCapabilities::default(),
        ) else {
            return;
        };
        if repr.src_port == 0 || repr.dst_port == 0 {
            return;
        }
        let flow = (
            SocketAddr::new(ip.dst_addr().into(), repr.dst_port),
            SocketAddr::new(ip.src_addr().into(), repr.src_port),
        );
        if self
            .udp_flows
            .get(&flow)
            .is_some_and(|f| f.closed.is_cancelled())
        {
            self.udp_flows.remove(&flow);
        }
        if !self.udp_flows.contains_key(&flow) {
            let Some(config) = &self.config else { return };
            if self.udp_flows.len() >= MAX_CONNECTIONS {
                return;
            }
            let listener = (ip.dst_addr() == self.local)
                .then(|| self.listeners.get(&(true, repr.dst_port)))
                .flatten()
                .filter(|tx| !tx.is_closed())
                .cloned();
            if listener.is_none()
                && ip.dst_addr() == self.local
                && config.served_udp_ports.as_ref().is_some_and(|ports| {
                    !ports
                        .iter()
                        .any(|(a, b)| *a <= repr.dst_port && repr.dst_port <= *b)
                })
            {
                return;
            }
            let handler = if ip.dst_addr() == self.local {
                config.on_udp.as_ref().and_then(|f| f(repr.dst_port))
            } else {
                config
                    .on_udp_forward
                    .as_ref()
                    .and_then(|f| f(from_ipv6(flow.0)))
            };
            if listener.is_none() && handler.is_none() {
                return;
            }
            let stream = self.new_udp_flow(flow);
            if let Some(tx) = listener {
                let _ = tx.try_send(AcceptedConnection::Udp(stream));
            } else if let Some(handler) = handler {
                tokio::spawn(handler(stream));
            }
        }
        if let Some(state) = self.udp_flows.get_mut(&flow) {
            state.touched = Instant::now();
            let _ = state.tx.try_send(packet.payload().to_vec());
        }
    }
    pub(super) fn udp_output(&mut self, flow: Flow, bytes: &[u8], generation: CancellationToken) {
        if generation.is_cancelled() {
            return;
        }
        let Some(state) = self.udp_flows.get_mut(&flow) else {
            return;
        };
        state.touched = Instant::now();
        let mut packet = vec![0; 48 + bytes.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((8 + bytes.len()) as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&protocol::nat64_addr(flow.0.ip()).octets());
        packet[24..40].copy_from_slice(&protocol::nat64_addr(flow.1.ip()).octets());
        let mut udp = UdpPacket::new_unchecked(&mut packet[40..]);
        udp.set_src_port(flow.0.port());
        udp.set_dst_port(flow.1.port());
        udp.set_len((8 + bytes.len()) as u16);
        udp.payload_mut().copy_from_slice(bytes);
        udp.fill_checksum(
            &protocol::nat64_addr(flow.0.ip()).into(),
            &protocol::nat64_addr(flow.1.ip()).into(),
        );
        self.device.outgoing.push_back(packet);
    }
    pub(super) fn expire_udp(&mut self) {
        let timeout = self
            .config
            .as_ref()
            .and_then(|c| c.udp_idle_timeout)
            .unwrap_or(Duration::from_secs(120));
        self.udp_flows.retain(|_, state| {
            !state.closed.is_cancelled()
                && !state.tx.is_closed()
                && state.touched.elapsed() < timeout
        });
        self.listeners.retain(|_, tx| !tx.is_closed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn udp_listener_roundtrip_and_release() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (region, _relay) = derp::start_local_relay().await.unwrap();
            let server = Server::start(ServerConfig {
                region: Some(region),
                served_udp_ports: Some(vec![]),
                udp_idle_timeout: Some(Duration::from_millis(150)),
                ..Default::default()
            })
            .await
            .unwrap();
            let mut listener = server.listen("udp", 0).await.unwrap();
            let port = listener.port();
            assert!(server.listen("udp", port).await.is_err());
            let client = Client::connect(&server.tailcat_addr(), None, None)
                .await
                .unwrap();
            let stream = client.dial_udp_port(port).await.unwrap();
            stream.send(b"one").await.unwrap();
            let AcceptedConnection::Udp(peer) = listener.accept().await.unwrap() else {
                panic!()
            };
            assert_eq!(peer.recv().await.unwrap(), b"one");
            stream.send(b"").await.unwrap();
            assert_eq!(peer.recv().await.unwrap(), b"");
            peer.send(b"reply").await.unwrap();
            assert_eq!(stream.recv().await.unwrap(), b"reply");
            // An above-MTU packet may be dropped, but must not crash the actor.
            stream.send(&vec![0; 65507]).await.unwrap();
            assert!(stream.send(&vec![0; 65508]).await.is_err());
            assert!(client.status().await.is_ok());
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(peer.recv().await.is_err());
            drop(listener);
            assert!(server.listen("udp", port).await.is_ok());
            client.close().await;
            server.close().await;
        })
        .await
        .unwrap();
    }
}

#[cfg(test)]
mod listener_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn tcp_listener_claim_overrides_filter_and_releases() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (region, _relay) = derp::start_local_relay().await.unwrap();
            let server = Server::start(ServerConfig {
                region: Some(region),
                served_tcp_ports: Some(vec![]),
                ..Default::default()
            })
            .await
            .unwrap();
            let mut listener = server.listen("tcp", 0).await.unwrap();
            let port = listener.port();
            let client = Client::connect(&server.tailcat_addr(), None, None)
                .await
                .unwrap();
            let mut stream = client.dial_tcp_port(port).await.unwrap();
            let AcceptedConnection::Tcp(mut peer) = listener.accept().await.unwrap() else {
                panic!()
            };
            stream.write_all(b"hello").await.unwrap();
            let mut bytes = [0; 5];
            peer.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"hello");
            drop(listener);
            assert!(server.listen("tcp", port).await.is_ok());
            client.close().await;
            server.close().await;
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn wrong_psk_cannot_open_a_service() {
        let (region, _relay) = derp::start_local_relay().await.unwrap();
        let server = Server::start(ServerConfig {
            region: Some(region),
            ..Default::default()
        })
        .await
        .unwrap();
        let mut listener = server.listen("tcp", 1234).await.unwrap();
        let mut address = protocol::parse_addr(&server.tailcat_addr()).unwrap();
        address.preshared_key = Some([99; 32]);
        let client = Client::connect(&address.addr().unwrap(), None, None)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(250), client.dial_tcp_port(1234))
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
        client.close().await;
        server.close().await;
    }
}
