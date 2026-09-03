//! Browser implementation: DERP over WebSocket, WireGuard, and userspace TCP.
//! The JavaScript API deliberately matches the original browser frontend.
#![allow(dead_code)]
#[path = "../../src/protocol.rs"]
#[allow(unused_imports)]
mod protocol;

use anyhow::{Context, Result, anyhow, bail};
use boringtun::noise::{Tunn, TunnResult};
use gloo_timers::future::TimeoutFuture;
use js_sys::{Function, Object, Promise, Reflect, Uint8Array};
use protocol::{ConnInfo, DerpMap, PrivateKey, Region};
use serde::{Deserialize, Serialize};
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
    cell::{Cell, RefCell},
    collections::{HashMap, VecDeque},
    net::Ipv6Addr,
    rc::Rc,
};
use wasm_bindgen::{JsCast, prelude::*};
use wasm_bindgen_futures::{JsFuture, future_to_promise, spawn_local};
use web_sys::{BinaryType, Event, MessageEvent, WebSocket};
use web_time::{Duration, Instant};

const TCP_BUFFER: usize = 256 << 10;
const MAX_CONNECTIONS: usize = 256;
const MAX_PEERS: usize = 1024;
type SharedEngine = Rc<RefCell<Engine>>;
type Frame = (u8, Vec<u8>);

fn js_error(error: impl std::fmt::Display) -> JsValue {
    js_sys::Error::new(&error.to_string()).into()
}
fn set(object: &JsValue, name: &str, value: &JsValue) -> Result<()> {
    Reflect::set(object, &name.into(), value).map_err(|e| anyhow!("setting {name}: {e:?}"))?;
    Ok(())
}
fn string_option(options: &JsValue, name: &str) -> String {
    Reflect::get(options, &name.into())
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default()
}
fn now_ms() -> i64 {
    js_sys::Date::now() as i64
}

#[wasm_bindgen(start)]
pub fn start() -> std::result::Result<(), JsValue> {
    console_error_panic_hook::set_once();
    let listen = Closure::<dyn Fn(JsValue) -> Promise>::new(|options| {
        future_to_promise(async move { listen(options).await.map_err(js_error) })
    });
    let dial = Closure::<dyn Fn(JsValue) -> Promise>::new(|options| {
        future_to_promise(async move { dial(options).await.map_err(js_error) })
    });
    Reflect::set(
        &js_sys::global(),
        &"tailcatListen".into(),
        &listen.into_js_value(),
    )?;
    Reflect::set(
        &js_sys::global(),
        &"tailcatDial".into(),
        &dial.into_js_value(),
    )?;
    if let Ok(callback) = Reflect::get(&js_sys::global(), &"onTailcatReady".into())
        && let Some(callback) = callback.dyn_ref::<Function>()
    {
        callback.call0(&JsValue::UNDEFINED)?;
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SavedKey {
    private: PrivateKey,
    public: ConnInfo,
}

struct FetchGuard(web_sys::AbortController);
impl Drop for FetchGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct MapReader(web_sys::ReadableStreamDefaultReader);
impl Drop for MapReader {
    fn drop(&mut self) {
        self.0.release_lock();
    }
}

async fn expand(ci: &mut ConnInfo, url: &str, server: bool) -> Result<()> {
    if !ci.region.is_empty() {
        return Ok(());
    }
    if ci.region_id == 0 {
        bail!("no DERP region in tailcat address");
    }
    let url = if url.is_empty() {
        protocol::DEFAULT_DERP_MAP_URL
    } else {
        url
    };
    let controller =
        web_sys::AbortController::new().map_err(|e| anyhow!("fetch abort controller: {e:?}"))?;
    let _abort = FetchGuard(controller.clone());
    let abort = controller.clone();
    let _timeout = gloo_timers::callback::Timeout::new(10_000, move || abort.abort());
    let response = gloo_net::http::Request::get(url)
        .header("Tailcat-Mode", if server { "server" } else { "client" })
        .abort_signal(Some(&controller.signal()))
        .send()
        .await
        .map_err(|e| anyhow!("fetching DERP map: {e}"))?;
    if !response.ok() {
        bail!("fetching DERP map: HTTP {}", response.status());
    }
    let reader = MapReader(
        response
            .body()
            .ok_or_else(|| anyhow!("empty DERP map response"))?
            .get_reader()
            .dyn_into::<web_sys::ReadableStreamDefaultReader>()
            .map_err(|_| anyhow!("DERP map reader unavailable"))?,
    );
    let mut body = Vec::new();
    loop {
        let chunk = JsFuture::from(reader.0.read())
            .await
            .map_err(|e| anyhow!("reading DERP map: {e:?}"))?;
        if Reflect::get(&chunk, &"done".into())
            .ok()
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            break;
        }
        let value =
            Reflect::get(&chunk, &"value".into()).map_err(|e| anyhow!("DERP map chunk: {e:?}"))?;
        let data = Uint8Array::new(&value);
        if body.len() + data.length() as usize > 8 << 20 {
            bail!("DERP map exceeds 8 MiB");
        }
        body.extend(data.to_vec());
    }
    let mut map: DerpMap = serde_json::from_slice(&body)?;
    let id = if ci.region_id == -1 {
        *map.regions
            .keys()
            .next()
            .ok_or_else(|| anyhow!("DERP map has no regions"))?
    } else {
        ci.region_id
    };
    ci.region = vec![
        map.regions
            .remove(&id)
            .ok_or_else(|| anyhow!("DERP region {id} does not exist"))?,
    ];
    if ci.region_id == -1 {
        ci.region_id = 0;
    }
    Ok(())
}

async fn listen(options: JsValue) -> Result<JsValue> {
    let callback = Reflect::get(&options, &"onConnection".into())
        .map_err(|e| anyhow!("onConnection: {e:?}"))?
        .dyn_into::<Function>()
        .map_err(|_| anyhow!("onConnection function is required"))?;
    let url = string_option(&options, "derpMapURL");
    if url.is_empty() {
        bail!("derpMapURL is required");
    }
    let existing = string_option(&options, "privateKey");
    let mut saved = if existing.is_empty() {
        let private = PrivateKey::new();
        let mut public = ConnInfo::for_key(&private);
        public.region_id = -1;
        SavedKey { private, public }
    } else {
        serde_json::from_str(&existing).context("parsing privateKey")?
    };
    // Recompute public keys so persisted legacy keys also get key separation.
    saved.public.server_public = saved.private.public();
    saved.public.server_disco_public = Some(saved.private.disco_public());
    let mut ci = saved.public.clone();
    expand(&mut ci, &url, true).await?;
    if existing.is_empty() {
        saved.public.region_id = ci.region[0].region_id;
    }
    let addr = saved.public.addr()?;
    let key_json = serde_json::to_string(&saved)?;
    let engine = Engine::create(saved.private, ci.region[0].clone(), None, Some(callback)).await?;
    run_engine(engine.clone());
    let object = Object::new();
    set(&object, "addr", &addr.into())?;
    set(&object, "privateKeyJSON", &key_json.into())?;
    let close = Closure::<dyn Fn()>::new(move || engine.borrow_mut().close());
    set(&object, "close", &close.into_js_value())?;
    Ok(object.into())
}

async fn dial(options: JsValue) -> Result<JsValue> {
    let addr = string_option(&options, "addr");
    if addr.is_empty() {
        bail!("addr is required");
    }
    let url = string_option(&options, "derpMapURL");
    let existing = string_option(&options, "privateKey");
    let key = if existing.is_empty() {
        PrivateKey::new()
    } else {
        serde_json::from_str::<SavedKey>(&existing)
            .context("parsing privateKey")?
            .private
    };
    let port = Reflect::get(&options, &"port".into())
        .ok()
        .and_then(|p| p.as_f64())
        .unwrap_or(1.0);
    if port.fract() != 0.0 || !(0.0..=65535.0).contains(&port) {
        bail!("port must be between 0 and 65535");
    }
    let mut ci = protocol::parse_addr(&addr)?;
    if ci.server_disco_public.is_none_or(|k| k == [0; 32]) {
        bail!("legacy tailcat address lacks a separate disco key");
    }
    expand(&mut ci, &url, false).await?;
    let server = ci.server_public;
    let engine = Engine::create(key, ci.region[0].clone(), Some(ci), None).await?;
    run_engine(engine.clone());
    let start = Instant::now();
    loop {
        {
            let e = engine.borrow();
            if e.closed {
                bail!("connection closed");
            }
            if e.meowed {
                break;
            }
        }
        if start.elapsed() > Duration::from_secs(60) {
            engine.borrow_mut().close();
            bail!("meow handshake timed out");
        }
        TimeoutFuture::new(5).await;
    }
    let (handle, generation) = engine
        .borrow_mut()
        .dial(protocol::tc_addr_for_key(&server), port as u16)?;
    loop {
        let state = {
            let engine = engine.borrow();
            if engine.closed || !engine.live_handle(handle, generation) {
                bail!("connection closed");
            }
            engine.sockets.get::<tcp::Socket>(handle).state()
        };
        if matches!(state, State::Established | State::CloseWait) {
            break;
        }
        if state == State::Closed {
            engine.borrow_mut().close();
            bail!("TCP connection refused");
        }
        if start.elapsed() > Duration::from_secs(60) {
            engine.borrow_mut().close();
            bail!("TCP connection timed out");
        }
        TimeoutFuture::new(5).await;
    }
    Ok(BrowserConn {
        engine,
        handle,
        generation,
        port: port as u16,
        reading: Rc::new(Cell::new(false)),
        writing: Rc::new(Cell::new(false)),
    }
    .into())
}

#[wasm_bindgen]
pub struct BrowserConn {
    engine: SharedEngine,
    handle: SocketHandle,
    generation: u64,
    pub port: u16,
    reading: Rc<Cell<bool>>,
    writing: Rc<Cell<bool>>,
}

struct BusyGuard(Rc<Cell<bool>>);
impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

#[wasm_bindgen]
impl BrowserConn {
    pub async fn read(&self) -> std::result::Result<JsValue, JsValue> {
        if self.reading.replace(true) {
            return Err(js_error("concurrent reads are unsupported"));
        }
        let _guard = BusyGuard(self.reading.clone());
        loop {
            {
                let mut engine = self.engine.borrow_mut();
                if engine.closed || !engine.live_handle(self.handle, self.generation) {
                    return Ok(JsValue::NULL);
                }
                let socket = engine.sockets.get_mut::<tcp::Socket>(self.handle);
                if socket.can_recv() {
                    let mut buffer = vec![0; (64 << 10).min(socket.recv_queue())];
                    let n = socket.recv_slice(&mut buffer).map_err(js_error)?;
                    return Ok(Uint8Array::from(&buffer[..n]).into());
                }
                if !socket.may_recv() {
                    return Ok(JsValue::NULL);
                }
            }
            TimeoutFuture::new(2).await;
        }
    }

    pub async fn write(&self, data: Uint8Array) -> std::result::Result<(), JsValue> {
        if self.writing.replace(true) {
            return Err(js_error("concurrent writes are unsupported"));
        }
        let _guard = BusyGuard(self.writing.clone());
        let data = data.to_vec();
        let mut offset = 0;
        while offset < data.len() {
            {
                let mut engine = self.engine.borrow_mut();
                if engine.closed || !engine.live_handle(self.handle, self.generation) {
                    return Err(js_error("connection is closed"));
                }
                let socket = engine.sockets.get_mut::<tcp::Socket>(self.handle);
                if !socket.may_send() {
                    return Err(js_error("connection write side is closed"));
                }
                if socket.can_send() {
                    offset += socket.send_slice(&data[offset..]).map_err(js_error)?;
                }
            }
            if offset < data.len() {
                TimeoutFuture::new(2).await;
            }
        }
        Ok(())
    }

    #[wasm_bindgen(js_name = closeWrite)]
    pub async fn close_write(&self) -> std::result::Result<(), JsValue> {
        if self.writing.get() {
            return Err(js_error("write must finish before closeWrite"));
        }
        let mut engine = self.engine.borrow_mut();
        if !engine.closed && engine.live_handle(self.handle, self.generation) {
            engine.sockets.get_mut::<tcp::Socket>(self.handle).close();
        }
        Ok(())
    }

    pub fn close(&self) {
        let mut engine = self.engine.borrow_mut();
        if !engine.closed && engine.live_handle(self.handle, self.generation) {
            engine.sockets.get_mut::<tcp::Socket>(self.handle).close();
            engine.links.get_mut(&self.handle).unwrap().app_closed = true;
            if engine.server.is_some() {
                engine.close_when_drained = true;
            }
        }
    }
}

struct Ws {
    socket: WebSocket,
    bytes: Rc<RefCell<VecDeque<u8>>>,
    closed: Rc<Cell<bool>>,
    _message: Closure<dyn FnMut(MessageEvent)>,
    _close: Closure<dyn FnMut(Event)>,
    _error: Closure<dyn FnMut(Event)>,
}

impl Drop for Ws {
    fn drop(&mut self) {
        self.socket.set_onmessage(None);
        self.socket.set_onclose(None);
        self.socket.set_onerror(None);
        let _ = self.socket.close();
    }
}

impl Ws {
    async fn connect(key: &PrivateKey, region: &Region, is_server: bool) -> Result<Self> {
        let mut error = anyhow!("DERP region has no relay nodes");
        let deadline = Instant::now() + Duration::from_secs(10);
        for node in region.nodes.iter().filter(|n| !n.stun_only) {
            if Instant::now() >= deadline {
                break;
            }
            let host = if node.host_name.contains(':') {
                format!("[{}]", node.host_name)
            } else {
                node.host_name.clone()
            };
            let port = if node.derp_port == 0 {
                443
            } else {
                node.derp_port
            };
            if !(1..=65535).contains(&port) {
                continue;
            }
            let url = format!("wss://{host}:{port}/derp");
            match Self::open(&url, key, is_server, deadline).await {
                Ok(ws) => return Ok(ws),
                Err(e) => error = e,
            }
        }
        Err(error)
    }

    async fn open(url: &str, key: &PrivateKey, is_server: bool, deadline: Instant) -> Result<Self> {
        let socket =
            WebSocket::new_with_str(url, "derp").map_err(|e| anyhow!("WebSocket: {e:?}"))?;
        socket.set_binary_type(BinaryType::Arraybuffer);
        let bytes = Rc::new(RefCell::new(VecDeque::new()));
        let closed = Rc::new(Cell::new(false));
        let queue = bytes.clone();
        let terminated = closed.clone();
        let ws = socket.clone();
        let message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if terminated.get() {
                return;
            }
            if event.data().is_instance_of::<js_sys::ArrayBuffer>() {
                let data = Uint8Array::new(&event.data());
                let mut queue = queue.borrow_mut();
                if queue.len() + data.length() as usize > 8 << 20 {
                    terminated.set(true);
                    let _ = ws.close();
                    return;
                }
                queue.extend(data.to_vec());
            }
        });
        let terminated = closed.clone();
        let close = Closure::<dyn FnMut(Event)>::new(move |_| terminated.set(true));
        let terminated = closed.clone();
        let error = Closure::<dyn FnMut(Event)>::new(move |_| terminated.set(true));
        socket.set_onmessage(Some(message.as_ref().unchecked_ref()));
        socket.set_onclose(Some(close.as_ref().unchecked_ref()));
        socket.set_onerror(Some(error.as_ref().unchecked_ref()));
        let result = Self {
            socket,
            bytes,
            closed,
            _message: message,
            _close: close,
            _error: error,
        };
        let (kind, greeting) = result.wait_frame(deadline).await?;
        if kind != 1 || greeting.len() < 40 || &greeting[..8] != b"DERP\xf0\x9f\x94\x91" {
            bail!("invalid DERP server greeting");
        }
        let server_key = greeting[8..40].try_into()?;
        let info = serde_json::to_vec(
            &serde_json::json!({"version":2,"CanAckPings":true,"AppName":if is_server {"tailcat-server"} else {"tailcat-client"}}),
        )?;
        let mut body = key.public().to_vec();
        body.extend(protocol::seal_box(&key.0, &server_key, &info)?);
        result.send(2, &body)?;
        loop {
            let (kind, info) = result.wait_frame(deadline).await?;
            match kind {
                3 => {
                    let info = protocol::open_box(&key.0, &server_key, &info)?;
                    let _: serde_json::Value = serde_json::from_slice(&info)?;
                    break;
                }
                6 => (),
                0x12 if info.len() == 8 => result.send(0x13, &info)?,
                _ => bail!("unexpected DERP authentication frame"),
            }
        }
        result.send(7, &[1])?;
        Ok(result)
    }

    fn next_frame(&self) -> Result<Option<Frame>> {
        let mut bytes = self.bytes.borrow_mut();
        if bytes.len() < 5 {
            return Ok(None);
        }
        let length = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        if length > (1 << 20) + 64 {
            bail!("DERP frame exceeds size limit");
        }
        if bytes.len() < 5 + length {
            return Ok(None);
        }
        let kind = bytes.pop_front().unwrap();
        bytes.drain(..4);
        Ok(Some((kind, bytes.drain(..length).collect())))
    }

    async fn wait_frame(&self, deadline: Instant) -> Result<Frame> {
        loop {
            if let Some(frame) = self.next_frame()? {
                return Ok(frame);
            }
            if self.closed.get() {
                bail!("DERP WebSocket closed");
            }
            if Instant::now() >= deadline {
                bail!("DERP connection timed out");
            }
            TimeoutFuture::new(2).await;
        }
    }

    fn send(&self, kind: u8, body: &[u8]) -> Result<()> {
        if self.closed.get() || self.socket.ready_state() != WebSocket::OPEN {
            bail!("DERP WebSocket is closed");
        }
        if self.socket.buffered_amount() > 1 << 20 {
            bail!("DERP send queue full");
        }
        let mut packet = vec![kind];
        packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
        packet.extend_from_slice(body);
        self.socket
            .send_with_u8_array(&packet)
            .map_err(|e| anyhow!("DERP send: {e:?}"))
    }

    fn packet(&self, key: &[u8; 32], packet: &[u8]) {
        let mut body = key.to_vec();
        body.extend_from_slice(packet);
        let _ = self.send(4, &body);
    }
}

struct Peer {
    disco: [u8; 32],
    tunnel: Tunn,
}
struct Link {
    generation: u64,
    flow: (IpEndpoint, IpEndpoint),
    port: u16,
    notified: bool,
    app_closed: bool,
    created: Instant,
}
struct Engine {
    key: PrivateKey,
    region: Region,
    ws: Ws,
    local: Ipv6Addr,
    server: Option<[u8; 32]>,
    on_connection: Option<Function>,
    peers: HashMap<[u8; 32], Peer>,
    device: PacketDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    links: HashMap<SocketHandle, Link>,
    meowed: bool,
    closed: bool,
    close_when_drained: bool,
    drained_at: Option<Instant>,
    last_timers: Instant,
    last_meow: Instant,
    last_heartbeat: Instant,
    next_port: u16,
    next_generation: u64,
}

impl Engine {
    async fn create(
        key: PrivateKey,
        region: Region,
        server: Option<ConnInfo>,
        on_connection: Option<Function>,
    ) -> Result<SharedEngine> {
        let ws = Ws::connect(&key, &region, server.is_none()).await?;
        let local = protocol::tc_addr_for_key(&key.public());
        let mut device = PacketDevice::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device, SmolInstant::from_millis(now_ms()));
        iface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new(local.into(), 128)).unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv6_route(local)
            .map_err(|e| anyhow!("route: {e:?}"))?;
        let mut engine = Self {
            key,
            region,
            ws,
            local,
            server: server.as_ref().map(|s| s.server_public),
            on_connection,
            peers: HashMap::new(),
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            links: HashMap::new(),
            meowed: false,
            closed: false,
            close_when_drained: false,
            drained_at: None,
            last_timers: Instant::now(),
            last_meow: Instant::now(),
            last_heartbeat: Instant::now(),
            next_port: 32768,
            next_generation: 1,
        };
        if let Some(server) = server {
            engine.add_peer(server.server_public, server.server_disco_public.unwrap());
        }
        Ok(Rc::new(RefCell::new(engine)))
    }

    fn add_peer(&mut self, key: [u8; 32], disco: [u8; 32]) {
        if self.peers.contains_key(&key)
            || self.peers.len() >= MAX_PEERS
            || key == [0; 32]
            || disco == [0; 32]
        {
            return;
        }
        let tunnel = Tunn::new(
            self.key.0.into(),
            key.into(),
            None,
            Some(25),
            self.peers.len() as u32 + 1,
            None,
        );
        self.peers.insert(key, Peer { disco, tunnel });
    }

    fn live_handle(&self, handle: SocketHandle, generation: u64) -> bool {
        self.links
            .get(&handle)
            .is_some_and(|link| link.generation == generation)
    }

    fn dial(&mut self, destination: Ipv6Addr, port: u16) -> Result<(SocketHandle, u64)> {
        if self.links.len() >= MAX_CONNECTIONS {
            bail!("too many TCP connections");
        }
        let flow = (
            IpEndpoint::new(self.local.into(), self.next_port),
            IpEndpoint::new(destination.into(), port),
        );
        let mut socket = tcp_socket();
        socket
            .connect(self.iface.context(), flow.1, flow.0)
            .map_err(|e| anyhow!("TCP dial: {e:?}"))?;
        self.next_port = if self.next_port == u16::MAX {
            32768
        } else {
            self.next_port + 1
        };
        let handle = self.sockets.add(socket);
        let generation = self.next_generation;
        self.next_generation += 1;
        self.links.insert(
            handle,
            Link {
                generation,
                flow,
                port,
                notified: true,
                app_closed: false,
                created: Instant::now(),
            },
        );
        Ok((handle, generation))
    }

    fn receive(&mut self, source: [u8; 32], data: &[u8]) {
        if protocol::is_meow_packet(data) {
            if self.server.is_none() {
                if let Some((node, disco)) = protocol::parse_meow_ping(data)
                    && node == source
                {
                    self.add_peer(source, disco);
                    if self.peers.contains_key(&source) {
                        self.ws.packet(&source, &protocol::encode_meowed());
                    }
                }
            } else if self.server == Some(source) && protocol::is_meowed_packet(data) {
                self.meowed = true;
            }
            return;
        }
        if data.starts_with(protocol::DISCO_MAGIC) {
            if let Some(peer) = self.peers.get(&source)
                && let Ok((disco, plaintext)) = protocol::open_disco(&self.key, data)
                && disco == peer.disco
                && plaintext.len() >= 14
                && plaintext[0] == 1
            {
                let mut pong = vec![2, 0];
                pong.extend_from_slice(&plaintext[2..14]);
                pong.extend_from_slice(&[0; 18]);
                if let Ok(packet) = protocol::seal_disco(&self.key, &disco, &pong) {
                    self.ws.packet(&source, &packet);
                }
            }
            return;
        }
        if !self.peers.contains_key(&source) {
            return;
        }
        let mut buffer = vec![0; 65536];
        let mut data = data;
        loop {
            match self
                .peers
                .get_mut(&source)
                .unwrap()
                .tunnel
                .decapsulate(None, data, &mut buffer)
            {
                TunnResult::WriteToNetwork(packet) => self.ws.packet(&source, packet),
                TunnResult::WriteToTunnelV6(packet, _) => {
                    let packet = packet.to_vec();
                    if packet.len() >= 40
                        && (self.server.is_some()
                            || packet[8..24] == protocol::tc_addr_for_key(&source).octets())
                    {
                        self.receive_ip(packet);
                    }
                }
                _ => break,
            }
            data = &[];
        }
    }

    fn receive_ip(&mut self, packet: Vec<u8>) {
        let Ok(ip) = Ipv6Packet::new_checked(packet.as_slice()) else {
            return;
        };
        if ip.version() != 6 || ip.dst_addr() != self.local || ip.next_header() != IpProtocol::Tcp {
            return;
        }
        let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else {
            return;
        };
        let Ok(tcp) = TcpRepr::parse(
            &tcp,
            &ip.src_addr().into(),
            &ip.dst_addr().into(),
            &ChecksumCapabilities::default(),
        ) else {
            return;
        };
        if tcp.control == TcpControl::Syn && tcp.ack_number.is_none() {
            if self.server.is_some() {
                return;
            }
            let port = tcp.dst_port;
            let flow = (
                IpEndpoint::new(ip.dst_addr().into(), port),
                IpEndpoint::new(ip.src_addr().into(), tcp.src_port),
            );
            let duplicate = self.links.iter().any(|(handle, link)| {
                link.flow == flow
                    && self.sockets.get::<tcp::Socket>(*handle).state() != State::Closed
            });
            if !duplicate && self.links.len() < MAX_CONNECTIONS {
                let mut socket = tcp_socket();
                if socket
                    .listen(IpEndpoint::new(self.local.into(), port))
                    .is_ok()
                {
                    let handle = self.sockets.add(socket);
                    let generation = self.next_generation;
                    self.next_generation += 1;
                    self.links.insert(
                        handle,
                        Link {
                            generation,
                            flow,
                            port,
                            notified: false,
                            app_closed: false,
                            created: Instant::now(),
                        },
                    );
                }
            }
        }
        // Browser service exposes only TCP, just like the Go packet filter.
        if self.device.incoming.len() < 256 {
            self.device.incoming.push_back(packet);
        }
    }

    fn tick(&mut self) -> Result<Vec<(SocketHandle, u64, u16)>> {
        for _ in 0..512 {
            let Some((kind, body)) = self.ws.next_frame()? else {
                break;
            };
            match kind {
                5 if (32..=65568).contains(&body.len()) => {
                    self.receive(body[..32].try_into()?, &body[32..])
                }
                0x12 if body.len() == 8 => {
                    let _ = self.ws.send(0x13, &body);
                }
                0x15 => {
                    self.ws.closed.set(true);
                }
                _ => (),
            }
        }
        if let Some(server) = self.server
            && !self.meowed
            && self.last_meow.elapsed() > Duration::from_secs(1)
        {
            self.last_meow = Instant::now();
            self.ws.packet(
                &server,
                &protocol::encode_meow_ping(&self.key.public(), &self.key.disco_public()),
            );
        }
        if self.last_heartbeat.elapsed() > Duration::from_secs(30) {
            self.last_heartbeat = Instant::now();
            let _ = self.ws.send(0x12, &rand::random::<[u8; 8]>());
        }
        let now = SmolInstant::from_millis(now_ms());
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        while let Some(packet) = self.device.outgoing.pop_front() {
            if packet.len() < 40 {
                continue;
            }
            let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
            let key = self.server.or_else(|| {
                self.peers
                    .keys()
                    .find(|k| protocol::tc_addr_for_key(k) == destination)
                    .copied()
            });
            if let Some(key) = key {
                let mut buffer = vec![0; 65536];
                if let TunnResult::WriteToNetwork(packet) = self
                    .peers
                    .get_mut(&key)
                    .unwrap()
                    .tunnel
                    .encapsulate(&packet, &mut buffer)
                {
                    self.ws.packet(&key, packet);
                }
            }
        }
        if self.last_timers.elapsed() > Duration::from_millis(250) {
            self.last_timers = Instant::now();
            for (key, peer) in &mut self.peers {
                let mut buffer = vec![0; 65536];
                if let TunnResult::WriteToNetwork(packet) = peer.tunnel.update_timers(&mut buffer) {
                    self.ws.packet(key, packet);
                }
            }
        }
        let mut accepted = Vec::new();
        let mut removed = Vec::new();
        for (handle, link) in &mut self.links {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            // Full close discards unread input while queued output and its FIN
            // finish; closeWrite by itself keeps reads pull-based.
            if link.app_closed && socket.can_recv() {
                let _ = socket.recv(|bytes| (bytes.len(), ()));
            }
            if !link.notified && matches!(socket.state(), State::Established | State::CloseWait) {
                link.notified = true;
                accepted.push((*handle, link.generation, link.port));
            }
            if !link.notified && link.created.elapsed() > Duration::from_secs(60) {
                socket.abort();
                link.app_closed = true;
            }
            if socket.state() == State::Closed && socket.recv_queue() == 0 {
                removed.push(*handle);
            }
        }
        for handle in removed {
            self.links.remove(&handle);
            self.sockets.remove(handle);
        }
        if self.close_when_drained
            && self.links.keys().all(|h| {
                matches!(
                    self.sockets.get::<tcp::Socket>(*h).state(),
                    State::Closed | State::TimeWait | State::FinWait2
                )
            })
        {
            let at = self.drained_at.get_or_insert_with(Instant::now);
            if at.elapsed() > Duration::from_millis(100) {
                self.close();
            }
        }
        Ok(accepted)
    }

    fn close(&mut self) {
        self.closed = true;
        self.ws.closed.set(true);
        let _ = self.ws.socket.close();
        for handle in self.links.keys() {
            self.sockets.get_mut::<tcp::Socket>(*handle).abort();
        }
        self.links.clear();
        self.sockets = SocketSet::new(vec![]);
        self.peers.clear();
        self.device.incoming.clear();
        self.device.outgoing.clear();
        self.ws.bytes.borrow_mut().clear();
    }
}

fn run_engine(engine: SharedEngine) {
    spawn_local(async move {
        loop {
            if engine.borrow().closed {
                return;
            }
            if engine.borrow().ws.closed.get() {
                let (key, region, server) = {
                    let e = engine.borrow();
                    (e.key.clone(), e.region.clone(), e.server.is_none())
                };
                match Ws::connect(&key, &region, server).await {
                    Ok(ws) => {
                        let mut e = engine.borrow_mut();
                        if e.closed {
                            drop(ws);
                            return;
                        }
                        e.ws = ws;
                        e.meowed = false;
                    }
                    Err(_) => {
                        TimeoutFuture::new(1000).await;
                        continue;
                    }
                }
            }
            let result = engine.borrow_mut().tick();
            match result {
                Ok(accepted) => {
                    let callback = engine.borrow().on_connection.clone();
                    if let Some(callback) = callback {
                        for (handle, generation, port) in accepted {
                            if !engine.borrow().live_handle(handle, generation) {
                                continue;
                            }
                            let conn = BrowserConn {
                                engine: engine.clone(),
                                handle,
                                generation,
                                port,
                                reading: Rc::new(Cell::new(false)),
                                writing: Rc::new(Cell::new(false)),
                            };
                            if let Err(error) = callback.call1(&JsValue::UNDEFINED, &conn.into()) {
                                web_sys::console::error_1(&error);
                                let mut engine = engine.borrow_mut();
                                if let Some(link) = engine.links.get_mut(&handle) {
                                    link.app_closed = true;
                                    engine.sockets.get_mut::<tcp::Socket>(handle).close();
                                }
                            }
                        }
                    }
                }
                Err(error) => {
                    web_sys::console::error_1(&js_error(error));
                    engine.borrow_mut().close();
                    return;
                }
            }
            TimeoutFuture::new(2).await;
        }
    });
}

fn tcp_socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
        tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
    );
    socket.set_nagle_enabled(false);
    socket.set_ack_delay(None);
    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(60)));
    socket
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
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.0.push_back(buffer);
        result
    }
}
impl Device for PacketDevice {
    type RxToken<'a> = ReceiveToken;
    type TxToken<'a> = TransmitToken<'a>;
    fn receive(&mut self, _: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.outgoing.len() >= 256 {
            return None;
        }
        self.incoming
            .pop_front()
            .map(|p| (ReceiveToken(p), TransmitToken(&mut self.outgoing)))
    }
    fn transmit(&mut self, _: SmolInstant) -> Option<Self::TxToken<'_>> {
        if self.outgoing.len() < 256 {
            Some(TransmitToken(&mut self.outgoing))
        } else {
            None
        }
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1280;
        capabilities.max_burst_size = Some(64);
        capabilities
    }
}
