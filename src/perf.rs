// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//! Upstream-compatible JSON-lines throughput protocol on port 5201.
use crate::runtime::{Client, DatagramStream, TcpHandler, UdpHandler};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{
        AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
        DuplexStream,
    },
    sync::{mpsc, watch},
    task::JoinSet,
};
pub const PORT: u16 = 5201;
pub fn direction_name(dir: &str) -> &str {
    match dir {
        "up" => "client -> server",
        "down" => "server -> client",
        _ => "both directions",
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Params {
    pub proto: String,
    pub dir: String,
    #[serde(default)]
    pub duration: u64,
    #[serde(default)]
    pub bytes: u64,
    pub streams: usize,
    pub length: usize,
    #[serde(default)]
    pub bitrate: u64,
    #[serde(default)]
    pub interval: u64,
}
impl Params {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.proto.as_str(), "tcp" | "udp")
            || !matches!(self.dir.as_str(), "up" | "down" | "both")
        {
            bail!("unknown protocol or direction");
        }
        if self.streams == 0 || self.streams > 128 {
            bail!("streams must be between 1 and 128");
        }
        if self.bytes == 0 && (self.duration == 0 || self.duration > 600_000_000_000) {
            bail!("duration must be positive and at most ten minutes");
        }
        if self.length == 0
            || self.length > 1 << 20
            || (self.proto == "udp" && !(32..=65507).contains(&self.length))
        {
            bail!("invalid data length");
        }
        if self.interval != 0 && self.interval < 100_000_000 {
            bail!("interval must be at least 100ms");
        }
        Ok(())
    }
    fn sends(&self, server: bool) -> bool {
        self.dir == "both" || self.dir == if server { "down" } else { "up" }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Stats {
    pub bytes: u64,
    pub duration: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub datagrams: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub reordered: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub jitter: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intervals: Vec<Interval>,
}
fn is_zero(n: &u64) -> bool {
    *n == 0
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Interval {
    pub bytes: u64,
    #[serde(default)]
    pub datagrams: u64,
}
fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
struct ControlReader<R> {
    reader: BufReader<R>,
    pending: Vec<u8>,
}
impl<R: AsyncRead + Unpin> ControlReader<R> {
    fn new(stream: R) -> Self {
        Self {
            reader: BufReader::new(stream),
            pending: Vec::new(),
        }
    }
    fn get_mut(&mut self) -> &mut R {
        self.reader.get_mut()
    }
}
// Keep partial lines in the reader across select cancellation (pings and reports).
async fn read_message<R: AsyncRead + Unpin>(reader: &mut ControlReader<R>) -> Result<Value> {
    loop {
        let buf = reader.reader.fill_buf().await?;
        if buf.is_empty() {
            bail!("performance control connection closed");
        }
        let n = buf
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buf.len(), |i| i + 1);
        if reader.pending.len() + n > 65536 {
            bail!("performance control line is too long");
        }
        let done = buf[n - 1] == b'\n';
        reader.pending.extend_from_slice(&buf[..n]);
        reader.reader.consume(n);
        if done {
            return Ok(serde_json::from_slice(&std::mem::take(
                &mut reader.pending,
            ))?);
        }
    }
}
async fn message<W: AsyncWrite + Unpin>(writer: &mut W, value: Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    Ok(())
}
enum Data {
    Tcp(BufReader<DuplexStream>),
    Udp(Arc<DatagramStream>),
}
struct Active {
    id: String,
    proto: String,
    tx: mpsc::Sender<(usize, Data)>,
}
#[derive(Default)]
pub struct Server {
    active: Mutex<Option<Active>>,
}
impl Server {
    pub fn tcp(self: &Arc<Self>) -> TcpHandler {
        let server = self.clone();
        Arc::new(move |stream| {
            let server = server.clone();
            Box::pin(async move {
                if let Err(e) = server.handle_tcp(stream).await {
                    tracing::debug!("perf: {e:#}");
                }
            })
        })
    }
    pub fn udp(self: &Arc<Self>) -> UdpHandler {
        let server = self.clone();
        Arc::new(move |stream| {
            let server = server.clone();
            Box::pin(async move {
                let first = tokio::time::timeout(Duration::from_secs(15), stream.recv()).await;
                if let Ok(Ok(bytes)) = first
                    && bytes.len() >= 32
                {
                    server.attach(
                        &hex::encode(&bytes[..8]),
                        u16::from_be_bytes([bytes[8], bytes[9]]) as usize,
                        Data::Udp(Arc::new(stream)),
                    );
                }
            })
        })
    }
    fn attach(&self, id: &str, index: usize, data: Data) {
        let active = self.active.lock().unwrap();
        if let Some(active) = active.as_ref()
            && active.id == id
            && (active.proto == "udp") == matches!(data, Data::Udp(_))
        {
            let _ = active.tx.try_send((index, data));
        }
    }
    async fn handle_tcp(&self, stream: DuplexStream) -> Result<()> {
        let mut reader = ControlReader::new(stream);
        let first =
            tokio::time::timeout(Duration::from_secs(15), read_message(&mut reader)).await??;
        if first["type"] == "stream" {
            self.attach(
                first["id"].as_str().unwrap_or(""),
                first["stream"].as_u64().unwrap_or(0) as usize,
                Data::Tcp(reader.reader),
            );
            return Ok(());
        }
        if first["type"] != "hello" {
            bail!("expected hello");
        }
        let result: Result<Params> = serde_json::from_value::<Params>(first["params"].clone())
            .map_err(Into::into)
            .and_then(|p| {
                p.validate()?;
                Ok(p)
            });
        let params = match result {
            Ok(p) => p,
            Err(e) => {
                message(
                    reader.get_mut(),
                    json!({"type":"error","error":e.to_string()}),
                )
                .await?;
                return Ok(());
            }
        };
        let id = hex::encode(rand::random::<[u8; 8]>());
        let (tx, mut rx) = mpsc::channel(128);
        let busy = {
            let mut active = self.active.lock().unwrap();
            if active.is_some() {
                true
            } else {
                *active = Some(Active {
                    id: id.clone(),
                    proto: params.proto.clone(),
                    tx,
                });
                false
            }
        };
        if busy {
            message(
                reader.get_mut(),
                json!({"type":"error","error":"the server is busy with another test"}),
            )
            .await?;
            return Ok(());
        }
        struct Release<'a>(&'a Mutex<Option<Active>>);
        impl Drop for Release<'_> {
            fn drop(&mut self) {
                *self.0.lock().unwrap() = None;
            }
        }
        let _release = Release(&self.active);
        message(reader.get_mut(), json!({"type":"ok","id":id})).await?;
        let data = tokio::time::timeout(Duration::from_secs(15), async {
            let mut data: Vec<Option<Data>> = (0..params.streams).map(|_| None).collect();
            let mut count = 0;
            while count < params.streams {
                let (i, stream) = rx.recv().await.context("data setup closed")?;
                if i < data.len() && data[i].is_none() {
                    data[i] = Some(stream);
                    count += 1;
                }
            }
            Ok::<_, anyhow::Error>(data.into_iter().map(Option::unwrap).collect::<Vec<_>>())
        })
        .await??;
        message(reader.get_mut(), json!({"type":"ready"})).await?;
        let result = tokio::time::timeout(
            Duration::from_secs(630),
            run(reader, params, id, data, true, false),
        )
        .await??;
        let peer = crate::runtime::CONNECTION_INFO
            .try_with(|c| c.remote_addr.to_string())
            .unwrap_or_default();
        eprintln!(
            "# perf test from {peer}: {} {} completed",
            result["params"]["proto"]
                .as_str()
                .unwrap_or("")
                .to_uppercase(),
            direction_name(result["params"]["dir"].as_str().unwrap_or(""))
        );
        Ok(())
    }
}
fn header(id: &[u8], stream: usize, flags: u8, seq: u64, data: &mut [u8]) {
    data[..8].copy_from_slice(id);
    data[8..10].copy_from_slice(&(stream as u16).to_be_bytes());
    data[10] = flags;
    data[11..16].fill(0);
    data[16..24].copy_from_slice(&seq.to_be_bytes());
    data[24..32].copy_from_slice(&now_ns().to_be_bytes());
}
fn count(stats: &mut Stats, n: usize, udp: bool, start: Instant, interval: u64) {
    stats.bytes += n as u64;
    stats.datagrams += u64::from(udp);
    if interval != 0 {
        let slot = (start.elapsed().as_nanos() / interval as u128) as usize;
        if slot < 6001 {
            stats.intervals.resize_with(slot + 1, Default::default);
            stats.intervals[slot].bytes += n as u64;
            stats.intervals[slot].datagrams += u64::from(udp);
        }
    }
}
#[allow(clippy::too_many_arguments)]
async fn send_data<W: AsyncWrite + Unpin>(
    mut writer: W,
    udp: Option<Arc<DatagramStream>>,
    p: Params,
    id: Vec<u8>,
    index: usize,
    start: Instant,
    counter: Arc<AtomicU64>,
) -> Result<Stats> {
    let mut stats = Stats::default();
    let mut bytes = (0..p.length).map(|i| i as u8).collect::<Vec<_>>();
    loop {
        if (p.bytes > 0 && stats.bytes >= p.bytes)
            || (p.bytes == 0 && start.elapsed().as_nanos() >= p.duration as u128)
        {
            break;
        }
        if p.bitrate > 0 {
            tokio::time::sleep_until(tokio::time::Instant::from_std(
                start + Duration::from_secs_f64(stats.bytes as f64 * 8.0 / p.bitrate as f64),
            ))
            .await;
        }
        let n = if let Some(udp) = &udp {
            header(&id, index, 0, stats.datagrams, &mut bytes);
            udp.send(&bytes).await?;
            bytes.len()
        } else {
            let n = if p.bytes > 0 {
                bytes.len().min((p.bytes - stats.bytes) as usize)
            } else {
                bytes.len()
            };
            writer.write_all(&bytes[..n]).await?;
            n
        };
        count(&mut stats, n, udp.is_some(), start, p.interval);
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }
    stats.duration = start.elapsed().as_nanos() as u64;
    if let Some(udp) = udp {
        let mut fin = [0; 32];
        header(&id, index, 2, 0, &mut fin);
        for _ in 0..3 {
            udp.send(&fin).await?;
        }
    } else {
        writer.shutdown().await?;
    }
    Ok(stats)
}
async fn receive_data<R: AsyncRead + Unpin>(
    mut reader: R,
    udp: Option<Arc<DatagramStream>>,
    p: Params,
    id: Vec<u8>,
    mut done: watch::Receiver<Option<Instant>>,
    start: Instant,
    counter: Arc<AtomicU64>,
) -> Result<Stats> {
    let mut stats = Stats::default();
    let mut bytes = vec![0; 65536];
    let mut expected = 0;
    let mut transit: Option<i128> = None;
    let mut jitter = 0f64;
    let mut first = None;
    loop {
        let deadline =
            (*done.borrow()).map(|t| t + Duration::from_secs(if udp.is_some() { 2 } else { 5 }));
        let packet = async {
            if let Some(udp) = &udp {
                udp.recv().await
            } else {
                let n = reader.read(&mut bytes).await?;
                Ok(bytes[..n].to_vec())
            }
        };
        let data = tokio::select! {
            packet = packet => packet?,
            _ = done.changed() => continue,
            _ = async { if let Some(deadline) = deadline { tokio::time::sleep_until(deadline.into()).await } else { std::future::pending().await } } => break,
        };
        if udp.is_some() {
            if data.len() < 32 || data[..8] != id {
                continue;
            }
            if data[10] & 2 != 0 {
                break;
            }
            if data[10] & 1 != 0 {
                continue;
            }
            let seq = u64::from_be_bytes(data[16..24].try_into()?);
            if seq < expected {
                stats.reordered += 1;
            } else {
                expected = seq + 1;
            }
            let current = now_ns() as i128 - u64::from_be_bytes(data[24..32].try_into()?) as i128;
            if let Some(old) = transit {
                jitter += ((current - old).abs() as f64 - jitter) / 16.0;
            }
            transit = Some(current);
        } else if data.is_empty() {
            break;
        }
        let first = *first.get_or_insert_with(Instant::now);
        stats.duration = first.elapsed().as_nanos() as u64;
        count(&mut stats, data.len(), udp.is_some(), start, p.interval);
        counter.fetch_add(data.len() as u64, Ordering::Relaxed);
    }
    stats.jitter = jitter as u64;
    Ok(stats)
}
fn combine(all: &[Stats]) -> Stats {
    let mut total = Stats::default();
    for s in all {
        total.bytes += s.bytes;
        total.datagrams += s.datagrams;
        total.reordered += s.reordered;
        total.duration = total.duration.max(s.duration);
        total.jitter += s.jitter / all.len() as u64;
        total.intervals.resize_with(
            total.intervals.len().max(s.intervals.len()),
            Default::default,
        );
        for (i, v) in s.intervals.iter().enumerate() {
            total.intervals[i].bytes += v.bytes;
            total.intervals[i].datagrams += v.datagrams;
        }
    }
    total
}
async fn run(
    mut control: ControlReader<DuplexStream>,
    p: Params,
    id: String,
    data: Vec<Data>,
    server: bool,
    progress: bool,
) -> Result<Value> {
    let start = Instant::now();
    let id = hex::decode(id)?;
    let (done_tx, done) = watch::channel(None);
    let send_counter = Arc::new(AtomicU64::new(0));
    let receive_counter = Arc::new(AtomicU64::new(0));
    let mut senders = JoinSet::new();
    let mut receivers = JoinSet::new();
    for (i, data) in data.into_iter().enumerate() {
        match data {
            Data::Tcp(stream) => {
                let (r, w) = tokio::io::split(stream);
                if p.sends(server) {
                    senders.spawn(send_data(
                        w,
                        None,
                        p.clone(),
                        id.clone(),
                        i,
                        start,
                        send_counter.clone(),
                    ));
                }
                if p.sends(!server) {
                    receivers.spawn(receive_data(
                        r,
                        None,
                        p.clone(),
                        id.clone(),
                        done.clone(),
                        start,
                        receive_counter.clone(),
                    ));
                }
            }
            Data::Udp(stream) => {
                if p.sends(server) {
                    senders.spawn(send_data(
                        tokio::io::sink(),
                        Some(stream.clone()),
                        p.clone(),
                        id.clone(),
                        i,
                        start,
                        send_counter.clone(),
                    ));
                }
                if p.sends(!server) {
                    receivers.spawn(receive_data(
                        tokio::io::empty(),
                        Some(stream),
                        p.clone(),
                        id.clone(),
                        done.clone(),
                        start,
                        receive_counter.clone(),
                    ));
                }
            }
        }
    }
    let mut sent = vec![];
    let mut received = vec![];
    let mut local_sent = None;
    let mut local_received = None;
    let mut peer_sent = None;
    let mut peer_received = None;
    let mut rtts = Vec::new();
    let mut ping = tokio::time::interval(Duration::from_millis(200));
    let mut pending_ping = None;
    let mut report = tokio::time::interval_at(
        (start + Duration::from_nanos(p.interval.max(100_000_000))).into(),
        Duration::from_nanos(p.interval.max(100_000_000)),
    );
    let mut previous = (0, 0);
    loop {
        if p.sends(server) && senders.is_empty() && local_sent.is_none() {
            let stats = combine(&sent);
            let mut wire = stats.clone();
            wire.intervals.clear();
            message(control.get_mut(), json!({"type":"done","stats":wire})).await?;
            local_sent = Some(stats);
        }
        if p.sends(!server) && receivers.is_empty() && local_received.is_none() {
            let stats = combine(&received);
            let mut wire = stats.clone();
            wire.intervals.clear();
            message(control.get_mut(), json!({"type":"result","stats":wire})).await?;
            local_received = Some(stats);
        }
        if (!p.sends(server) || (local_sent.is_some() && peer_received.is_some()))
            && (!p.sends(!server) || (local_received.is_some() && peer_sent.is_some()))
        {
            break;
        }
        tokio::select! {
            result = senders.join_next(), if !senders.is_empty() => { sent.push(result.unwrap()??); },
            result = receivers.join_next(), if !receivers.is_empty() => { received.push(result.unwrap()??); },
            m = read_message(&mut control) => { let m = m?; match m["type"].as_str().unwrap_or("") {
                "ping" => message(control.get_mut(),json!({"type":"pong","t":m["t"]})).await?,
                "pong" => { if let Some((stamp,at)) = pending_ping.take() && m["t"].as_u64() == Some(stamp) { let at: Instant = at; rtts.push(at.elapsed().as_nanos() as u64); } },
                "done" => { peer_sent = Some(serde_json::from_value::<Stats>(m["stats"].clone())?); let _ = done_tx.send(Some(Instant::now())); },
                "result" => peer_received = Some(serde_json::from_value::<Stats>(m["stats"].clone())?),
                "error" => bail!("perf: {}",m["error"]), _ => {},
            } },
            _ = ping.tick(), if !server => { if pending_ping.is_none() { let stamp = now_ns(); pending_ping = Some((stamp,Instant::now())); message(control.get_mut(),json!({"type":"ping","t":stamp})).await?; } },
            _ = report.tick(), if progress && p.interval > 0 => {
                let totals = (send_counter.load(Ordering::Relaxed),receive_counter.load(Ordering::Relaxed));
                print!("[{:6.1}s]",start.elapsed().as_secs_f64());
                if p.sends(false) { let n = totals.0-previous.0; print!("  sent {n} B {:.0} bit/s",n as f64*8e9/p.interval as f64); }
                if p.sends(true) { let n = totals.1-previous.1; print!("  received {n} B {:.0} bit/s",n as f64*8e9/p.interval as f64); }
                if let Some(rtt) = rtts.last() { print!("  rtt {rtt}ns"); }
                println!(); previous = totals;
            },
        }
    }
    let (client_sent, server_sent, client_received, server_received) = if server {
        (peer_sent, local_sent, peer_received, local_received)
    } else {
        (local_sent, peer_sent, local_received, peer_received)
    };
    let mut result = json!({"params":p});
    for (key, stats) in [
        ("clientSent", client_sent),
        ("serverSent", server_sent),
        ("clientReceived", client_received),
        ("serverReceived", server_received),
    ] {
        if let Some(stats) = stats {
            result[key] = serde_json::to_value(stats)?;
        }
    }
    if !rtts.is_empty() {
        result["rtt"] = json!({"min":rtts.iter().min(),"max":rtts.iter().max(),"avg":rtts.iter().sum::<u64>()/rtts.len() as u64,"count":rtts.len()});
    }
    control.get_mut().shutdown().await?;
    Ok(result)
}

pub async fn run_client(client: &Client, p: Params, progress: bool) -> Result<Value> {
    p.validate()?;
    tokio::time::timeout(Duration::from_secs(630), async {
        let mut control = ControlReader::new(client.dial_tcp_port(PORT).await?);
        message(control.get_mut(),json!({"type":"hello","params":p})).await?;
        let reply = tokio::time::timeout(Duration::from_secs(15),read_message(&mut control)).await??;
        if reply["type"] != "ok" { bail!("perf: {}", reply["error"]); }
        let id = reply["id"].as_str().context("missing test ID")?.to_owned();
        let decoded = hex::decode(&id)?; if decoded.len() != 8 { bail!("invalid test ID"); }
        let mut data = Vec::new();
        for i in 0..p.streams {
            if p.proto == "tcp" { let mut stream = client.dial_tcp_port(PORT).await?; message(&mut stream,json!({"type":"stream","id":id,"stream":i})).await?; data.push(Data::Tcp(BufReader::new(stream))); }
            else { data.push(Data::Udp(Arc::new(client.dial_udp_port(PORT).await?))); }
        }
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut timer = tokio::time::interval(Duration::from_millis(200));
            loop { tokio::select! {
                _ = timer.tick(), if p.proto == "udp" => { for (i,s) in data.iter().enumerate() { if let Data::Udp(s) = s { let mut bytes = [0;32]; header(&decoded,i,1,0,&mut bytes); s.send(&bytes).await?; } } },
                reply = read_message(&mut control) => { let reply = reply?; if reply["type"] == "ready" { break; } else if reply["type"] == "error" { bail!("perf: {}",reply["error"]); } },
            } }
            Ok::<_,anyhow::Error>(())
        }).await??;
        run(control,p,id,data,false,progress).await
    }).await?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn native_perf_all_transports_and_directions() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let (region, _relay) = crate::derp::start_local_relay().await.unwrap();
            let perf = Arc::new(Server::default());
            let tcp = perf.clone();
            let udp = perf.clone();
            let server = crate::Server::start(crate::ServerConfig {
                region: Some(region),
                on_tcp: Some(Arc::new(move |p| (p == PORT).then(|| tcp.tcp()))),
                on_udp: Some(Arc::new(move |p| (p == PORT).then(|| udp.udp()))),
                ..Default::default()
            })
            .await
            .unwrap();
            let client = Client::connect(&server.tailcat_addr(), None, None)
                .await
                .unwrap();
            for proto in ["tcp", "udp"] {
                for dir in ["up", "down", "both"] {
                    let p = Params {
                        proto: proto.into(),
                        dir: dir.into(),
                        duration: 0,
                        bytes: 12000,
                        streams: 2,
                        length: 1200,
                        bitrate: 1_000_000,
                        interval: 0,
                    };
                    let result = run_client(&client, p, false)
                        .await
                        .unwrap_or_else(|e| panic!("{proto} {dir}: {e:#}"));
                    if dir != "down" {
                        assert_eq!(result["clientSent"]["bytes"], 24000);
                        assert_eq!(result["serverReceived"]["bytes"], 24000);
                    }
                    if dir != "up" {
                        assert_eq!(result["serverSent"]["bytes"], 24000);
                        assert_eq!(result["clientReceived"]["bytes"], 24000);
                    }
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            }
            client.close().await;
            server.close().await;
        })
        .await
        .unwrap();
    }
}
