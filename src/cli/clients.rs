use super::{args::Args, keys::client_key, util::*};
use crate::{protocol, runtime::Client};
use anyhow::{Context, Result, anyhow, bail};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    task::JoinSet,
};

pub async fn connect(args: &Args, address: &str) -> Result<Arc<Client>> {
    let addr = resolve_address(address).await?;
    Ok(Arc::new(
        Client::connect(&addr, Some(client_key(args)?), Some(&args.derp_map_url)).await?,
    ))
}

pub async fn pipe(args: &Args) -> Result<()> {
    if args.positional.is_empty() || args.positional.len() > 2 {
        bail!("client mode takes <tc-addr> [<port>]");
    }
    let dest = args.positional.get(1).map(String::as_str).unwrap_or("1");
    let port = if dest.contains(':') {
        None
    } else {
        Some(decimal_port(dest, true).context("invalid port number")?)
    };
    let target = if port.is_none() {
        Some(dest.parse::<SocketAddr>().context("invalid IP:port")?)
    } else {
        None
    };
    let client = connect(args, &args.positional[0]).await?;
    client.ping().await.context("tailcat Ping")?;
    let mut stream = tokio::time::timeout(Duration::from_secs(10), async {
        match target {
            Some(target) => client.dial_tcp(target).await,
            None => client.dial_tcp_port(port.unwrap()).await,
        }
    })
    .await
    .context("Dial timed out")??;
    let (mut reader, mut writer) = tokio::io::split(&mut stream);
    let input = async {
        tokio::io::copy(&mut tokio::io::stdin(), &mut writer).await?;
        writer.shutdown().await
    };
    let output = async {
        let mut stdout = tokio::io::stdout();
        tokio::io::copy(&mut reader, &mut stdout).await?;
        stdout.flush().await
    };
    // Do not exit at stdin EOF: the response and both FINs still live in the
    // userspace TCP stack, which must remain alive until delivery completes.
    tokio::try_join!(input, output)?;
    client.drain_tcp(Duration::from_secs(5)).await?;
    client.close().await;
    Ok(())
}

pub async fn ping(args: &Args) -> Result<()> {
    if args.positional.len() != 1 {
        bail!("ping requires one <tc-addr> argument");
    }
    let client = connect(args, &args.positional[0]).await?;
    let deadline = tokio::time::Instant::now() + args.timeout;
    loop {
        let started = Instant::now();
        let result = tokio::time::timeout_at(deadline, client.disco_ping()).await;
        let ping = match result {
            Ok(result) => result?,
            Err(_) if args.until_direct => {
                bail!("no direct path to the server after {:?}", args.timeout)
            }
            Err(_) => bail!("ping timed out after {:?}", args.timeout),
        };
        let via = ping.endpoint.map_or_else(
            || format!("DERP({})", ping.derp_region_id),
            |ep| ep.to_string(),
        );
        println!("pong in {:.2?} via {via}", ping.latency);
        if ping.endpoint.is_some() || !args.until_direct {
            break;
        }
        if deadline.saturating_duration_since(tokio::time::Instant::now())
            < Duration::from_millis(500)
        {
            bail!("no direct path to the server after {:?}", args.timeout);
        }
        tokio::time::sleep(Duration::from_secs(1).saturating_sub(started.elapsed())).await;
    }
    client.close().await;
    Ok(())
}

pub async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result?, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

pub async fn browse(args: &Args) -> Result<()> {
    if args.positional.len() != 1 {
        bail!("browse requires one <tc-addr>");
    }
    let mut args = args.clone();
    args.open_browser = true;
    args.positional.push("0:80".into());
    forward(&args).await
}
fn open_browser(mut address: SocketAddr) {
    if address.ip().is_unspecified() {
        address.set_ip(Ipv4Addr::LOCALHOST.into());
    }
    let url = format!("http://{address}/");
    eprintln!("# Opening {url}");
    tokio::spawn(async move {
        #[cfg(target_os = "macos")]
        let (program, prefix): (&str, Vec<&str>) = ("open", vec![]);
        #[cfg(target_os = "windows")]
        let (program, prefix): (&str, Vec<&str>) = ("cmd", vec!["/C", "start", ""]);
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let (program, prefix): (&str, Vec<&str>) = ("xdg-open", vec![]);
        match tokio::process::Command::new(program)
            .args(prefix)
            .arg(url)
            .status()
            .await
        {
            Ok(s) if s.success() => {}
            result => eprintln!("# opening browser failed: {result:?}"),
        }
    });
}

pub async fn forward(args: &Args) -> Result<()> {
    if args.positional.len() < 2 {
        bail!("forward takes a <tc-addr> and at least one port mapping");
    }
    if args.open_browser && args.positional.len() != 2 {
        bail!("--open-browser requires exactly one port mapping");
    }
    let mut listeners = vec![];
    for spec in &args.positional[1..] {
        let mapping = parse_forward_spec(&args.bind, spec)
            .with_context(|| format!("mapping {spec:?} is invalid"))?;
        let listener = TcpListener::bind(&mapping.listen_addr)
            .await
            .with_context(|| format!("listen on {}", mapping.listen_addr))?;
        listeners.push((listener, mapping));
    }
    let client = connect(args, &args.positional[0]).await?;
    let mut tasks = JoinSet::new();
    for (listener, mapping) in listeners {
        eprintln!(
            "forwarding {} -> remote {}",
            listener.local_addr()?,
            mapping.remote_target()
        );
        if args.open_browser {
            open_browser(listener.local_addr()?);
        }
        let client = client.clone();
        let verbose = args.verbose;
        tasks.spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut local, _) = accepted?;
                        let client = client.clone();
                        let mapping = mapping.clone();
                        connections.spawn(async move {
                            let result: Result<()> = async {
                                let mut remote = match mapping.target { Some(ap) => client.dial_tcp(ap).await?, None => client.dial_tcp_port(mapping.port).await? };
                                tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
                                Ok(())
                            }.await;
                            if verbose && let Err(err) = result { eprintln!("forward: {err:#}"); }
                        });
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
            #[allow(unreachable_code)] Ok::<(),anyhow::Error>(())
        });
    }
    tokio::select! {
        result = shutdown_signal() => result?,
        Some(result) = tasks.join_next() => result??,
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    client.close().await;
    Ok(())
}

struct SocksClients {
    args: Args,
    key: protocol::PrivateKey,
    fixed: Option<String>,
    clients: Mutex<HashMap<String, Arc<Client>>>,
}

impl SocksClients {
    async fn get(&self, addr: &str) -> Result<Arc<Client>> {
        let mut clients = self.clients.lock().await;
        if let Some(client) = clients.get(addr) {
            return Ok(client.clone());
        }
        let client = Arc::new(
            Client::connect(addr, Some(self.key.clone()), Some(&self.args.derp_map_url)).await?,
        );
        clients.insert(addr.to_owned(), client.clone());
        Ok(client)
    }
    async fn close(&self) {
        let mut clients = self.clients.lock().await;
        for (_, client) in clients.drain() {
            client.close().await;
        }
    }
}

fn executable_exists(program: &str) -> bool {
    if program.contains(['/', '\\']) {
        return std::path::Path::new(program).is_file();
    }
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|path| {
            if path.join(program).is_file() {
                return true;
            }
            #[cfg(windows)]
            for extension in ["exe", "cmd", "bat", "com"] {
                if path.join(format!("{program}.{extension}")).is_file() {
                    return true;
                }
            }
            false
        })
    })
}

pub async fn socks(args: &Args) -> Result<()> {
    let mut commands = args.positional.as_slice();
    let fixed = if let Some(first) = commands.first() {
        if protocol::parse_addr(first).is_ok() || (first.contains('.') && !executable_exists(first))
        {
            let address = resolve_address(first).await?;
            commands = &commands[1..];
            Some(address)
        } else {
            None
        }
    } else {
        None
    };
    let clients = Arc::new(SocksClients {
        args: args.clone(),
        key: client_key(args)?,
        fixed,
        clients: Mutex::new(HashMap::new()),
    });
    if let Some(addr) = &clients.fixed {
        clients.get(addr).await?.ping().await?;
    }
    let listen = normalize_listen(&args.listen);
    let listen = if listen.starts_with(':') {
        format!("0.0.0.0{listen}")
    } else {
        listen
    };
    let listener = TcpListener::bind(&listen).await?;
    let proxy = format!("socks5h://{}", listener.local_addr()?);
    let proxy_clients = clients.clone();
    let verbose = args.verbose;
    let mut task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let clients = proxy_clients.clone();
                    connections.spawn(async move {
                        if let Err(err) = socks_connection(stream, clients).await && verbose { eprintln!("socks5: {err:#}"); }
                    });
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });
    let result = if commands.is_empty() {
        eprintln!("SOCKS running at {proxy}");
        tokio::select! { result = shutdown_signal() => result, result = &mut task => result? }
    } else {
        if args.verbose {
            eprintln!("SOCKS running at {proxy}");
        }
        let mut command = tokio::process::Command::new(&commands[0]);
        command
            .args(&commands[1..])
            .env("all_proxy", &proxy)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let status = command
            .status()
            .await
            .with_context(|| format!("running {:?}", commands[0]));
        status.and_then(|status| {
            if status.success() {
                Ok(())
            } else {
                Err(anyhow!("command exited with {status}"))
            }
        })
    };
    task.abort();
    clients.close().await;
    result
}

async fn socks_connection(mut stream: TcpStream, clients: Arc<SocksClients>) -> Result<()> {
    let (host, port, operation) = tokio::time::timeout(Duration::from_secs(15), async {
        let version = stream.read_u8().await?;
        if version != 5 {
            bail!("unsupported SOCKS version");
        }
        let count = stream.read_u8().await? as usize;
        let mut methods = vec![0u8; count];
        stream.read_exact(&mut methods).await?;
        if !methods.contains(&0) {
            stream.write_all(&[5, 255]).await?;
            bail!("client does not support no-auth SOCKS");
        }
        stream.write_all(&[5, 0]).await?;
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        if header[0] != 5 || !matches!(header[1], 1 | 3) || header[2] != 0 {
            stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            bail!("SOCKS supports CONNECT and UDP ASSOCIATE only");
        }
        let host = match header[3] {
            1 => {
                let mut octets = [0; 4];
                stream.read_exact(&mut octets).await?;
                Ipv4Addr::from(octets).to_string()
            }
            3 => {
                let length = stream.read_u8().await? as usize;
                let mut bytes = vec![0; length];
                stream.read_exact(&mut bytes).await?;
                String::from_utf8(bytes).context("invalid SOCKS hostname")?
            }
            4 => {
                let mut octets = [0; 16];
                stream.read_exact(&mut octets).await?;
                Ipv6Addr::from(octets).to_string()
            }
            _ => {
                stream.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                bail!("unsupported SOCKS address type");
            }
        };
        let port = stream.read_u16().await?;
        Ok::<_, anyhow::Error>((host, port, header[1]))
    })
    .await
    .context("SOCKS negotiation timed out")??;
    if operation == 3 {
        return socks_udp(stream, clients, &host, port).await;
    }
    let dial = tokio::time::timeout(Duration::from_secs(15), async {
        let target = match classify_socks_target(&host, port, &[]) {
            Ok(target) => target,
            Err(_) => {
                let addresses = tokio::net::lookup_host((host.as_str(),port)).await?.map(|addr| addr.ip()).collect::<Vec<IpAddr>>();
                classify_socks_target(&host,port,&addresses)?
            }
        };
        match target {
            SocksTarget::Address(addr,port) => clients.get(&addr).await?.dial_tcp_port(port).await,
            SocksTarget::Server(port) => clients.get(clients.fixed.as_deref().context("no tailcat address argument was given to tailcat socks")?).await?.dial_tcp_port(port).await,
            SocksTarget::Exit(target) => clients.get(clients.fixed.as_deref().context("no tailcat address argument was given to tailcat socks; only tailcat address hostnames can be dialed")?).await?.dial_tcp(target).await,
        }
    }).await;
    let mut remote = match dial {
        Ok(Ok(remote)) => remote,
        result => {
            stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            match result {
                Ok(Err(err)) => return Err(err),
                _ => bail!("SOCKS dial timed out"),
            }
        }
    };
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
    Ok(())
}

fn udp_socks_target(packet: &[u8]) -> Result<(String, u16, usize)> {
    if packet.len() < 4 || packet[..3] != [0, 0, 0] {
        bail!("fragmented or invalid SOCKS UDP packet");
    }
    let (host, offset) = match packet[3] {
        1 if packet.len() >= 10 => (
            Ipv4Addr::from(<[u8; 4]>::try_from(&packet[4..8])?).to_string(),
            8,
        ),
        4 if packet.len() >= 22 => (
            Ipv6Addr::from(<[u8; 16]>::try_from(&packet[4..20])?).to_string(),
            20,
        ),
        3 if packet.len() >= 5 && packet.len() >= 7 + packet[4] as usize => (
            String::from_utf8(packet[5..5 + packet[4] as usize].to_vec())?,
            5 + packet[4] as usize,
        ),
        _ => bail!("invalid SOCKS UDP address"),
    };
    Ok((
        host,
        u16::from_be_bytes(packet[offset..offset + 2].try_into()?),
        offset + 2,
    ))
}

async fn socks_udp(
    mut control: TcpStream,
    clients: Arc<SocksClients>,
    host: &str,
    port: u16,
) -> Result<()> {
    let peer = control.peer_addr()?;
    let requested: IpAddr = host
        .parse()
        .context("UDP association requires an IP address")?;
    if !requested.is_unspecified() && requested != peer.ip() {
        bail!("UDP association address does not match TCP peer");
    }
    let socket = Arc::new(
        tokio::net::UdpSocket::bind(SocketAddr::new(control.local_addr()?.ip(), 0)).await?,
    );
    let bound = socket.local_addr()?;
    let mut reply = vec![5, 0, 0];
    match bound.ip() {
        IpAddr::V4(ip) => {
            reply.push(1);
            reply.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            reply.push(4);
            reply.extend(ip.octets());
        }
    }
    reply.extend(bound.port().to_be_bytes());
    control.write_all(&reply).await?;
    let mut source = (port != 0).then_some(SocketAddr::new(peer.ip(), port));
    let mut routes: HashMap<(String, u16), tokio::sync::mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut packet = vec![0; 65536];
    let mut eof = [0];
    loop {
        tokio::select! {
            _ = control.read(&mut eof) => return Ok(()),
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            received = socket.recv_from(&mut packet) => {
                let (n, from) = received?;
                if from.ip() != peer.ip() || source.is_some_and(|s| s != from) { continue; }
                let Ok((host, port, offset)) = udp_socks_target(&packet[..n]) else { continue };
                source = Some(from);
                let key = (host.clone(), port);
                routes.retain(|_,tx| !tx.is_closed());
                if !routes.contains_key(&key) {
                    if routes.len() >= 256 { continue; }
                    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
                    routes.insert(key, tx);
                    let socket = socket.clone(); let clients = clients.clone(); let header = packet[..offset].to_vec(); let host = host.clone();
                    tasks.spawn(async move {
                        let result: Result<()> = async {
                            let target = match classify_socks_target(&host, port, &[]) { Ok(t) => t, Err(_) => { let addresses = tokio::net::lookup_host((host.as_str(),port)).await?.map(|a|a.ip()).collect::<Vec<_>>(); classify_socks_target(&host,port,&addresses)? } };
                            let remote = match target {
                                SocksTarget::Address(addr,p) => clients.get(&addr).await?.dial_udp_port(p).await?,
                                SocksTarget::Server(p) => clients.get(clients.fixed.as_deref().context("missing server")?).await?.dial_udp_port(p).await?,
                                SocksTarget::Exit(target) => clients.get(clients.fixed.as_deref().context("missing exit server")?).await?.dial_udp(target).await?,
                            };
                            loop { tokio::select! {
                                bytes = rx.recv() => { let Some(bytes) = bytes else { return Ok(()) }; remote.send(&bytes).await?; },
                                bytes = remote.recv() => { let mut response = header.clone(); response.extend(bytes?); socket.send_to(&response, from).await?; },
                            } }
                        }.await;
                        if let Err(err) = result { tracing::debug!("SOCKS UDP: {err:#}"); }
                    });
                }
                if let Some(tx) = routes.get(&(host,port)) { let _ = tx.try_send(packet[offset..n].to_vec()); }
            }
        }
    }
}

pub async fn ssh(args: &Args) -> Result<()> {
    if args.positional.is_empty() {
        bail!("ssh requires a [user@]<tc-addr> destination argument");
    }
    let port = validated_ssh_port(&args.port)?;
    let (user, host) = args.positional[0]
        .split_once('@')
        .unwrap_or(("", &args.positional[0]));
    let address = validated_address(host).await?;
    if !args.skip_dns_safety_check
        && matches!(
            super::util::classify_address(host)?,
            super::util::AddressArg::DnsName(_)
        )
    {
        let probe = tokio::time::timeout(Duration::from_secs(10), async {
            let client = Client::connect(
                &address,
                Some(crate::protocol::PrivateKey::new()),
                Some(&args.derp_map_url),
            )
            .await?;
            let stream = if let Ok(target) = port.parse() {
                client.dial_tcp(target).await?
            } else {
                client.dial_tcp_port(port.parse()?).await?
            };
            let result = crate::services::probe_no_auth(stream, user).await;
            client.close().await;
            result
        })
        .await;
        if matches!(probe, Ok(Ok(true))) {
            bail!(
                "refusing to connect to {host}: its SSH server is wide open. DNS TXT records are public. Use --allow or --ssh-authorized-keys on the server, or --skip-dns-safety-check to connect anyway"
            );
        }
    }
    let host = ssh_dest_host(&address);
    let destination = if user.is_empty() {
        host
    } else {
        format!("{user}@{host}")
    };
    let mut command = ssh_command(args, "ssh", &address, &port)?;
    command
        .arg("--")
        .arg(destination)
        .args(&args.positional[1..]);
    exec_command(command)
}

pub async fn cp(args: &Args) -> Result<()> {
    if args.positional.len() < 2 {
        bail!("cp requires at least one source and a target");
    }
    let port = validated_ssh_port(&args.port)?;
    let mut server = None;
    for arg in &args.positional {
        if let Some((host, _)) = split_remote_arg(arg) {
            if server.is_some_and(|old| old != host) {
                bail!("all remote paths must name the same server");
            }
            server = Some(host);
        }
    }
    let address = validated_address(
        server.context("no remote <tc-addr>:path argument; nothing to copy through tailcat")?,
    )
    .await?;
    let mut command = ssh_command(args, "scp", &address, &port)?;
    if let Ok(output) = std::process::Command::new("scp")
        .args(["-s", "--"])
        .output()
    {
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .to_lowercase();
        if ![
            "unknown option -- s",
            "illegal option -- s",
            "invalid option -- s",
        ]
        .iter()
        .any(|s| text.contains(s))
        {
            command.arg("-s");
        }
    }
    if args.recursive {
        command.arg("-r");
    }
    if args.preserve {
        command.arg("-p");
    }
    command.arg("--");
    for arg in &args.positional {
        if let Some((_, path)) = split_remote_arg(arg) {
            command.arg(format!("{}:{path}", ssh_dest_host(&address)));
        } else {
            command.arg(arg);
        }
    }
    exec_command(command)
}

fn ssh_command(
    args: &Args,
    program: &str,
    address: &str,
    port: &str,
) -> Result<std::process::Command> {
    let exe = std::env::current_exe()?;
    let exe = exe
        .to_str()
        .context("tailcat executable path is not UTF-8")?;
    let proxy = ssh_proxy_command(exe, &args.key, &args.derp_map_url, address, port)?;
    let mut command = std::process::Command::new(program);
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    command.args([
        "-o",
        "UpdateHostKeys no",
        "-o",
        "StrictHostKeyChecking no",
        "-o",
        &format!("UserKnownHostsFile {null}"),
        "-o",
        "LogLevel ERROR",
        "-o",
        &format!("ProxyCommand={proxy}"),
    ]);
    Ok(command)
}

fn exec_command(mut command: std::process::Command) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        Err(command.exec()).context("failed to run system SSH client")
    }
    #[cfg(not(unix))]
    {
        let status = command
            .status()
            .context("failed to run system SSH client")?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

pub async fn ls(args: &Args) -> Result<()> {
    if args.positional.len() != 1 {
        bail!("ls requires one <tc-addr>[:path] argument");
    }
    let (host, path) = split_remote_arg(&args.positional[0]).unwrap_or((&args.positional[0], "."));
    let path = if path.is_empty() { "." } else { path };
    let client = connect(args, host).await?;
    let entries = tokio::time::timeout(Duration::from_secs(30), async {
        let stream = client.dial_tcp_port(22).await?;
        crate::services::list_files(stream, path).await
    })
    .await
    .context("file listing timed out")??;
    for entry in entries {
        let attributes = entry.attributes;
        let mode = attributes.permissions.unwrap_or(0);
        let is_dir = mode & 0o170000 == 0o040000;
        let name = format!("{}{}", entry.name, if is_dir { "/" } else { "" });
        if !args.long {
            println!("{name}");
            continue;
        }
        let modified = chrono::DateTime::from_timestamp(attributes.mtime.unwrap_or(0) as i64, 0)
            .unwrap_or_default()
            .with_timezone(&chrono::Local);
        let format = if chrono::Local::now()
            .signed_duration_since(modified)
            .num_days()
            > 180
        {
            "%b %e  %Y"
        } else {
            "%b %e %H:%M"
        };
        println!(
            "{} {:12} {} {name}",
            mode_string(mode),
            attributes.size.unwrap_or(0),
            modified.format(format)
        );
    }
    client.close().await;
    Ok(())
}

fn mode_string(mode: u32) -> String {
    let mut value = String::from(match mode & 0o170000 {
        0o040000 => "d",
        0o120000 => "L",
        _ => "-",
    });
    for (bit, c) in [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o40, 'r'),
        (0o20, 'w'),
        (0o10, 'x'),
        (0o4, 'r'),
        (0o2, 'w'),
        (0o1, 'x'),
    ] {
        value.push(if mode & bit != 0 { c } else { '-' });
    }
    value
}

pub async fn perf(args: &Args) -> Result<()> {
    if args.positional.len() != 1 {
        bail!("perf requires one <tc-addr>");
    }
    if args.reverse && args.bidir {
        bail!("--reverse and --bidir are exclusive");
    }
    let p = crate::perf::Params {
        proto: if args.perf_udp { "udp" } else { "tcp" }.into(),
        dir: if args.bidir {
            "both"
        } else if args.reverse {
            "down"
        } else {
            "up"
        }
        .into(),
        duration: if args.perf_bytes > 0 {
            0
        } else {
            args.perf_time.as_nanos().try_into()?
        },
        bytes: args.perf_bytes,
        streams: args.parallel,
        length: if args.length != 0 {
            args.length
        } else if args.perf_udp {
            1232
        } else {
            128 << 10
        },
        bitrate: args
            .bitrate
            .unwrap_or(if args.perf_udp { 1_000_000 } else { 0 }),
        interval: args.interval.as_nanos().try_into()?,
    };
    p.validate()?;
    let address = resolve_address(&args.positional[0]).await?;
    let mut info = protocol::parse_addr(&address)?;
    info.expand(Some(&args.derp_map_url), false).await?;
    let client = connect(args, &address).await?;
    let start = Instant::now();
    let path = loop {
        let path = client.disco_ping().await?;
        if path.endpoint.is_some() || start.elapsed() >= args.timeout {
            break path;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    if path.endpoint.is_none() {
        if !args.via_derp {
            bail!(
                "no direct path; refusing a throughput test through a DERP relay (use --via-derp for your own relay)"
            );
        }
        if info.region.iter().flat_map(|r| &r.nodes).any(|n| {
            let host = n.host_name.trim_end_matches('.').to_lowercase();
            host.ends_with(".ipn.dev") || host.ends_with(".tailscale.com")
        }) {
            bail!("refusing a throughput test through Tailscale's shared DERP relay");
        }
    }
    let describe_path = |p: &crate::runtime::PingResult| serde_json::json!({"direct":p.endpoint.is_some(),"endpoint":p.endpoint.map(|e|e.to_string()),"rtt":p.latency.as_nanos() as u64,"derpRegion":p.derp_region_id.to_string()});
    if let Some(endpoint) = path.endpoint {
        eprintln!("# path: direct via {endpoint}, rtt {:?}", path.latency);
    } else {
        eprintln!("# path: relayed via DERP({})", path.derp_region_id);
    }
    if !args.json {
        print!(
            "{}, {}, {} stream{}",
            p.proto.to_uppercase(),
            crate::perf::direction_name(&p.dir),
            p.streams,
            if p.streams == 1 { "" } else { "s" }
        );
        if p.bytes > 0 {
            print!(", {} B per stream", p.bytes);
        } else {
            print!(", {}s", p.duration as f64 / 1e9);
        }
        if p.bitrate > 0 {
            print!(", {} bit/s per stream", p.bitrate);
        }
        println!();
    }
    let mut result = tokio::select! { result = crate::perf::run_client(&client,p,!args.json) => result?, _ = shutdown_signal() => bail!("perf: interrupted") };
    result["path"] = describe_path(&path);
    if let Ok(Ok(after)) = tokio::time::timeout(Duration::from_secs(3), client.disco_ping()).await {
        result["pathAfter"] = describe_path(&after);
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        for (sender, receiver) in [
            ("clientSent", "serverReceived"),
            ("serverSent", "clientReceived"),
        ] {
            if !result[sender].is_object() {
                continue;
            }
            if args.bidir {
                println!(
                    "{}:",
                    if sender == "clientSent" {
                        "client -> server"
                    } else {
                        "server -> client"
                    }
                );
            }
            for (label, key) in [("sent", sender), ("received", receiver)] {
                let stats = &result[key];
                let bytes = stats["bytes"].as_u64().unwrap_or(0);
                let seconds = stats["duration"].as_u64().unwrap_or(0) as f64 / 1e9;
                print!(
                    "{label}  {bytes} B in {:.1}s {:.0} bit/s",
                    seconds,
                    if seconds > 0.0 {
                        bytes as f64 * 8.0 / seconds
                    } else {
                        0.0
                    }
                );
                if args.perf_udp {
                    let sent = result[sender]["datagrams"].as_u64().unwrap_or(0);
                    let received = result[receiver]["datagrams"].as_u64().unwrap_or(0);
                    print!("  {} datagrams", stats["datagrams"].as_u64().unwrap_or(0));
                    if label == "received" {
                        let lost = sent.saturating_sub(received);
                        print!(
                            ", {lost} lost ({:.1}%), {} reordered, jitter {}ns",
                            if sent > 0 {
                                lost as f64 * 100.0 / sent as f64
                            } else {
                                0.0
                            },
                            stats["reordered"].as_u64().unwrap_or(0),
                            stats["jitter"].as_u64().unwrap_or(0)
                        );
                    }
                }
                println!();
            }
        }
        if result["rtt"].is_object() {
            let r = &result["rtt"];
            println!(
                "rtt under load  min {}ns  avg {}ns  max {}ns  ({} samples)",
                r["min"], r["avg"], r["max"], r["count"]
            );
        }
    }
    client.drain_tcp(Duration::from_secs(5)).await?;
    client.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{Server, ServerConfig};

    #[tokio::test]
    async fn socks_udp_roundtrip_and_control_cleanup() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (region, _relay) = crate::derp::start_local_relay().await.unwrap();
            let server = Server::start(ServerConfig {
                region: Some(region),
                on_udp: Some(Arc::new(|_| {
                    Some(Arc::new(|remote| {
                        Box::pin(async move {
                            while let Ok(packet) = remote.recv().await {
                                if remote.send(&packet).await.is_err() {
                                    break;
                                }
                            }
                        })
                    }))
                })),
                ..Default::default()
            })
            .await
            .unwrap();
            let clients = Arc::new(SocksClients {
                args: Args::default(),
                key: protocol::PrivateKey::new(),
                fixed: Some(server.tailcat_addr()),
                clients: Mutex::new(HashMap::new()),
            });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let bound = listener.local_addr().unwrap();
            let peers = clients.clone();
            let association = tokio::spawn(async move {
                socks_connection(listener.accept().await.unwrap().0, peers)
                    .await
                    .unwrap();
            });
            let mut control = TcpStream::connect(bound).await.unwrap();
            control.write_all(&[5, 1, 0]).await.unwrap();
            let mut response = [0; 2];
            control.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 0]);
            control
                .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut response = [0; 10];
            control.read_exact(&mut response).await.unwrap();
            assert_eq!(&response[..4], &[5, 0, 0, 1]);
            let relay = SocketAddr::from((
                [127, 0, 0, 1],
                u16::from_be_bytes([response[8], response[9]]),
            ));
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut header = vec![0, 0, 0, 3, 14];
            header.extend(b"server.tailcat");
            header.extend(1234u16.to_be_bytes());
            for payload in [b"hello".as_slice(), b""] {
                let mut packet = header.clone();
                packet.extend(payload);
                socket.send_to(&packet, relay).await.unwrap();
                let mut response = [0; 1024];
                let (n, _) =
                    tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut response))
                        .await
                        .expect("waiting for UDP response")
                        .unwrap();
                assert_eq!(&response[..n], &packet);
            }
            assert!(udp_socks_target(&[0, 0, 1, 1, 0, 0, 0, 0, 0, 0]).is_err());
            drop(control);
            association.await.unwrap();
            clients.close().await;
            server.close().await;
        })
        .await
        .expect("SOCKS UDP test timed out");
    }
}
