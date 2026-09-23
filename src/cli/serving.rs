use super::{
    args::Args,
    clients::shutdown_signal,
    keys::{secure_write, selected_key},
    util::{parse_serve_spec, port_ranges},
};
use crate::{
    protocol::{self, ConnInfo, PrivateKey},
    runtime::{Server, ServerConfig, TcpHandler},
    services::{FileShare, SshConfig},
};
use anyhow::{Context, Result, bail};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncWriteExt, DuplexStream},
    net::TcpStream,
    sync::Notify,
};

fn forwarding_handler(destination: String, verbose: bool) -> TcpHandler {
    Arc::new(move |mut remote: DuplexStream| {
        let destination = destination.clone();
        Box::pin(async move {
            let result: Result<()> = async {
                let mut local = if let Some(port) = destination.strip_prefix("localhost:") {
                    let port = port.parse::<u16>()?;
                    match TcpStream::connect((std::net::Ipv6Addr::LOCALHOST, port)).await {
                        Ok(stream) => stream,
                        Err(_) => TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await?,
                    }
                } else {
                    TcpStream::connect(&destination).await?
                };
                tokio::io::copy_bidirectional(&mut remote, &mut local).await?;
                Ok(())
            }
            .await;
            if verbose && let Err(err) = result {
                eprintln!("error proxying to {destination}: {err:#}");
            }
        })
    })
}

fn udp_forwarding_handler(target: std::net::SocketAddr) -> crate::runtime::UdpHandler {
    Arc::new(move |remote| {
        Box::pin(async move {
            let result: Result<()> = async {
            let local = tokio::net::UdpSocket::bind(if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
            local.connect(target).await?;
            let mut bytes = vec![0; 65536];
            loop {
                tokio::select! {
                    packet = remote.recv() => { local.send(&packet?).await?; }
                    packet = local.recv(&mut bytes) => { remote.send(&bytes[..packet?]).await?; }
                }
            }
        }.await;
            if let Err(err) = result {
                tracing::debug!("UDP forward: {err:#}");
            }
        })
    })
}

pub async fn serve(args: &Args) -> Result<()> {
    let mut value = args.serve.clone();
    let mut files_value = args.files.clone();
    if args.command == "recv" {
        if args.positional.len() > 1 {
            bail!("recv takes at most one directory argument");
        }
        if !files_value.is_empty() {
            bail!("recv takes the directory as an argument, not --files");
        }
        files_value = format!(
            "{}:{}",
            args.positional.first().map(String::as_str).unwrap_or("."),
            if args.accept_dirs { "wo+" } else { "wo" }
        );
        value.clear();
    } else if !args.positional.is_empty() {
        if args.command.is_empty() {
            bail!("no positional arguments are valid along with --serve");
        }
        if !value.is_empty() {
            bail!("use either --serve or positional port/service arguments, not both");
        }
        value = args.positional.join(",");
    }
    let mut spec = parse_serve_spec(&value).context("invalid port or service to serve")?;
    if !files_value.is_empty() {
        spec.services.insert("files".into());
    }
    let exec_args = crate::services::resolve_command(&args.exec).context("exec command:")?;
    if !args.exec.is_empty()
        && !spec.services.contains("ssh")
        && !spec.services.contains("no-auth-ssh")
    {
        spec.services.insert("exec".into());
    }
    if spec.services.contains("perf") && spec.ports.contains(&crate::perf::PORT) {
        bail!("port 5201 is used by the 'perf' service and cannot also be proxied");
    }
    let exec_service = spec.services.contains("exec");
    if exec_service && args.exec.is_empty() {
        bail!("exec requires a command after --");
    }
    if !args.exec.is_empty()
        && !exec_service
        && !spec.services.contains("ssh")
        && !spec.services.contains("no-auth-ssh")
    {
        bail!("command after -- requires exec or SSH service");
    }
    if !args.exec.is_empty()
        && (spec.services.contains("ssh") || spec.services.contains("no-auth-ssh"))
        && spec.services.contains("files")
    {
        bail!("files cannot be served with an SSH -- command");
    }

    for (port, target) in &spec.targets {
        eprintln!("# Proxying port {port} to {target}");
    }
    let one_shot = spec.ports.is_empty() && spec.services.is_empty();
    let exit_node = spec.services.contains("exit-node");
    let files = if spec.services.contains("files") {
        Some(FileShare::parse(if files_value.is_empty() {
            "."
        } else {
            &files_value
        })?)
    } else {
        None
    };
    let authenticated_ssh = spec.services.contains("ssh");
    let no_auth_ssh = spec.services.contains("no-auth-ssh");
    if authenticated_ssh && no_auth_ssh {
        bail!("ssh and no-auth-ssh are mutually exclusive");
    }
    if authenticated_ssh && args.ssh_authorized_keys.is_empty() {
        bail!("ssh requires --ssh-authorized-keys");
    }
    if !args.ssh_authorized_keys.is_empty() && !authenticated_ssh {
        bail!("--ssh-authorized-keys requires the ssh service");
    }
    if no_auth_ssh && args.allow.is_empty() {
        eprintln!(
            "# ⚠️ WARNING: no-auth-ssh {} anyone with this address; keep it secret (never in a DNS TXT record) or restrict clients with --allow",
            if exec_args.is_empty() {
                "gives a shell to"
            } else {
                "runs the command for"
            }
        );
    }
    if !exec_args.is_empty() {
        eprintln!(
            "{}{}{}",
            if exec_service {
                "# Running "
            } else {
                "# SSH sessions run only "
            },
            exec_args.join(" "),
            if exec_service {
                " for each connection"
            } else {
                ""
            }
        );
    }
    if spec.services.contains("perf") {
        eprintln!("# Accepting perf tests");
    }
    let ssh = if authenticated_ssh || no_auth_ssh || files.is_some() {
        let mut config = SshConfig::new(authenticated_ssh || no_auth_ssh, files)?;
        config.forced_command = exec_args.clone();
        if authenticated_ssh {
            config.authorized_keys =
                Some(crate::services::load_authorized_keys(&args.ssh_authorized_keys).await?);
        }
        Some(Arc::new(config))
    } else {
        None
    };
    let mut allowed = vec![];
    if !args.allow.is_empty() {
        for value in args.allow.split(',') {
            if value == "none" {
                allowed.push([0; 32]);
                continue;
            }
            let bytes = hex::decode(
                value
                    .strip_prefix("nodekey:")
                    .context("--allow keys must begin with nodekey:")?,
            )
            .with_context(|| format!("invalid key {value:?} in --allow"))?;
            allowed.push(
                bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid key length in --allow"))?,
            );
        }
    }
    let saved = selected_key(args, true)?;
    let (key, info, saved_identity) = match saved {
        Some(saved) => (saved.private, saved.public, true),
        None => (
            PrivateKey::new(),
            ConnInfo {
                server_public: [0; 32],
                server_disco_public: None,
                preshared_key: None,
                region: vec![],
                region_id: -1,
            },
            false,
        ),
    };
    let use_psk = args.psk
        && (!saved_identity || info.preshared_key.is_some() || args.explicit.contains("psk"));
    if saved_identity && use_psk && info.preshared_key.is_none() {
        bail!("key file has no WireGuard pre-shared key");
    }
    let psk = if use_psk {
        Some(info.preshared_key.unwrap_or_else(rand::random))
    } else {
        None
    };
    if psk.is_none() {
        if saved_identity {
            eprintln!(
                "# ⚠️ WARNING: saved key {:?} is not using a WireGuard PSK",
                if args.key.is_empty() {
                    "default"
                } else {
                    &args.key
                }
            );
        } else {
            eprintln!("# ⚠️ WARNING: serving without a WireGuard PSK");
        }
    }
    let local_relay = if std::env::var("TS_DEBUG_TAILCAT_LOCAL_DERP")
        .is_ok_and(|value| value == "1" || value == "true")
    {
        eprintln!("Local DERP mode.");
        Some(crate::derp::start_local_relay().await?)
    } else {
        None
    };
    let embed = args.full_address || !info.region.is_empty() || local_relay.is_some();
    let mut ports: BTreeSet<u16> = spec.ports.clone();
    if ssh.is_some() {
        ports.insert(22);
    }
    if spec.services.contains("perf") {
        ports.insert(crate::perf::PORT);
    }
    let served_tcp_ports = if one_shot || exit_node || exec_service {
        None
    } else {
        Some(port_ranges(&ports))
    };
    let perf = spec
        .services
        .contains("perf")
        .then(|| Arc::new(crate::perf::Server::default()));
    let perf_udp = perf.clone();
    let done = Arc::new(Notify::new());
    let handler_done = done.clone();
    let verbose = args.verbose;
    let on_tcp = Arc::new(move |port: u16| -> Option<TcpHandler> {
        if port == crate::perf::PORT
            && let Some(perf) = &perf
        {
            return Some(perf.tcp());
        }
        if port == 22
            && let Some(config) = &ssh
        {
            let config = config.clone();
            return Some(Arc::new(move |stream| {
                let config = config.clone();
                Box::pin(async move {
                    if let Err(err) = crate::services::serve_ssh(stream, config).await
                        && verbose
                    {
                        eprintln!("SSH: {err:#}");
                    }
                })
            }));
        }

        if one_shot {
            let done = handler_done.clone();
            return Some(Arc::new(move |mut stream| {
                let done = done.clone();
                Box::pin(async move {
                    let mut stdout = tokio::io::stdout();
                    let result = tokio::io::copy(&mut stream, &mut stdout).await;
                    if let Err(err) = result {
                        eprintln!("copying connection to stdout: {err}");
                    }
                    let _ = stdout.flush().await;
                    let _ = stream.shutdown().await;
                    drop(stream);
                    done.notify_one();
                })
            }));
        }
        if spec.ports.contains(&port) {
            Some(forwarding_handler(
                spec.targets
                    .get(&port)
                    .cloned()
                    .unwrap_or_else(|| format!("localhost:{port}")),
                verbose,
            ))
        } else if exec_service {
            Some(crate::services::exec_handler(exec_args.clone()))
        } else if exit_node {
            Some(forwarding_handler(format!("localhost:{port}"), verbose))
        } else {
            None
        }
    });
    let on_tcp_forward = if exit_node {
        Some(
            Arc::new(move |target| Some(forwarding_handler(format!("{target}"), verbose)))
                as Arc<dyn Fn(std::net::SocketAddr) -> Option<TcpHandler> + Send + Sync>,
        )
    } else {
        None
    };
    let disco = key.disco_public();
    let server = Server::start(ServerConfig {
        key: Some(key),
        preshared_key: psk,
        disable_preshared_key: !use_psk,
        region: local_relay
            .as_ref()
            .map(|(region, _)| region.clone())
            .or_else(|| info.region.first().cloned()),
        region_id: info.region_id,
        derp_map_url: Some(args.derp_map_url.clone()),
        allowed_clients: allowed,
        on_tcp: Some(on_tcp),
        on_tcp_forward,
        served_tcp_ports,
        on_udp: perf_udp.map(|perf| {
            Arc::new(move |port| (port == crate::perf::PORT).then(|| perf.udp()))
                as crate::runtime::UdpPortHandler
        }),
        on_udp_forward: exit_node.then(|| {
            Arc::new(|target| Some(udp_forwarding_handler(target)))
                as crate::runtime::UdpForwardHandler
        }),
        ..Default::default()
    })
    .await
    .context("Server.Start")?;
    let mut region = server.region().clone();
    eprintln!(
        "# Selected bootstrap relay region {}, {}",
        region.region_id, region.region_name
    );
    let info = if embed {
        region.region_code.clear();
        region.nodes.truncate(1);
        for node in &mut region.nodes {
            node.region_id = 0;
        }
        ConnInfo {
            preshared_key: psk,
            server_public: server.public_key(),
            server_disco_public: Some(disco),
            region: vec![region],
            region_id: 0,
        }
    } else {
        ConnInfo {
            preshared_key: psk,
            server_public: server.public_key(),
            server_disco_public: Some(disco),
            region: vec![],
            region_id: region.region_id,
        }
    };
    let address = protocol::encode_addr(&info)?;
    if saved_identity {
        eprintln!(
            "# 🐈 Server listening with saved key {:?}: {address}",
            if args.key.is_empty() {
                "default"
            } else {
                &args.key
            }
        );
    } else {
        eprintln!("# 🐈 Server listening with new address: {address}");
    }
    if args.json {
        println!("{}", serde_json::json!({"listenAddr":address}));
    }
    if let Ok(path) = std::env::var("TAILCAT_ADDR_FILE")
        && !path.is_empty()
    {
        if let Some(target) = path.strip_prefix("tcp:") {
            let mut stream = TcpStream::connect(target)
                .await
                .with_context(|| format!("TAILCAT_ADDR_FILE tcp dial {target:?}"))?;
            stream.write_all(format!("{address}\n").as_bytes()).await?;
            stream.shutdown().await?;
        } else {
            secure_write(std::path::Path::new(&path), address.as_bytes(), true)?;
        }
    }
    tokio::select! { _ = done.notified(), if one_shot => {}, result = shutdown_signal() => result? }
    server.drain_tcp(Duration::from_secs(5)).await?;
    server.close().await;
    Ok(())
}
