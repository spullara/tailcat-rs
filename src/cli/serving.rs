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
                let mut local = TcpStream::connect(&destination).await?;
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
    let ssh = if spec.services.contains("no-auth-ssh") || files.is_some() {
        Some(Arc::new(SshConfig::new(
            spec.services.contains("no-auth-ssh"),
            files,
        )?))
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
                region: vec![],
                region_id: -1,
            },
            false,
        ),
    };
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
    let served_tcp_ports = if one_shot || exit_node {
        None
    } else {
        Some(port_ranges(&ports))
    };
    let done = Arc::new(Notify::new());
    let handler_done = done.clone();
    let verbose = args.verbose;
    let on_tcp = Arc::new(move |port: u16| -> Option<TcpHandler> {
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
        if exit_node {
            return Some(forwarding_handler(format!("localhost:{port}"), verbose));
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
            server_public: server.public_key(),
            server_disco_public: Some(disco),
            region: vec![region],
            region_id: 0,
        }
    } else {
        ConnInfo {
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
