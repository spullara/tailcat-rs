use super::args::DEFAULT_DERP_MAP_URL;
use crate::protocol;
use anyhow::{Context, Result, anyhow, bail};
use hickory_resolver::TokioAsyncResolver;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

#[derive(Debug, PartialEq, Eq)]
pub enum AddressArg {
    Address(String),
    DnsName(String),
}

pub fn classify_address(arg: &str) -> Result<AddressArg> {
    if protocol::parse_addr(arg).is_ok() {
        return Ok(AddressArg::Address(arg.into()));
    }
    if !arg.contains('.') {
        bail!("argument {arg:?} is neither a valid tailcat address nor a DNS name");
    }
    let name = arg.strip_suffix('.').unwrap_or(arg);
    for label in name.split('.') {
        if protocol::parse_addr(label).is_ok() {
            bail!("argument contains a valid tailcat address as a DNS label; refusing DNS lookup");
        }
    }
    validate_dns_name(name).with_context(|| format!("invalid DNS name {arg:?}"))?;
    Ok(AddressArg::DnsName(arg.into()))
}

pub fn validate_dns_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("name is empty");
    }
    if name.len() > 253 {
        bail!("name is longer than 253 bytes");
    }
    for label in name.split('.') {
        if label.is_empty() {
            bail!("name contains an empty label");
        }
        if label.len() > 63 {
            bail!("name contains a label longer than 63 bytes");
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("name contains a label beginning or ending with a hyphen");
        }
        if let Some(c) = label
            .bytes()
            .find(|c| !c.is_ascii_alphanumeric() && *c != b'-')
        {
            bail!("name contains invalid character {:?}", c as char);
        }
    }
    Ok(())
}

pub async fn resolve_address(arg: &str) -> Result<String> {
    match classify_address(arg)? {
        AddressArg::Address(addr) => Ok(addr),
        AddressArg::DnsName(name) => {
            let resolver = TokioAsyncResolver::tokio_from_system_conf()
                .context("loading DNS resolver configuration")?;
            let txts =
                tokio::time::timeout(Duration::from_secs(5), resolver.txt_lookup(name.clone()))
                    .await
                    .context("DNS lookup timed out")?
                    .with_context(|| format!("looking up TXT record for {name:?}"))?;
            for txt in txts.iter() {
                let value = txt
                    .txt_data()
                    .iter()
                    .flat_map(|part| part.iter().copied())
                    .collect::<Vec<_>>();
                if let Some(addr) = String::from_utf8_lossy(&value).strip_prefix("tailcat=") {
                    let addr = addr.trim().to_string();
                    protocol::parse_addr(&addr).context("invalid tailcat= TXT record")?;
                    return Ok(addr);
                }
            }
            bail!("no \"tailcat=\" TXT record found for {name:?}")
        }
    }
}

pub async fn validated_address(arg: &str) -> Result<String> {
    if arg.contains('.') {
        resolve_address(arg).await
    } else {
        protocol::parse_addr(arg).with_context(|| format!("invalid tailcat address {arg:?}"))?;
        Ok(arg.into())
    }
}

pub fn decimal_port(value: &str, allow_zero: bool) -> Result<u16> {
    if value.is_empty() || !value.bytes().all(|c| c.is_ascii_digit()) {
        bail!("invalid port {value:?}");
    }
    let port: u16 = value
        .parse()
        .with_context(|| format!("invalid port {value:?}"))?;
    if port == 0 && !allow_zero {
        bail!("invalid port {value:?}");
    }
    Ok(port)
}

pub fn validated_ssh_port(value: &str) -> Result<String> {
    if let Ok(p) = decimal_port(value, false) {
        return Ok(p.to_string());
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 22).to_string());
    }
    if let Ok(ap) = value.parse::<SocketAddr>()
        && ap.port() != 0
    {
        return Ok(ap.to_string());
    }
    bail!("invalid port or IP:port {value:?}")
}

pub fn split_remote_arg(arg: &str) -> Option<(&str, &str)> {
    let i = arg.find(':')?;
    if i <= 1 || arg[..i].contains(['/', '\\']) {
        return None;
    }
    Some((&arg[..i], &arg[i + 1..]))
}

pub fn ssh_dest_host(addr: &str) -> String {
    format!(
        "tailcat-{}",
        hex::encode(&Sha256::digest(addr.as_bytes())[..8])
    )
}

pub fn proxy_command_join_unix(args: &[String]) -> Result<String> {
    args.iter()
        .map(|arg| {
            if arg.contains(['\r', '\n', '\0']) {
                bail!("ProxyCommand argument contains a control character");
            }
            Ok(format!(
                "'{}'",
                arg.replace('%', "%%").replace('\'', "'\"'\"'")
            ))
        })
        .collect::<Result<Vec<_>>>()
        .map(|args| args.join(" "))
}

pub fn proxy_command_join_windows(args: &[String]) -> Result<String> {
    args.iter()
        .map(|arg| {
            if arg.contains(['"', '%', '!', '\r', '\n', '\0']) {
                bail!("ProxyCommand argument contains a character unsafe for cmd.exe");
            }
            Ok(format!(
                "\"{}{}\"",
                arg,
                "\\".repeat(arg.len() - arg.trim_end_matches('\\').len())
            ))
        })
        .collect::<Result<Vec<_>>>()
        .map(|args| args.join(" "))
}

pub fn ssh_proxy_command(
    exe: &str,
    key: &str,
    url: &str,
    addr: &str,
    port: &str,
) -> Result<String> {
    let mut args = vec![exe.to_string()];
    if !key.is_empty() {
        args.push(format!("--key={key}"));
    }
    if url != DEFAULT_DERP_MAP_URL {
        args.push(format!("--derpmap-url={url}"));
    }
    args.extend([addr.to_string(), port.to_string()]);
    if cfg!(windows) {
        proxy_command_join_windows(&args)
    } else {
        proxy_command_join_unix(&args)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardSpec {
    pub listen_addr: String,
    pub target: Option<SocketAddr>,
    pub port: u16,
}

impl ForwardSpec {
    pub fn remote_target(&self) -> String {
        self.target
            .map_or_else(|| format!("localhost:{}", self.port), |ap| ap.to_string())
    }
}

pub fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub fn parse_forward_spec(bind: &str, spec: &str) -> Result<ForwardSpec> {
    let (local, remote, colon) = spec
        .split_once(':')
        .map_or((spec, spec, false), |(l, r)| (l, r, true));
    let local_port = decimal_port(local, colon).context("local port")?;
    let listen_addr = join_host_port(bind, local_port);
    if let Ok(port) = decimal_port(remote, false) {
        return Ok(ForwardSpec {
            listen_addr,
            target: None,
            port,
        });
    }
    let target = remote
        .parse::<SocketAddr>()
        .map_err(|_| anyhow!("remote target {remote:?} is not a port or address:port"))?;
    Ok(ForwardSpec {
        listen_addr,
        target: Some(target),
        port: 0,
    })
}

pub fn normalize_listen(value: &str) -> String {
    if let Ok(port) = decimal_port(value, true) {
        return format!("127.0.0.1:{port}");
    }
    if let Some((host, port)) = value.rsplit_once(':')
        && (!host.contains(':') || (host.starts_with('[') && host.ends_with(']')))
    {
        return format!("{host}:{}", if port.is_empty() { "0" } else { port });
    }
    format!("{value}:0")
}

#[derive(Debug, Default)]
pub struct ServeSpec {
    pub ports: BTreeSet<u16>,
    pub services: BTreeSet<String>,
}

pub fn parse_serve_spec(value: &str) -> Result<ServeSpec> {
    let mut spec = ServeSpec::default();
    if value.is_empty() {
        return Ok(spec);
    }
    for part in value.trim().split(',').map(str::trim) {
        match part {
            "all" => spec.ports.extend(1..=u16::MAX),
            "exit-node" | "no-auth-ssh" | "files" => {
                spec.services.insert(part.into());
            }
            _ => {
                let (a, b) = part.split_once('-').unwrap_or((part, part));
                let lo = decimal_port(a, true).with_context(|| format!("{part:?} is not a known named service or port (want all, no-auth-ssh, files, exit-node)"))?;
                let hi = decimal_port(b, true)?;
                spec.ports.extend(lo.min(hi)..=lo.max(hi));
            }
        }
    }
    Ok(spec)
}

pub fn port_ranges(ports: &BTreeSet<u16>) -> Vec<(u16, u16)> {
    let mut ranges: Vec<(u16, u16)> = vec![];
    for &p in ports {
        if let Some(last) = ranges.last_mut()
            && last.1.checked_add(1) == Some(p)
        {
            last.1 = p;
            continue;
        }
        ranges.push((p, p));
    }
    ranges
}

pub fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        _ => ip,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SocksTarget {
    Server(u16),
    Address(String, u16),
    Exit(SocketAddr),
}

pub fn classify_socks_target(host: &str, port: u16, resolved: &[IpAddr]) -> Result<SocksTarget> {
    if host.is_empty() || host == "server.tailcat" {
        return Ok(SocksTarget::Server(port));
    }
    if host.starts_with("tc") && !host.contains('.') && protocol::parse_addr(host).is_ok() {
        return Ok(SocksTarget::Address(host.into(), port));
    }
    let ip = match host.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => *resolved
            .iter()
            .find(|ip| unmap(**ip).is_ipv4())
            .or(resolved.first())
            .ok_or_else(|| anyhow!("no addresses found for {host:?}"))?,
    };
    Ok(SocksTarget::Exit(SocketAddr::new(unmap(ip), port)))
}
