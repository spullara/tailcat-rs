//! The original CLI stops parsing flags at the first positional argument.
//! Keeping that rule is essential for commands passed through to SSH and SOCKS.

use anyhow::{Result, anyhow, bail};
use std::{collections::BTreeSet, time::Duration};

pub const COMMANDS: &[&str] = &[
    "serve", "recv", "ping", "socks", "ssh", "cp", "ls", "forward", "parse", "resolve", "genkey",
    "printpub", "version", "readme",
];
pub const DEFAULT_DERP_MAP_URL: &str = "https://tailcat.dev/derpmap.json";

#[derive(Clone, Debug)]
pub struct Args {
    pub command: String,
    pub positional: Vec<String>,
    pub serve: String,
    pub key: String,
    pub verbose: bool,
    pub json: bool,
    pub derp_map_url: String,
    pub allow: String,
    pub full_address: bool,
    pub files: String,
    pub accept_dirs: bool,
    pub until_direct: bool,
    pub timeout: Duration,
    pub listen: String,
    pub bind: String,
    pub port: String,
    pub recursive: bool,
    pub preserve: bool,
    pub long: bool,
    pub genkey_key: String,
    pub client: bool,
    pub force: bool,
    pub delete: bool,
    pub list: bool,
    pub region: String,
    pub fixed_region: bool,
    pub embed_derp_map: bool,
    pub explicit: BTreeSet<String>,
    pub help: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            command: String::new(),
            positional: vec![],
            serve: String::new(),
            key: String::new(),
            verbose: false,
            json: false,
            derp_map_url: std::env::var("TAILCAT_DERPMAP_URL")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_DERP_MAP_URL.into()),
            allow: String::new(),
            full_address: false,
            files: String::new(),
            accept_dirs: false,
            until_direct: false,
            timeout: Duration::from_secs(10),
            listen: "127.0.0.1:0".into(),
            bind: "127.0.0.1".into(),
            port: "22".into(),
            recursive: false,
            preserve: false,
            long: false,
            genkey_key: String::new(),
            client: false,
            force: false,
            delete: false,
            list: false,
            region: "auto".into(),
            fixed_region: false,
            embed_derp_map: false,
            explicit: BTreeSet::new(),
            help: false,
        }
    }
}

impl Args {
    pub fn parse(input: impl IntoIterator<Item = String>) -> Result<Self> {
        let input: Vec<_> = input.into_iter().collect();
        let mut out = Self::default();
        let mut i = 0;
        while i < input.len() {
            let arg = &input[i];
            if arg == "--" {
                out.positional.extend_from_slice(&input[i + 1..]);
                break;
            }
            if arg == "--version" {
                out.command = "version".into();
                return Ok(out);
            }
            if arg == "-h" || arg == "--help" {
                out.help = true;
                return Ok(out);
            }
            if !arg.starts_with('-') || arg == "-" {
                if out.command.is_empty() && COMMANDS.contains(&arg.as_str()) {
                    out.command = arg.clone();
                    i += 1;
                    continue;
                }
                if out.command.is_empty() && arg == "help" {
                    out.help = true;
                    return Ok(out);
                }
                out.positional.extend_from_slice(&input[i..]);
                break;
            }
            let (name, inline) = arg
                .split_once('=')
                .map_or((arg.as_str(), None), |(n, v)| (n, Some(v)));
            let server = out.command == "serve" || out.command == "recv";
            let boolean = match name {
                "--verbose" | "--json" => true,
                "--full-address" if server => true,
                "--accept-dirs" if out.command == "recv" => true,
                "--until-direct" if out.command == "ping" => true,
                "-r" | "-p" if out.command == "cp" => true,
                "-l" if out.command == "ls" => true,
                "--client" | "--force" | "--delete" | "--list" | "--fixed-region"
                | "--embed-derp-map"
                    if out.command == "genkey" =>
                {
                    true
                }
                _ => false,
            };
            let value = if boolean {
                match inline {
                    None => "true",
                    Some("true") => "true",
                    Some("false") => "false",
                    _ => bail!("invalid boolean value for {name}"),
                }
                .to_owned()
            } else if let Some(v) = inline {
                v.to_owned()
            } else {
                i += 1;
                if i == input.len() {
                    if name == "--serve" {
                        out.command = "serve".into();
                        out.help = true;
                        return Ok(out);
                    }
                    bail!("missing value for {name}");
                }
                input[i].clone()
            };
            let yes = value == "true";
            match name {
                "--serve" => out.serve = value,
                "--key" if out.command == "genkey" => out.genkey_key = value,
                "--key" => out.key = value,
                "--verbose" => out.verbose = yes,
                "--json" => out.json = yes,
                "--derpmap-url" => out.derp_map_url = value,
                "--allow" if server => out.allow = value,
                "--full-address" if server => out.full_address = yes,
                "--files" if server => out.files = value,
                "--accept-dirs" if out.command == "recv" => out.accept_dirs = yes,
                "--until-direct" if out.command == "ping" => out.until_direct = yes,
                "--timeout" if out.command == "ping" => out.timeout = parse_duration(&value)?,
                "--listen" if out.command == "socks" => out.listen = value,
                "--bind" if out.command == "forward" => out.bind = value,
                "-p" if out.command == "ssh" => out.port = value,
                "-P" if out.command == "cp" => out.port = value,
                "-r" if out.command == "cp" => out.recursive = yes,
                "-p" if out.command == "cp" => out.preserve = yes,
                "-l" if out.command == "ls" => out.long = yes,
                "--client" if out.command == "genkey" => out.client = yes,
                "--force" if out.command == "genkey" => out.force = yes,
                "--delete" if out.command == "genkey" => out.delete = yes,
                "--list" if out.command == "genkey" => out.list = yes,
                "--region" if out.command == "genkey" => out.region = value,
                "--fixed-region" if out.command == "genkey" => out.fixed_region = yes,
                "--embed-derp-map" if out.command == "genkey" => out.embed_derp_map = yes,
                _ => bail!("unknown flag {name}"),
            }
            out.explicit.insert(name.trim_start_matches('-').to_owned());
            i += 1;
        }
        Ok(out)
    }
}

pub fn parse_duration(value: &str) -> Result<Duration> {
    if value == "0" {
        return Ok(Duration::ZERO);
    }
    let mut rest = value;
    let mut secs = 0f64;
    while !rest.is_empty() {
        let n = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .ok_or_else(|| anyhow!("invalid duration {value:?}"))?;
        let amount: f64 = rest[..n].parse()?;
        rest = &rest[n..];
        let (unit, multiplier) = [
            ("ns", 1e-9),
            ("us", 1e-6),
            ("µs", 1e-6),
            ("μs", 1e-6),
            ("ms", 1e-3),
            ("s", 1.),
            ("m", 60.),
            ("h", 3600.),
        ]
        .into_iter()
        .find(|(u, _)| rest.starts_with(u))
        .ok_or_else(|| anyhow!("invalid duration {value:?}"))?;
        secs += amount * multiplier;
        rest = &rest[unit.len()..];
    }
    Duration::try_from_secs_f64(secs).map_err(Into::into)
}

pub fn help(command: &str) -> String {
    let globals = "  --key <name|path|new>  Saved identity (default/client-default when present)\n  --verbose              Verbose networking logs\n  --json                 Print server listenAddr JSON\n  --derpmap-url <URL>     DERP map URL (or TAILCAT_DERPMAP_URL)\n  --serve <services>      Server ports/services\n  -h, --help             Print help\n";
    let (usage, description, flags) = match command {
        "serve" => (
            "tailcat serve [flags] [<port,service,...> ...]",
            "Serve local ports, ranges, all, exit-node, no-auth-ssh, or files.\nWith no services, accept one connection and copy it to stdout.",
            "  --allow <keys|none>  Allowed node public keys\n  --full-address      Embed relay information in the address\n  --files <dir[:ro|rw|wo|wo+]>  File directory (default current directory, read-only)\n",
        ),
        "recv" => (
            "tailcat recv [flags] [<dir>]",
            "Receive files in a write-only drop box (default current directory).",
            "  --accept-dirs  Accept directory trees (permits directory creation/stat)\n  --allow <keys|none>\n  --full-address\n",
        ),
        "ping" => (
            "tailcat ping [flags] <tc-addr>",
            "Ping a server, reporting the DERP or direct path.",
            "  --until-direct  Continue until a direct path works\n  --timeout <duration>  Deadline (default 10s)\n",
        ),
        "socks" => (
            "tailcat socks [flags] [<tc-addr>] [<cmd> [args...]]",
            "Run SOCKS5; child commands receive all_proxy. server.tailcat means the fixed server; other destinations use its exit node.",
            "  --listen <address:port>  Default 127.0.0.1:0; bare port means localhost\n",
        ),
        "ssh" => (
            "tailcat ssh [-p <port|ip:port>] [user@]<tc-addr> [<command> [args...]]",
            "Connect the system SSH client through tailcat.",
            "  -p <port|ip:port>  SSH port (default 22); a bare IP means port 22\n",
        ),
        "cp" => (
            "tailcat cp [-r] [-p] [-P <port>] <source>... <target>",
            "Copy using system scp. Remote paths use <tc-addr>:path.",
            "  -r  Recursively copy directories\n  -p  Preserve timestamps and modes\n  -P <port>  SSH port (default 22)\n",
        ),
        "ls" => (
            "tailcat ls [-l] <tc-addr>[:path]",
            "List files offered by a tailcat server using SFTP.",
            "  -l  Long listing: permissions, size, modification time\n",
        ),
        "forward" => (
            "tailcat forward [flags] <tc-addr> <[local:]remote-port|local-port:remote-ip:remote-port> ...",
            "Forward local TCP listeners to a tailcat server. Local port 0 selects a free port.",
            "  --bind <address>  Local bind address (default 127.0.0.1)\n",
        ),
        "genkey" => (
            "tailcat genkey --key=<name> [flags]",
            "Generate, list, or delete saved keys. Server default: default; client default: client-default.",
            "  --key <name|path>  Required key name or path\n  --client  Create client identity only\n  --force   Overwrite an existing key\n  --delete  Delete the named key\n  --list    List saved key names\n  --region <auto|list|id|code|hostname>  Relay selection (default auto)\n  --fixed-region  Pick the nearest region now\n  --embed-derp-map  Embed relay nodes in the address\n",
        ),
        "parse" => (
            "tailcat parse <tc-addr>",
            "Decode address fields as JSON.",
            "",
        ),
        "resolve" => (
            "tailcat resolve <tc-addr>",
            "Expand an address to embed DERP server information.",
            "",
        ),
        "printpub" => (
            "tailcat printpub",
            "Print the public key selected for client mode.",
            "",
        ),
        "version" => ("tailcat version", "Print the version.", ""),
        "readme" => ("tailcat readme", "Print the complete README.", ""),
        _ => (
            "tailcat [flags] [<subcommand> [flags]] [args...]",
            "Securely pipe or serve network connections over WireGuard and DERP, without a control plane.\nNo arguments: accept one connection into stdout. <tc-addr> [port]: pipe stdin/stdout (default port 1).\nAddresses may be DNS names with a tailcat= TXT record.",
            "",
        ),
    };
    let commands = if command.is_empty() {
        format!("\nSUBCOMMANDS\n  {}\n", COMMANDS.join("  "))
    } else {
        String::new()
    };
    format!(
        "USAGE\n  {usage}\n\n{description}\n{commands}\nFLAGS\n{flags}{globals}\nFlags precede positional arguments.\nTAILCAT_ADDR_FILE writes the listening address to a file, or tcp:<address>.\n"
    )
}
