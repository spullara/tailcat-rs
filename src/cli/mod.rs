//! Native Rust implementation of the Tailcat command line.

mod args;
mod clients;
mod keys;
mod serving;
mod util;

use anyhow::{Result, bail};
pub use args::Args;

pub async fn run(args: &Args) -> Result<()> {
    if args.help {
        print!("{}", args::help(&args.command));
        return Ok(());
    }
    match args.command.as_str() {
        "serve" | "recv" => serving::serve(args).await,
        "" if args.positional.is_empty() || !args.serve.is_empty() => serving::serve(args).await,
        "" => clients::pipe(args).await,
        "ping" => clients::ping(args).await,
        "socks" => clients::socks(args).await,
        "ssh" => clients::ssh(args).await,
        "cp" => clients::cp(args).await,
        "ls" => clients::ls(args).await,
        "forward" => clients::forward(args).await,
        "genkey" => keys::genkey(args).await,
        "parse" => {
            if args.positional.len() != 1 {
                bail!("parse requires one <tc-addr> argument");
            }
            let value = crate::protocol::parse_addr_raw(&args.positional[0])?;
            let mut writer = Vec::new();
            let mut serializer = serde_json::Serializer::with_formatter(
                &mut writer,
                serde_json::ser::PrettyFormatter::with_indent(b"    "),
            );
            serde::Serialize::serialize(&value, &mut serializer)?;
            println!("{}", String::from_utf8(writer)?);
            Ok(())
        }
        "resolve" => {
            if args.positional.len() != 1 {
                bail!("resolve requires one <tc-addr> argument");
            }
            let addr = util::resolve_address(&args.positional[0]).await?;
            let addr = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                crate::protocol::resolve_addr(&addr, Some(&args.derp_map_url)),
            )
            .await??;
            println!("{addr}");
            Ok(())
        }
        "printpub" => {
            println!("nodekey:{}", hex::encode(keys::client_key(args)?.public()));
            Ok(())
        }
        "version" => {
            println!(
                "{}",
                option_env!("TAILCAT_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
            );
            Ok(())
        }
        "readme" => {
            print!("{}", include_str!("../../README.md"));
            Ok(())
        }
        _ => bail!("unknown command {:?}", args.command),
    }
}

pub async fn main() -> i32 {
    crate::protocol::enable_disk_derp_cache();
    let input = std::env::args().skip(1).collect::<Vec<_>>();
    let args = match Args::parse(input.clone()) {
        Ok(args) => args,
        Err(err) => {
            let command = input
                .iter()
                .find(|arg| args::COMMANDS.contains(&arg.as_str()))
                .map(String::as_str)
                .unwrap_or("");
            eprintln!("{}\n{err:#}", args::help(command));
            return 1;
        }
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(if args.verbose {
            "tailcat=debug,boringtun=info"
        } else {
            "off"
        })
    });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
    if let Err(err) = run(&args).await {
        // Help for usage errors is intentionally kept off stdout: stdout may be
        // a pipe carrying user data or machine-readable JSON.
        if is_usage_error(&err.to_string()) {
            eprintln!("{}", args::help(&args.command));
        }
        eprintln!("{err:#}");
        1
    } else {
        0
    }
}

fn is_usage_error(error: &str) -> bool {
    [
        "requires",
        "takes ",
        "must be",
        "mutually exclusive",
        "probably a mistake",
        "positional",
        "use either",
        "no remote",
        "all remote",
        "invalid port",
        "mapping ",
    ]
    .iter()
    .any(|part| error.contains(part))
}

#[cfg(test)]
mod tests;
