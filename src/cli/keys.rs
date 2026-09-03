use super::args::Args;
use crate::protocol::{self, ConnInfo, Node, PrivateKey, Region};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
pub struct SavedKey {
    #[serde(rename = "Private")]
    pub private: PrivateKey,
    #[serde(rename = "Public")]
    pub public: ConnInfo,
}

pub fn key_is_path(name: &str) -> bool {
    name.contains(['/', '\\'])
}

pub fn key_dir() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .context("cannot determine user configuration directory")?
        .join("tailcat")
        .join("keys"))
}

pub fn key_path(name: &str) -> Result<PathBuf> {
    if key_is_path(name) {
        Ok(name.into())
    } else {
        Ok(key_dir()?.join(format!("{name}.private.json")))
    }
}

pub fn read_key(name: &str) -> Result<SavedKey> {
    let path = key_path(name)?;
    let data = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&data).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn selected_key(args: &Args, server: bool) -> Result<Option<SavedKey>> {
    let default = if server { "default" } else { "client-default" };
    let name = if args.key.is_empty() {
        match fs::metadata(key_path(default)?) {
            Ok(_) => default,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        }
    } else {
        &args.key
    };
    if name == "new" {
        Ok(None)
    } else {
        read_key(name).map(Some)
    }
}

pub fn client_key(args: &Args) -> Result<PrivateKey> {
    Ok(selected_key(args, false)?.map_or_else(PrivateKey::new, |saved| saved.private))
}

pub fn secure_write(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    if !force {
        let mut file = options.open(path).with_context(|| {
            format!(
                "{} already exists or cannot be created; use --force to overwrite",
                path.display()
            )
        })?;
        file.write_all(bytes)?;
        file.sync_all()?;
        return Ok(());
    }
    // Replace atomically rather than following an existing symlink or retaining
    // permissions from an older, less restrictive key file.
    let filename = path
        .file_name()
        .context("key path has no file name")?
        .to_string_lossy();
    let temporary = path.with_file_name(format!(
        ".{filename}.{}.{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let result = (|| -> Result<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub async fn genkey(args: &Args) -> Result<()> {
    if !args.key.is_empty() {
        bail!("genkey's --key argument must be after \"genkey\"");
    }
    if !args.positional.is_empty() {
        bail!("genkey takes no positional arguments");
    }
    if args.list {
        let entries = match fs::read_dir(key_dir()?) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.into()),
        };
        let mut names = entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()?
                    .strip_suffix(".private.json")
                    .map(str::to_owned)
            })
            .collect::<Vec<_>>();
        names.sort();
        for name in names {
            println!("{name}");
        }
        return Ok(());
    }
    if args.delete {
        if args.genkey_key.is_empty() {
            bail!(
                "genkey --delete requires saying which key to delete with --key=<name> (see genkey --list)"
            );
        }
        if key_is_path(&args.genkey_key) {
            bail!("can't delete key {:?}; it's a path", args.genkey_key);
        }
        fs::remove_file(key_path(&args.genkey_key)?)?;
        return Ok(());
    }
    if args.genkey_key.is_empty() && args.region != "list" {
        bail!(
            "genkey requires a --key=<name>; {} mode automatically loads the key named {:?} when it exists",
            if args.client { "client" } else { "server" },
            if args.client {
                "client-default"
            } else {
                "default"
            }
        );
    }
    if args.client {
        for flag in ["region", "fixed-region", "embed-derp-map"] {
            if args.explicit.contains(flag) {
                bail!("genkey --client does not take --{flag}; client keys have no DERP region");
            }
        }
        if args.genkey_key == "default" {
            bail!(
                "genkey --client with --key=default is probably a mistake; client modes use --key=client-default"
            );
        }
    }
    if args.fixed_region && args.explicit.contains("region") {
        bail!("genkey --fixed-region and --region are mutually exclusive");
    }
    let private = PrivateKey::new();
    let mut public = ConnInfo {
        server_public: private.public(),
        server_disco_public: Some(private.disco_public()),
        region: vec![],
        region_id: 0,
    };
    if !args.client {
        if args.fixed_region {
            public.region_id = -1;
            protocol::expand(&mut public, Some(&args.derp_map_url), true).await?;
            public.region_id = public
                .region
                .first()
                .context("couldn't determine the closest DERP region; specify --region")?
                .region_id;
            if !args.embed_derp_map {
                public.region.clear();
            }
        } else if args.region == "auto" {
            public.region_id = -1;
        } else if let Ok(id) = args.region.parse::<i64>() {
            public.region_id = id;
        } else if args.region.contains('.') {
            public.region.push(Region {
                nodes: args
                    .region
                    .split(',')
                    .map(|host| Node {
                        host_name: host.into(),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            });
        } else {
            let map = protocol::fetch_derp_map(Some(&args.derp_map_url), true).await?;
            let needle = args.region.to_lowercase();
            let found = map
                .regions
                .values()
                .find(|r| r.region_code.eq_ignore_ascii_case(&args.region))
                .or_else(|| {
                    map.regions
                        .values()
                        .find(|r| r.region_name.to_lowercase().contains(&needle))
                });
            if args.region == "list" || found.is_none() {
                let mut regions = map.regions.values().collect::<Vec<_>>();
                regions.sort_by_key(|r| r.region_id);
                for r in regions {
                    eprintln!("  {:3} {} {}", r.region_id, r.region_code, r.region_name);
                }
                if args.region == "list" {
                    return Ok(());
                }
                bail!("no region found matching {:?}", args.region);
            }
            public.region_id = found.unwrap().region_id;
        }
        if args.embed_derp_map {
            protocol::expand(&mut public, Some(&args.derp_map_url), true).await?;
            for region in &mut public.region {
                region.nodes.truncate(2);
                for node in &mut region.nodes {
                    node.ipv6.clear();
                }
            }
            public.region_id = 0;
        }
    }
    let path = key_path(&args.genkey_key)?;
    if !key_is_path(&args.genkey_key) {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path.parent().context("key path has no parent")?)?;
    }
    let saved = SavedKey { private, public };
    secure_write(&path, &serde_json::to_vec_pretty(&saved)?, args.force)?;
    eprintln!("# wrote file to {}", path.display());
    if args.client {
        println!("nodekey:{}", hex::encode(saved.private.public()));
    } else {
        println!("{}", protocol::encode_addr(&saved.public)?);
    }
    Ok(())
}
