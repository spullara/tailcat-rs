use crate::runtime::TcpHandler;
use anyhow::{Result, bail};
use std::{path::Path, process::Stdio, sync::Arc};
use tokio::io::AsyncWriteExt;

/// Resolve the executable before advertising a service, without invoking a shell.
pub fn resolve_command(args: &[String]) -> Result<Vec<String>> {
    if args.is_empty() {
        return Ok(vec![]);
    }
    let name = &args[0];
    let executable = |p: &Path| {
        if !p.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            p.metadata()
                .is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
        }
        #[cfg(not(unix))]
        {
            true
        }
    };
    let found = if name.contains(['/', '\\']) {
        executable(Path::new(name)).then(|| Path::new(name).to_path_buf())
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .flat_map(|p| {
                let names = vec![p.join(name)];
                #[cfg(windows)]
                let names = {
                    let mut names = names;
                    for ext in std::env::var("PATHEXT")
                        .unwrap_or(".EXE;.CMD;.BAT".into())
                        .split(';')
                    {
                        names.push(p.join(format!("{name}{ext}")));
                    }
                    names
                };
                names
            })
            .find(|p| executable(p))
    };
    let Some(path) = found else {
        bail!("executable {name:?} not found");
    };
    let mut result = args.to_vec();
    result[0] = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    }
    .to_string_lossy()
    .into_owned();
    Ok(result)
}

pub fn exec_handler(args: Vec<String>) -> TcpHandler {
    Arc::new(move |stream| {
        let args = args.clone();
        Box::pin(async move {
            let result: Result<()> = async {
                let mut child = tokio::process::Command::new(&args[0])
                    .args(&args[1..])
                    .envs(crate::runtime::connection_env())
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .kill_on_drop(true)
                    .spawn()?;
                let mut stdin = child.stdin.take().unwrap();
                let mut stdout = child.stdout.take().unwrap();
                let (mut read, mut write) = tokio::io::split(stream);
                let input = async {
                    tokio::io::copy(&mut read, &mut stdin).await?;
                    stdin.shutdown().await?;
                    drop(stdin);
                    Ok::<_, std::io::Error>(())
                };
                let output = async {
                    tokio::io::copy(&mut stdout, &mut write).await?;
                    write.shutdown().await
                };
                tokio::try_join!(input, output)?;
                child.wait().await?;
                Ok(())
            }
            .await;
            if let Err(err) = result {
                tracing::debug!("exec: {err:#}");
            }
        })
    })
}
