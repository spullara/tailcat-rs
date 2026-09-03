// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//! Native SSH, SFTP, and file sharing over an authenticated tailcat stream.
mod files;
mod shell;

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use russh::{
    Channel, ChannelId, Pty,
    server::{self, Msg, Session},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use files::{FileMode, FileShare};

/// Initialize once and share across accepted TCP connections. The host key is
/// stable across sessions and compatible with the original Go PKCS#8 file.
pub struct SshConfig {
    pub shell: bool,
    pub files: Option<FileShare>,
    config: Arc<server::Config>,
}

impl SshConfig {
    pub fn new(shell: bool, files: Option<FileShare>) -> Result<Self> {
        let dir = dirs::config_dir()
            .context("user config directory is unavailable")?
            .join("tailcat/ssh");
        Self::with_key_path(shell, files, &dir.join("ssh_host_ed25519_key"))
    }

    pub fn with_key_path(shell: bool, files: Option<FileShare>, key_path: &Path) -> Result<Self> {
        let key = host_key(key_path)?;
        let config = server::Config {
            keys: vec![key],
            ..Default::default()
        };
        Ok(Self {
            shell,
            files,
            config: Arc::new(config),
        })
    }
}

fn host_key(path: &Path) -> Result<russh::keys::PrivateKey> {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    match std::fs::read_to_string(path) {
        Ok(key) => {
            return russh::keys::decode_secret_key(&key, None).context("parsing SSH host key");
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => (),
        Err(err) => return Err(err).context("reading SSH host key"),
    }
    let parent = path
        .parent()
        .context("SSH host key has no parent directory")?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(parent)?;
    let key = russh::keys::PrivateKey::random(&mut rand10::rng(), russh::keys::Algorithm::Ed25519)?;
    let mut pem = Vec::new();
    russh::keys::encode_pkcs8_pem(&key, &mut pem)?;
    // Publish only complete contents, atomically, without replacing a key that
    // another tailcat process generated while we were starting.
    let temporary = parent.join(format!(".ssh-host-key-{:016x}", rand10::random::<u64>()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let result = (|| -> Result<()> {
        use std::io::Write;
        file.write_all(&pem)?;
        file.sync_all()?;
        match std::fs::hard_link(&temporary, path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e.into()),
        }
    })();
    drop(file);
    let _ = std::fs::remove_file(temporary);
    result?;
    russh::keys::load_secret_key(path, None).context("loading SSH host key")
}

/// Serve one SSH connection. Authentication and peer authorization must already
/// have been performed by the encrypted tunnel; no SSH credentials are required.
pub async fn serve_ssh<S>(stream: S, config: Arc<SshConfig>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    server::run_stream(
        config.config.clone(),
        stream,
        SshSession {
            config,
            pending: HashMap::new(),
        },
    )
    .await?
    .await
}

struct Pending {
    channel: Channel<Msg>,
    env: HashMap<String, String>,
    terminal: Option<shell::Terminal>,
}

struct SshSession {
    config: Arc<SshConfig>,
    pending: HashMap<ChannelId, Pending>,
}

impl SshSession {
    fn start_shell(&mut self, id: ChannelId, command: String, session: &mut Session) -> Result<()> {
        let Some(pending) = self.pending.remove(&id) else {
            session.channel_failure(id)?;
            return Ok(());
        };
        session.channel_success(id)?;
        if self.config.shell {
            tokio::spawn(shell::run(
                pending.channel,
                command,
                pending.env,
                pending.terminal,
            ));
        } else {
            tokio::spawn(async move {
                let c = pending.channel;
                let _ = c.extended_data(1, &b"this tailcat server only offers file transfer (SFTP); shell and exec sessions are disabled\r\n"[..]).await;
                let _ = c.exit_status(1).await;
                let _ = c.eof().await;
                let _ = c.close().await;
            });
        }
        Ok(())
    }
}

impl server::Handler for SshSession {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<server::Auth> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<()> {
        self.pending.insert(
            channel.id(),
            Pending {
                channel,
                env: HashMap::new(),
                terminal: None,
            },
        );
        reply.accept().await;
        Ok(())
    }

    async fn channel_close(&mut self, id: ChannelId, _session: &mut Session) -> Result<()> {
        self.pending.remove(&id);
        Ok(())
    }

    async fn env_request(
        &mut self,
        id: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Result<()> {
        if shell::accepted_env(name)
            && !value.contains('\0')
            && let Some(pending) = self.pending.get_mut(&id)
        {
            pending.env.insert(name.to_owned(), value.to_owned());
            session.channel_success(id)?;
            return Ok(());
        }
        session.channel_failure(id)?;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        id: ChannelId,
        term: &str,
        columns: u32,
        rows: u32,
        width: u32,
        height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<()> {
        if let Some(pending) = self.pending.get_mut(&id) {
            pending.terminal = Some(shell::Terminal {
                term: term.to_owned(),
                size: shell::size(columns, rows, width, height),
                modes: modes.to_vec(),
            });
            session.channel_success(id)?;
        } else {
            session.channel_failure(id)?;
        }
        Ok(())
    }

    async fn shell_request(&mut self, id: ChannelId, session: &mut Session) -> Result<()> {
        self.start_shell(id, String::new(), session)
    }

    async fn exec_request(
        &mut self,
        id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<()> {
        match std::str::from_utf8(data) {
            Ok(s) if !s.contains('\0') => self.start_shell(id, s.to_owned(), session),
            _ => {
                session.channel_failure(id)?;
                Ok(())
            }
        }
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<()> {
        if name != "sftp" || (!self.config.shell && self.config.files.is_none()) {
            session.channel_failure(id)?;
            return Ok(());
        }
        let Some(pending) = self.pending.remove(&id) else {
            session.channel_failure(id)?;
            return Ok(());
        };
        session.channel_success(id)?;
        let files = files::Files::new(self.config.files.as_ref());
        let handle = session.handle();
        tokio::spawn(async move {
            let stream = pending.channel.into_stream();
            // Keep the stream alive until after exit-status, so scp observes
            // successful completion before the SSH channel is closed.
            let (result, _stream) = run_sftp(stream, files).await;
            let code = if let Err(err) = result {
                tracing::debug!("SFTP session: {err:#}");
                1
            } else {
                0
            };
            let _ = handle.exit_status_request(id, code).await;
            let _ = handle.eof(id).await;
            let _ = handle.close(id).await;
        });
        Ok(())
    }
}

async fn run_sftp<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    mut files: files::Files,
) -> (Result<()>, S) {
    let result = async {
        loop {
            let n = match stream.read_u32().await {
                Ok(n) => n,
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(err) => return Err(err.into()),
            };
            if n == 0 || n > 256 * 1024 {
                bail!("invalid SFTP packet length {n}");
            }
            let mut data = vec![0; n as usize];
            stream.read_exact(&mut data).await?;
            let packet = russh_sftp::protocol::Packet::try_from(&mut Bytes::from(data))?;
            // Disk operations can block (including on network-mounted shares).
            // Keep them off Tokio's workers while retaining ordered requests
            // and the session's capability/handle ownership.
            let (next_files, response) = tokio::task::spawn_blocking(move || {
                let response = files.process(packet);
                (files, response)
            })
            .await?;
            files = next_files;
            let reply = Bytes::try_from(response)?;
            stream.write_all(&reply).await?;
            stream.flush().await?;
        }
    }
    .await;
    (result, stream)
}

#[derive(Debug, Clone)]
pub struct ListEntry {
    pub name: String,
    pub attributes: russh_sftp::protocol::FileAttributes,
}

struct TunnelClient;
impl russh::client::Handler for TunnelClient {
    type Error = anyhow::Error;
    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool> {
        // Tailcat's authenticated WireGuard key already identifies the server.
        Ok(true)
    }
}

/// List a directory (sorted by name), or return the named file as one entry.
/// This performs SSH and SFTP natively and does not invoke OpenSSH programs.
pub async fn list_files<S>(stream: S, path: &str) -> Result<Vec<ListEntry>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut ssh = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        stream,
        TunnelClient,
    )
    .await
    .context("SSH handshake")?;
    if !ssh.authenticate_none("").await?.success() {
        bail!("SSH server refused authentication-free access");
    }
    let channel = ssh.channel_open_session().await?;
    channel.request_subsystem(true, "sftp").await?;
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .context("opening SFTP session")?;
    let path = if path.is_empty() { "." } else { path };
    let metadata = sftp
        .metadata(path)
        .await
        .with_context(|| format!("stat {path}"))?;
    let mut entries = if metadata.is_dir() {
        sftp.read_dir(path)
            .await?
            .map(|entry| ListEntry {
                name: entry.file_name(),
                attributes: entry.metadata(),
            })
            .collect()
    } else {
        vec![ListEntry {
            name: path.strip_prefix("./").unwrap_or(path).to_owned(),
            attributes: metadata,
        }]
    };
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    sftp.close().await?;
    ssh.disconnect(russh::Disconnect::ByApplication, "", "")
        .await?;
    Ok(entries)
}

#[cfg(test)]
mod tests;
