// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

use super::*;
use russh::ChannelMsg;
use russh_sftp::{
    client::SftpSession,
    protocol::{FileAttributes, OpenFlags},
};
use std::fs;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fixture() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("existing.txt"), b"existing content").unwrap();
    fs::create_dir(dir.path().join("sub")).unwrap();
    fs::write(dir.path().join("sub/inner.txt"), b"inner").unwrap();
    dir
}

async fn sftp(dir: &Path, mode: FileMode) -> SftpSession {
    let share = FileShare::new(dir, mode).unwrap();
    let files = files::Files::new(Some(&share));
    let (client, server) = tokio::io::duplex(1024 * 1024);
    tokio::spawn(async move {
        let (result, _) = run_sftp(server, files).await;
        result.unwrap();
    });
    SftpSession::new(client).await.unwrap()
}

async fn upload(c: &SftpSession, path: &str, content: &[u8]) -> Result<()> {
    let mut f = c
        .open_with_flags(
            path,
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
        )
        .await?;
    f.write_all(content).await?;
    f.shutdown().await?;
    Ok(())
}

async fn download(c: &SftpSession, path: &str) -> Result<Vec<u8>> {
    let mut f = c.open(path).await?;
    let mut content = Vec::new();
    f.read_to_end(&mut content).await?;
    Ok(content)
}

#[tokio::test]
async fn sftp_read_only_enforces_every_write_entry_point() {
    let dir = fixture();
    let c = sftp(dir.path(), FileMode::ReadOnly).await;
    assert_eq!(
        download(&c, "/existing.txt").await.unwrap(),
        b"existing content"
    );
    assert_eq!(download(&c, "sub/inner.txt").await.unwrap(), b"inner");
    assert_eq!(c.read_dir("/").await.unwrap().count(), 2);
    assert!(upload(&c, "new.txt", b"x").await.is_err());
    assert!(c.remove_file("existing.txt").await.is_err());
    assert!(c.create_dir("newdir").await.is_err());
    assert!(c.rename("existing.txt", "renamed").await.is_err());
    let attrs = FileAttributes {
        permissions: Some(0o600),
        ..Default::default()
    };
    assert!(c.set_metadata("existing.txt", attrs.clone()).await.is_err());
    let f = c.open("existing.txt").await.unwrap();
    assert!(f.set_metadata(attrs).await.is_err());
    assert_eq!(
        fs::read(dir.path().join("existing.txt")).unwrap(),
        b"existing content"
    );
    c.close().await.unwrap();
}

#[tokio::test]
async fn sftp_read_write_offsets_metadata_and_operations() {
    let dir = fixture();
    let c = sftp(dir.path(), FileMode::ReadWrite).await;
    upload(&c, "new.txt", b"hello").await.unwrap();
    assert_eq!(download(&c, "new.txt").await.unwrap(), b"hello");
    c.create_dir("newdir").await.unwrap();
    c.rename("new.txt", "newdir/moved.txt").await.unwrap();
    c.set_metadata(
        "newdir/moved.txt",
        FileAttributes {
            permissions: Some(0o600),
            size: Some(3),
            atime: Some(1000),
            mtime: Some(2000),
            uid: Some(1234),
            gid: Some(1234),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(download(&c, "newdir/moved.txt").await.unwrap(), b"hel");
    c.set_metadata(
        "newdir/moved.txt",
        FileAttributes {
            atime: Some(1000),
            mtime: Some(2000),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let m = c.metadata("newdir/moved.txt").await.unwrap();
    assert_eq!(m.mtime, Some(2000));
    #[cfg(unix)]
    assert_eq!(m.permissions.unwrap() & 0o777, 0o600);
    c.remove_file("newdir/moved.txt").await.unwrap();
    c.remove_dir("newdir").await.unwrap();
    c.close().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn shell_sftp_has_full_filesystem_access_and_native_metadata() {
    use std::os::unix::fs::{MetadataExt, symlink};
    let dir = fixture();
    let external = fixture();
    symlink(external.path(), dir.path().join("external")).unwrap();
    let (client, server) = tokio::io::duplex(1024 * 1024);
    tokio::spawn(async move {
        let (result, _) = run_sftp(server, files::Files::new(None)).await;
        result.unwrap();
    });
    let c = SftpSession::new(client).await.unwrap();
    let path = dir
        .path()
        .join("existing.txt")
        .to_string_lossy()
        .into_owned();
    let external_path = dir
        .path()
        .join("external/existing.txt")
        .to_string_lossy()
        .into_owned();
    assert_eq!(
        download(&c, &external_path).await.unwrap(),
        b"existing content"
    );
    assert_eq!(
        c.canonicalize(".").await.unwrap(),
        dirs::home_dir().unwrap().to_string_lossy()
    );
    assert!(c.fs_info(&path).await.unwrap().is_some());
    let metadata = fs::metadata(&path).unwrap();
    c.set_metadata(
        &path,
        FileAttributes {
            size: Some(3),
            mtime: Some(2000),
            atime: Some(1000),
            uid: Some(metadata.uid()),
            gid: Some(metadata.gid()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(c.metadata(&path).await.unwrap().mtime, Some(2000));
    assert_eq!(download(&c, &path).await.unwrap(), b"exi");
    c.close().await.unwrap();
}

#[tokio::test]
async fn sftp_flat_dropbox_preserves_privacy_and_session_ownership() {
    let dir = fixture();
    let c = sftp(dir.path(), FileMode::WriteOnly).await;
    for bytes in [b"first".as_slice(), b"second".as_slice()] {
        upload(&c, "existing.txt", bytes).await.unwrap();
    }
    assert_eq!(
        fs::read(dir.path().join("existing.txt")).unwrap(),
        b"existing content"
    );
    let names: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("existing.") && n != "existing.txt")
        .collect();
    assert_eq!(names.len(), 2);
    for name in &names {
        let fields: Vec<_> = name.split('.').collect();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[1].len(), 14);
        assert_eq!(fields[2].len(), 16);
        assert_eq!(fields[3], "txt");
    }
    let attrs = FileAttributes {
        permissions: Some(0o600),
        ..Default::default()
    };
    c.set_metadata("existing.txt", attrs).await.unwrap();
    assert_eq!(c.metadata("existing.txt").await.unwrap().size, Some(6));
    assert!(c.open("existing.txt").await.is_err());
    for name in ["existing.txt", "missing.txt"] {
        assert!(c.open_with_flags(name, OpenFlags::WRITE).await.is_err());
    }
    assert!(c.create_dir("newdir").await.is_err());
    assert!(upload(&c, "sub/nested", b"no").await.is_err());
    assert!(c.metadata("sub").await.is_err());
    assert!(c.metadata("/").await.unwrap().is_dir());
    assert!(c.read_dir("/").await.is_err());
    assert!(c.remove_file("existing.txt").await.is_err());
    assert!(c.rename("existing.txt", "new").await.is_err());
    let other = sftp(dir.path(), FileMode::WriteOnly).await;
    assert!(other.metadata("existing.txt").await.is_err());
    c.close().await.unwrap();
    other.close().await.unwrap();
}

#[tokio::test]
async fn sftp_recursive_dropbox_collisions_and_directories() {
    let dir = fixture();
    let c = sftp(dir.path(), FileMode::WriteOnlyPlus).await;
    upload(&c, "drop.txt", b"first").await.unwrap();
    upload(&c, "drop.txt", b"second").await.unwrap();
    assert_eq!(fs::read(dir.path().join("drop.txt")).unwrap(), b"first");
    assert_eq!(c.metadata("drop.txt").await.unwrap().size, Some(6));
    assert!(c.metadata("sub").await.unwrap().is_dir());
    assert!(c.metadata("existing.txt").await.is_err());
    c.create_dir("newdir").await.unwrap();
    upload(&c, "newdir/nested.txt", b"nested").await.unwrap();
    assert_eq!(
        fs::read(dir.path().join("newdir/nested.txt")).unwrap(),
        b"nested"
    );
    assert!(c.read_dir("/").await.is_err());
    assert!(c.open("drop.txt").await.is_err());
    c.close().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn sftp_confines_reads_writes_and_metadata_through_symlinks() {
    use std::os::unix::fs::symlink;
    let dir = fixture();
    let outside = fixture();
    symlink(outside.path(), dir.path().join("escape")).unwrap();
    symlink("existing.txt", dir.path().join("internal")).unwrap();
    let c = sftp(dir.path(), FileMode::ReadWrite).await;
    assert_eq!(download(&c, "internal").await.unwrap(), b"existing content");
    assert!(download(&c, "escape/existing.txt").await.is_err());
    assert!(upload(&c, "escape/created.txt", b"no").await.is_err());
    assert!(
        c.set_metadata(
            "escape/existing.txt",
            FileAttributes {
                size: Some(0),
                ..Default::default()
            }
        )
        .await
        .is_err()
    );
    assert!(c.create_dir("escape/newdir").await.is_err());
    assert!(
        c.rename("existing.txt", "escape/renamed.txt")
            .await
            .is_err()
    );
    assert_eq!(
        fs::read(outside.path().join("existing.txt")).unwrap(),
        b"existing content"
    );
    // ../ is interpreted within the virtual SFTP root, never the host parent.
    assert_eq!(
        download(&c, "../../existing.txt").await.unwrap(),
        b"existing content"
    );
    c.close().await.unwrap();
}

async fn ssh_client(config: Arc<SshConfig>) -> russh::client::Handle<TunnelClient> {
    let (client, server) = tokio::io::duplex(1024 * 1024);
    tokio::spawn(async move {
        if let Err(e) = serve_ssh(server, config).await {
            tracing::debug!("test SSH server closed: {e}");
        }
    });
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client,
        TunnelClient,
    )
    .await
    .unwrap();
    assert!(
        client
            .authenticate_none("ignored-user")
            .await
            .unwrap()
            .success()
    );
    client
}

async fn collect(
    mut channel: russh::Channel<russh::client::Msg>,
) -> (Vec<u8>, Vec<u8>, Option<u32>) {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (mut out, mut err, mut status) = (Vec::new(), Vec::new(), None);
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => out.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => err.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::Close => break,
                _ => (),
            }
        }
        (out, err, status)
    })
    .await
    .expect("SSH session did not finish")
}

fn config(dir: &Path, shell: bool, share: Option<FileShare>) -> Arc<SshConfig> {
    Arc::new(SshConfig::with_key_path(shell, share, &dir.join("ssh/key")).unwrap())
}

#[tokio::test]
async fn ssh_exec_preserves_streams_and_exit_status() {
    let dir = tempfile::tempdir().unwrap();
    let client = ssh_client(config(dir.path(), true, None)).await;
    let channel = client.channel_open_session().await.unwrap();
    #[cfg(unix)]
    let command = "printf out-marker; printf err-marker >&2; exit 42";
    #[cfg(not(unix))]
    let command = "[Console]::Write('out-marker'); [Console]::Error.Write('err-marker'); exit 42";
    channel.exec(true, command).await.unwrap();
    let (out, err, code) = collect(channel).await;
    assert_eq!(out, b"out-marker");
    assert_eq!(err, b"err-marker");
    assert_eq!(code, Some(42));
}

#[tokio::test]
async fn ssh_file_only_refuses_shell_and_serves_native_listing() {
    let dir = fixture();
    let cfg = config(
        dir.path(),
        false,
        Some(FileShare::new(dir.path(), FileMode::ReadOnly).unwrap()),
    );
    let client = ssh_client(cfg.clone()).await;
    let channel = client.channel_open_session().await.unwrap();
    channel.exec(true, "echo forbidden").await.unwrap();
    let (out, err, code) = collect(channel).await;
    assert!(out.is_empty());
    assert!(String::from_utf8_lossy(&err).contains("disabled"));
    assert_eq!(code, Some(1));
    let (local, remote) = tokio::io::duplex(1024 * 1024);
    tokio::spawn(async move {
        let _ = serve_ssh(remote, cfg).await;
    });
    let entries = list_files(local, "sub").await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "inner.txt");
    assert_eq!(entries[0].attributes.size, Some(5));
}

#[cfg(unix)]
#[tokio::test]
async fn ssh_pty_is_real_and_preserves_term_and_dimensions() {
    let dir = tempfile::tempdir().unwrap();
    let client = ssh_client(config(dir.path(), true, None)).await;
    let channel = client.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm-256color", 91, 37, 0, 0, &[(Pty::ECHO, 0)])
        .await
        .unwrap();
    channel
        .exec(true, "tty; printf '%s\\n' \"$TERM\"; stty size")
        .await
        .unwrap();
    let (out, _, code) = collect(channel).await;
    let out = String::from_utf8_lossy(&out);
    assert!(out.contains("/dev/"), "{out}");
    assert!(out.contains("xterm-256color"), "{out}");
    assert!(out.contains("37 91"), "{out}");
    assert_eq!(code, Some(0));
}

#[cfg(unix)]
#[tokio::test]
async fn ssh_environment_filter_and_stdin_eof() {
    let dir = tempfile::tempdir().unwrap();
    let client = ssh_client(config(dir.path(), true, None)).await;
    let channel = client.channel_open_session().await.unwrap();
    channel.set_env(true, "LC_TEST", "forwarded").await.unwrap();
    channel
        .set_env(false, "TAILCAT_SECRET_TEST", "forbidden")
        .await
        .unwrap();
    channel
        .exec(
            true,
            "cat; printf ':LC=%s:BAD=%s' \"$LC_TEST\" \"$TAILCAT_SECRET_TEST\"",
        )
        .await
        .unwrap();
    channel.data(&b"input"[..]).await.unwrap();
    channel.eof().await.unwrap();
    let (out, _, code) = collect(channel).await;
    assert_eq!(out, b"input:LC=forwarded:BAD=");
    assert_eq!(code, Some(0));
}

#[cfg(unix)]
#[tokio::test]
async fn ssh_interactive_ctrl_c_and_resize() {
    let dir = tempfile::tempdir().unwrap();
    let client = ssh_client(config(dir.path(), true, None)).await;
    let mut channel = client.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[(Pty::ECHO, 0)])
        .await
        .unwrap();
    channel.request_shell(true).await.unwrap();
    channel.data(&b"echo READY; sleep 60\n"[..]).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut output = Vec::new();
        while !String::from_utf8_lossy(&output).contains("READY") {
            if let Some(ChannelMsg::Data { data }) = channel.wait().await {
                output.extend_from_slice(&data);
            }
        }
    })
    .await
    .unwrap();
    // READY precedes the foreground job handoff. Give the shell time to put
    // sleep in the foreground before delivering a terminal interrupt.
    tokio::time::sleep(Duration::from_millis(200)).await;
    channel.window_change(93, 38, 0, 0).await.unwrap();
    channel.data(&b"\x03"[..]).await.unwrap();
    // The terminal flushes queued input when processing VINTR; subsequent
    // interactive input must arrive after that flush, as it would from a user.
    tokio::time::sleep(Duration::from_millis(200)).await;
    channel
        .data(&b"echo after-interrupt; stty size; exit\n"[..])
        .await
        .unwrap();
    let (out, _, _) = collect(channel).await;
    let out = String::from_utf8_lossy(&out);
    assert!(out.contains("after-interrupt"), "{out}");
    assert!(out.contains("38 93"), "{out}");
}

#[cfg(unix)]
#[tokio::test]
async fn system_openssh_exec_and_sftp_exit_status() {
    if std::process::Command::new("ssh")
        .arg("-V")
        .output()
        .is_err()
        || std::process::Command::new("sftp")
            .arg("-h")
            .output()
            .is_err()
    {
        return;
    }
    let dir = fixture();
    let cfg = config(
        dir.path(),
        true,
        Some(FileShare::new(dir.path(), FileMode::ReadWrite).unwrap()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let cfg = cfg.clone();
            tokio::spawn(async move {
                let _ = serve_ssh(stream, cfg).await;
            });
        }
    });
    let common = [
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "BatchMode=yes",
    ];
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new("ssh")
            .args(common)
            .args([
                "-p",
                &addr.port().to_string(),
                "127.0.0.1",
                "printf native-ssh",
            ])
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"native-ssh");
    let fetched = tempfile::tempdir().unwrap();
    let destination = fetched.path().join("fetched.txt");
    let batch = fetched.path().join("batch");
    fs::write(
        &batch,
        format!(
            "get /existing.txt {}\nput {} /uploaded.txt\nln -s /existing.txt /linked.txt\n",
            destination.display(),
            destination.display()
        ),
    )
    .unwrap();
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new("sftp")
            .args(common)
            .args(["-P", &addr.port().to_string(), "-b"])
            .arg(&batch)
            .arg("127.0.0.1")
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(destination).unwrap(), b"existing content");
    assert_eq!(
        fs::read(dir.path().join("uploaded.txt")).unwrap(),
        b"existing content"
    );
    assert_eq!(
        fs::read(dir.path().join("linked.txt")).unwrap(),
        b"existing content"
    );
    server.abort();
}

#[test]
fn host_key_persists_with_restrictive_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ssh/key");
    let first = host_key(&path).unwrap();
    let second = host_key(&path).unwrap();
    assert_eq!(first.public_key(), second.public_key());
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .starts_with("-----BEGIN PRIVATE KEY-----")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
