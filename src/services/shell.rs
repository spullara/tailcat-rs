// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Stdio;

#[cfg(not(unix))]
use anyhow::Context;
use anyhow::Result;
use portable_pty::{CommandBuilder, PtySize};
use russh::{Channel, ChannelMsg, Pty, server::Msg};
use tokio::io::AsyncWriteExt;

#[derive(Clone)]
pub(super) struct Terminal {
    pub term: String,
    pub size: PtySize,
    pub modes: Vec<(Pty, u32)>,
}

pub(super) fn accepted_env(name: &str) -> bool {
    name == "TERM" || name == "LANG" || name.starts_with("LC_")
}

struct CommandSpec {
    program: String,
    args: Vec<String>,
    home: PathBuf,
    env: HashMap<String, String>,
}

struct KillOnDrop(Option<Box<dyn portable_pty::ChildKiller + Send + Sync>>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(killer) = self.0.as_mut() {
            let _ = killer.kill();
        }
    }
}

fn command_spec(command: &str, forwarded: &HashMap<String, String>) -> Result<CommandSpec> {
    let (user, home, uid) = current_user()?;
    #[cfg(unix)]
    let (program, args, mut env) = {
        let shell = login_shell(&user);
        let args = if command.is_empty() {
            vec!["-l".into()]
        } else {
            vec!["-c".into(), command.into()]
        };
        let path = if uid == 0 {
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        } else {
            "/usr/local/bin:/usr/bin:/bin"
        };
        let env = HashMap::from([
            ("SHELL".into(), shell.clone()),
            ("USER".into(), user),
            ("HOME".into(), home.to_string_lossy().into_owned()),
            ("PATH".into(), path.into()),
        ]);
        (shell, args, env)
    };
    #[cfg(not(unix))]
    let (program, args, mut env) = {
        let _ = (user, uid);
        let shell = powershell();
        let args = if command.is_empty() {
            vec!["-NoLogo".into()]
        } else {
            vec!["-Command".into(), command.into()]
        };
        (shell, args, std::env::vars().collect::<HashMap<_, _>>())
    };
    env.extend(
        forwarded
            .iter()
            .filter(|(k, v)| accepted_env(k) && !v.contains('\0'))
            .map(|(k, v)| (k.clone(), v.clone())),
    );
    Ok(CommandSpec {
        program,
        args,
        home,
        env,
    })
}

#[cfg(unix)]
fn current_user() -> Result<(String, PathBuf, u32)> {
    use std::ffi::CStr;
    // getpwuid_r writes pointers into this owned buffer; convert them before
    // dropping it. The uid is the process identity, never the SSH username.
    let uid = unsafe { libc::geteuid() };
    let mut storage = vec![0u8; 16 * 1024];
    loop {
        let mut pw = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        let code = unsafe {
            libc::getpwuid_r(
                uid,
                pw.as_mut_ptr(),
                storage.as_mut_ptr().cast(),
                storage.len(),
                &mut found,
            )
        };
        if code == libc::ERANGE {
            storage.resize(storage.len() * 2, 0);
            continue;
        }
        if code != 0 || found.is_null() {
            anyhow::bail!("failed to get current user (uid {uid})");
        }
        let pw = unsafe { pw.assume_init() };
        let name = unsafe { CStr::from_ptr(pw.pw_name) }
            .to_string_lossy()
            .into_owned();
        let home = unsafe { CStr::from_ptr(pw.pw_dir) }
            .to_string_lossy()
            .into_owned();
        return Ok((name, PathBuf::from(home), uid));
    }
}

#[cfg(not(unix))]
fn current_user() -> Result<(String, PathBuf, u32)> {
    Ok((
        std::env::var("USERNAME").unwrap_or_default(),
        dirs::home_dir().context("current user's home directory unavailable")?,
        1,
    ))
}

#[cfg(unix)]
fn login_shell(user: &str) -> String {
    #[cfg(target_os = "macos")]
    if let Ok(out) = std::process::Command::new("dscl")
        .args([".", "-read", &format!("/Users/{user}"), "UserShell"])
        .output()
        && out.status.success()
        && let Some(shell) = String::from_utf8_lossy(&out.stdout).strip_prefix("UserShell: ")
        && !shell.trim().is_empty()
    {
        return shell.trim().to_owned();
    }
    let _ = user;
    std::env::var("SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/bin/sh".into())
}

#[cfg(not(unix))]
fn powershell() -> String {
    // `reg query` avoids an extra registry dependency while honoring the same
    // OpenSSH default-shell policy as the original Windows server.
    if let Ok(out) = std::process::Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\OpenSSH",
            "/v",
            "DefaultShell",
            "/reg:64",
        ])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        if let Some((_, value)) = text.split_once("REG_SZ") {
            let value = value.trim();
            let base = std::path::Path::new(value)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_ascii_lowercase();
            if matches!(base.as_str(), "pwsh.exe" | "powershell.exe")
                && std::path::Path::new(value).is_file()
            {
                return value.into();
            }
        }
    }
    let candidates = [
        "pwsh.exe".to_string(),
        format!(
            r"{}\PowerShell\7\pwsh.exe",
            std::env::var("ProgramFiles").unwrap_or_default()
        ),
        "powershell.exe".into(),
    ];
    for candidate in candidates {
        if std::path::Path::new(&candidate).is_file() {
            return candidate;
        }
        if std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .any(|dir| dir.join(&candidate).is_file())
        {
            return candidate;
        }
    }
    format!(
        r"{}\System32\WindowsPowerShell\v1.0\powershell.exe",
        std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())
    )
}

pub(super) async fn run(
    channel: Channel<Msg>,
    command: String,
    env: HashMap<String, String>,
    terminal: Option<Terminal>,
) {
    let result = match command_spec(&command, &env) {
        Ok(spec) => match terminal {
            Some(term) => run_pty(channel, spec, term).await,
            None => run_pipes(channel, spec).await,
        },
        Err(err) => {
            let _ = channel
                .extended_data(1, format!("tailcat: {err}\r\n").as_bytes())
                .await;
            let _ = channel.exit_status(1).await;
            let _ = channel.eof().await;
            let _ = channel.close().await;
            return;
        }
    };
    if let Err(err) = result {
        tracing::debug!("SSH shell: {err:#}");
    }
}

async fn run_pipes(channel: Channel<Msg>, spec: CommandSpec) -> Result<()> {
    let mut command = tokio::process::Command::new(&spec.program);
    command
        .args(spec.args)
        .current_dir(spec.home)
        .env_clear()
        .envs(spec.env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let (mut input, output) = channel.split();
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            output
                .extended_data(1, format!("start: {err}\r\n").as_bytes())
                .await?;
            output.exit_status(1).await?;
            output.eof().await?;
            output.close().await?;
            return Ok(());
        }
    };
    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let mut stdout_writer = output.make_writer();
    let mut stderr_writer = output.make_writer_ext(Some(1));
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
    let input_task = tokio::spawn(async move {
        while let Some(msg) = input.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    if let Some(writer) = &mut stdin
                        && writer.write_all(&data).await.is_err()
                    {
                        stdin = None;
                    }
                }
                ChannelMsg::Eof => {
                    stdin = None;
                }
                ChannelMsg::Close => break,
                _ => (),
            }
        }
        let _ = closed_tx.send(());
    });
    let drain = async {
        tokio::try_join!(
            tokio::io::copy(&mut stdout, &mut stdout_writer),
            tokio::io::copy(&mut stderr, &mut stderr_writer)
        )?;
        Result::<()>::Ok(())
    };
    let result = tokio::select! {
        result = drain => { result?; child.wait().await? },
        _ = closed_rx => { let _ = child.kill().await; child.wait().await? },
    };
    input_task.abort();
    // Output is completely drained before the status and channel close.
    output
        .exit_status(result.code().unwrap_or(1) as u32)
        .await?;
    output.eof().await?;
    output.close().await?;
    Ok(())
}

async fn run_pty(channel: Channel<Msg>, spec: CommandSpec, terminal: Terminal) -> Result<()> {
    let system = portable_pty::native_pty_system();
    let pair = match system.openpty(terminal.size) {
        Ok(pair) => pair,
        Err(err) => {
            #[cfg(windows)]
            {
                let _ = channel
                    .extended_data(
                        1,
                        format!("tailcat: ConPTY unavailable ({err}); running without a PTY\r\n")
                            .as_bytes(),
                    )
                    .await;
                return run_pipes(channel, spec).await;
            }
            #[cfg(not(windows))]
            {
                channel
                    .extended_data(1, format!("pty open: {err}\r\n").as_bytes())
                    .await?;
                channel.exit_status(1).await?;
                channel.close().await?;
                return Ok(());
            }
        }
    };
    #[cfg(unix)]
    if let Some(fd) = pair.master.as_raw_fd() {
        apply_modes(fd, &terminal.modes)?;
    }
    // SSH terminal modes describe POSIX termios settings. Non-Unix PTYs,
    // including ConPTY, have no corresponding termios configuration API.
    #[cfg(not(unix))]
    drop(terminal.modes);
    let mut command = CommandBuilder::new(&spec.program);
    command.args(spec.args);
    command.cwd(spec.home);
    command.env_clear();
    for (key, value) in spec.env {
        command.env(key, value);
    }
    if !terminal.term.is_empty() {
        command.env("TERM", terminal.term);
    }
    #[cfg(windows)]
    clear_ctrl_c_ignore();
    let mut child = match pair.slave.spawn_command(command) {
        Ok(child) => child,
        Err(err) => {
            channel
                .extended_data(1, format!("start: {err}\r\n").as_bytes())
                .await?;
            channel.exit_status(1).await?;
            channel.close().await?;
            return Ok(());
        }
    };
    let mut killer = KillOnDrop(Some(child.clone_killer()));
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader()?;
    let mut writer = pair.master.take_writer()?;
    let mut master = Some(pair.master);
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
    tokio::task::spawn_blocking(move || {
        let mut buffer = vec![0; 32 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.blocking_send(buffer[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
    let mut in_tx = Some(in_tx);
    tokio::task::spawn_blocking(move || {
        while let Some(bytes) = in_rx.blocking_recv() {
            if writer.write_all(&bytes).is_err() {
                break;
            }
        }
    });
    let mut waiting = tokio::task::spawn_blocking(move || child.wait());
    let (mut input, output) = channel.split();
    let mut exited = None;
    let mut output_done = false;
    let mut input_done = false;
    while exited.is_none() || !output_done {
        tokio::select! {
            status = &mut waiting, if exited.is_none() => {
                exited = Some(status??.exit_code());
                killer.0.take();
                in_tx.take();
                // On Windows this closes ConPTY and releases the output pipe;
                // output is consumed concurrently so ClosePseudoConsole cannot deadlock.
                if let Some(master) = master.take() { tokio::task::spawn_blocking(move || drop(master)); }
            }
            data = out_rx.recv(), if !output_done => {
                if let Some(data) = data { output.data_bytes(data).await?; } else { output_done = true; }
            }
            message = input.wait(), if !input_done => match message {
                Some(ChannelMsg::Data { data }) => { if let Some(tx) = &in_tx { let _ = tx.send(data.to_vec()).await; } }
                Some(ChannelMsg::Eof) => { in_tx.take(); }
                Some(ChannelMsg::WindowChange { col_width, row_height, pix_width, pix_height }) => {
                    if let Some(master) = &master { let _ = master.resize(size(col_width, row_height, pix_width, pix_height)); }
                }
                None | Some(ChannelMsg::Close) => { input_done = true; in_tx.take(); if let Some(k) = killer.0.as_mut() { let _ = k.kill(); } }
                _ => (),
            }
        }
    }
    output.exit_status(exited.unwrap_or(1)).await?;
    output.eof().await?;
    output.close().await?;
    Ok(())
}

pub(super) fn size(columns: u32, rows: u32, width: u32, height: u32) -> PtySize {
    PtySize {
        cols: if columns == 0 {
            80
        } else {
            columns.min(u16::MAX as u32) as u16
        },
        rows: if rows == 0 {
            24
        } else {
            rows.min(u16::MAX as u32) as u16
        },
        pixel_width: width.min(u16::MAX as u32) as u16,
        pixel_height: height.min(u16::MAX as u32) as u16,
    }
}

#[cfg(windows)]
fn clear_ctrl_c_ignore() {
    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(handler: *const std::ffi::c_void, add: i32) -> i32;
    }
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| unsafe {
        SetConsoleCtrlHandler(std::ptr::null(), 0);
    });
}

#[cfg(unix)]
fn apply_modes(fd: libc::c_int, modes: &[(Pty, u32)]) -> Result<()> {
    let mut term = std::mem::MaybeUninit::<libc::termios>::uninit();
    if unsafe { libc::tcgetattr(fd, term.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut term = unsafe { term.assume_init() };
    for &(opcode, value) in modes {
        let cc = match opcode {
            Pty::VINTR => Some(libc::VINTR),
            Pty::VQUIT => Some(libc::VQUIT),
            Pty::VERASE => Some(libc::VERASE),
            Pty::VKILL => Some(libc::VKILL),
            Pty::VEOF => Some(libc::VEOF),
            Pty::VEOL => Some(libc::VEOL),
            Pty::VEOL2 => Some(libc::VEOL2),
            Pty::VSTART => Some(libc::VSTART),
            Pty::VSTOP => Some(libc::VSTOP),
            Pty::VSUSP => Some(libc::VSUSP),
            Pty::VREPRINT => Some(libc::VREPRINT),
            Pty::VWERASE => Some(libc::VWERASE),
            Pty::VLNEXT => Some(libc::VLNEXT),
            Pty::VDISCARD => Some(libc::VDISCARD),
            #[cfg(target_os = "linux")]
            Pty::VSWTCH => Some(libc::VSWTC),
            #[cfg(target_os = "macos")]
            Pty::VDSUSP => Some(libc::VDSUSP),
            #[cfg(target_os = "macos")]
            Pty::VSTATUS => Some(libc::VSTATUS),
            _ => None,
        };
        if let Some(cc) = cc {
            term.c_cc[cc] = value as libc::cc_t;
            continue;
        }
        let flag = match opcode {
            Pty::IGNPAR => Some((&mut term.c_iflag, libc::IGNPAR)),
            Pty::PARMRK => Some((&mut term.c_iflag, libc::PARMRK)),
            Pty::INPCK => Some((&mut term.c_iflag, libc::INPCK)),
            Pty::ISTRIP => Some((&mut term.c_iflag, libc::ISTRIP)),
            Pty::INLCR => Some((&mut term.c_iflag, libc::INLCR)),
            Pty::IGNCR => Some((&mut term.c_iflag, libc::IGNCR)),
            Pty::ICRNL => Some((&mut term.c_iflag, libc::ICRNL)),
            #[cfg(target_os = "linux")]
            Pty::IUCLC => Some((&mut term.c_iflag, libc::IUCLC)),
            Pty::IXON => Some((&mut term.c_iflag, libc::IXON)),
            Pty::IXANY => Some((&mut term.c_iflag, libc::IXANY)),
            Pty::IXOFF => Some((&mut term.c_iflag, libc::IXOFF)),
            Pty::IMAXBEL => Some((&mut term.c_iflag, libc::IMAXBEL)),
            Pty::IUTF8 => Some((&mut term.c_iflag, libc::IUTF8)),
            Pty::ISIG => Some((&mut term.c_lflag, libc::ISIG)),
            Pty::ICANON => Some((&mut term.c_lflag, libc::ICANON)),
            #[cfg(target_os = "linux")]
            Pty::XCASE => Some((&mut term.c_lflag, libc::XCASE)),
            Pty::ECHO => Some((&mut term.c_lflag, libc::ECHO)),
            Pty::ECHOE => Some((&mut term.c_lflag, libc::ECHOE)),
            Pty::ECHOK => Some((&mut term.c_lflag, libc::ECHOK)),
            Pty::ECHONL => Some((&mut term.c_lflag, libc::ECHONL)),
            Pty::NOFLSH => Some((&mut term.c_lflag, libc::NOFLSH)),
            Pty::TOSTOP => Some((&mut term.c_lflag, libc::TOSTOP)),
            Pty::IEXTEN => Some((&mut term.c_lflag, libc::IEXTEN)),
            Pty::ECHOCTL => Some((&mut term.c_lflag, libc::ECHOCTL)),
            Pty::ECHOKE => Some((&mut term.c_lflag, libc::ECHOKE)),
            Pty::PENDIN => Some((&mut term.c_lflag, libc::PENDIN)),
            Pty::OPOST => Some((&mut term.c_oflag, libc::OPOST)),
            #[cfg(target_os = "linux")]
            Pty::OLCUC => Some((&mut term.c_oflag, libc::OLCUC)),
            Pty::ONLCR => Some((&mut term.c_oflag, libc::ONLCR)),
            Pty::OCRNL => Some((&mut term.c_oflag, libc::OCRNL)),
            Pty::ONOCR => Some((&mut term.c_oflag, libc::ONOCR)),
            Pty::ONLRET => Some((&mut term.c_oflag, libc::ONLRET)),
            Pty::PARENB => Some((&mut term.c_cflag, libc::PARENB)),
            Pty::PARODD => Some((&mut term.c_cflag, libc::PARODD)),
            _ => None,
        };
        if let Some((flags, mask)) = flag {
            if value == 0 {
                *flags &= !mask;
            } else {
                *flags |= mask;
            }
        }
        match opcode {
            Pty::CS7 if value != 0 => {
                term.c_cflag = (term.c_cflag & !libc::CSIZE) | libc::CS7;
            }
            Pty::CS8 if value != 0 => {
                term.c_cflag = (term.c_cflag & !libc::CSIZE) | libc::CS8;
            }
            Pty::TTY_OP_ISPEED | Pty::TTY_OP_OSPEED => {
                let speed = match value {
                    0 => Some(libc::B0),
                    50 => Some(libc::B50),
                    75 => Some(libc::B75),
                    110 => Some(libc::B110),
                    300 => Some(libc::B300),
                    600 => Some(libc::B600),
                    1200 => Some(libc::B1200),
                    2400 => Some(libc::B2400),
                    4800 => Some(libc::B4800),
                    9600 => Some(libc::B9600),
                    19200 => Some(libc::B19200),
                    38400 => Some(libc::B38400),
                    57600 => Some(libc::B57600),
                    115200 => Some(libc::B115200),
                    _ => None,
                };
                if let Some(speed) = speed {
                    unsafe {
                        if opcode == Pty::TTY_OP_ISPEED {
                            libc::cfsetispeed(&mut term, speed);
                        } else {
                            libc::cfsetospeed(&mut term, speed);
                        }
                    }
                }
            }
            _ => (),
        }
    }
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
