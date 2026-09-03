// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//! SFTP filesystem policy. Rooted operations never use ambient path lookups.
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use cap_fs_ext::{DirExt, SystemTimeSpec};
use cap_std::fs::{Dir, OpenOptions};
use russh_sftp::protocol::{self as p, FileAttributes, OpenFlags, Packet, StatusCode};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FileMode {
    #[default]
    ReadOnly,
    ReadWrite,
    WriteOnly,
    WriteOnlyPlus,
}

impl FileMode {
    fn write_only(self) -> bool {
        matches!(self, Self::WriteOnly | Self::WriteOnlyPlus)
    }
}

/// An open directory capability and the access permitted through it.
#[derive(Clone, Debug)]
pub struct FileShare {
    pub dir: PathBuf,
    pub mode: FileMode,
    root: Arc<Dir>,
}

impl FileShare {
    pub fn new(dir: impl AsRef<Path>, mode: FileMode) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let root = Dir::open_ambient_dir(&dir, cap_std::ambient_authority())
            .with_context(|| format!("opening file service directory {}", dir.display()))?;
        Ok(Self {
            dir,
            mode,
            root: Arc::new(root),
        })
    }

    pub fn parse(value: &str) -> Result<Self> {
        let (dir, mode) = match value.rsplit_once(':') {
            Some((dir, "ro")) => (dir, FileMode::ReadOnly),
            Some((dir, "rw")) => (dir, FileMode::ReadWrite),
            Some((dir, "wo")) => (dir, FileMode::WriteOnly),
            Some((dir, "wo+")) => (dir, FileMode::WriteOnlyPlus),
            _ => (value, FileMode::ReadOnly),
        };
        if dir.is_empty() {
            bail!("file service directory is empty");
        }
        Self::new(dir, mode)
    }
}

enum OpenHandle {
    File {
        file: fs::File,
        readable: bool,
        writable: bool,
    },
    Directory {
        entries: Vec<p::File>,
        next: usize,
    },
}

pub(super) struct Files {
    root: Option<Arc<Dir>>,
    home: PathBuf,
    mode: FileMode,
    wrote: HashMap<PathBuf, PathBuf>,
    handles: HashMap<String, OpenHandle>,
    next_handle: u64,
    initialized: bool,
}

type FxResult<T> = std::result::Result<T, StatusCode>;

fn status(err: io::Error) -> StatusCode {
    match err.kind() {
        io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        io::ErrorKind::Unsupported => StatusCode::OpUnsupported,
        _ => StatusCode::Failure,
    }
}

/// SFTP paths use slash separators on every platform. Clean at the virtual
/// root before handing a relative path to cap-std (the same rule as Go's SFTP).
fn relative(path: &str) -> FxResult<PathBuf> {
    if path.contains('\0') {
        return Err(StatusCode::BadMessage);
    }
    #[cfg(windows)]
    if path.contains('\\') || path.contains(':') {
        return Err(StatusCode::PermissionDenied);
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => (),
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    Ok(if parts.is_empty() {
        PathBuf::from(".")
    } else {
        parts.iter().collect()
    })
}

fn clean_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => (),
            Component::ParentDir => {
                result.pop();
            }
            _ => result.push(component.as_os_str()),
        }
    }
    result
}

fn sftp_path(path: &Path) -> String {
    let path = path.to_string_lossy().into_owned();
    #[cfg(windows)]
    {
        path.replace('\\', "/")
    }
    #[cfg(not(windows))]
    {
        path
    }
}

fn unique_path(path: &Path) -> PathBuf {
    let base = path.file_name().unwrap_or_default().to_string_lossy();
    // path.Ext in Go includes the dot, including for a leading-dot filename.
    let (stem, ext) = match base.rfind('.') {
        Some(i) => (&base[..i], &base[i..]),
        None => (&*base, ""),
    };
    let name = format!(
        "{}.{}.{:016x}{}",
        stem,
        chrono::Utc::now().format("%Y%m%d%H%M%S"),
        rand10::random::<u64>(),
        ext
    );
    path.with_file_name(name)
}

impl Files {
    pub(super) fn new(share: Option<&FileShare>) -> Self {
        Self {
            root: share.map(|s| s.root.clone()),
            home: dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")),
            mode: share.map_or(FileMode::ReadWrite, |s| s.mode),
            wrote: HashMap::new(),
            handles: HashMap::new(),
            next_handle: 0,
            initialized: false,
        }
    }

    fn path(&self, path: &str) -> FxResult<PathBuf> {
        if self.root.is_some() {
            return relative(path);
        }
        if path.contains('\0') {
            return Err(StatusCode::BadMessage);
        }
        let path = Path::new(path);
        Ok(if path.is_absolute() {
            path.to_owned()
        } else {
            clean_path(&self.home.join(path))
        })
    }

    fn metadata(&self, path: &Path, follow: bool) -> FxResult<FileAttributes> {
        if let Some(root) = &self.root {
            let m = if follow {
                root.metadata(path)
            } else {
                root.symlink_metadata(path)
            }
            .map_err(status)?;
            #[cfg(unix)]
            {
                use cap_std::fs::MetadataExt;
                Ok(FileAttributes {
                    size: Some(m.len()),
                    permissions: Some(m.mode()),
                    uid: Some(m.uid()),
                    gid: Some(m.gid()),
                    atime: Some(m.atime().max(0) as u32),
                    mtime: Some(m.mtime().max(0) as u32),
                    ..Default::default()
                })
            }
            #[cfg(not(unix))]
            {
                let ty = if m.is_dir() {
                    0o040000
                } else if m.is_symlink() {
                    0o120000
                } else {
                    0o100000
                };
                Ok(FileAttributes {
                    size: Some(m.len()),
                    permissions: Some(
                        ty | if m.permissions().readonly() {
                            0o444
                        } else {
                            0o644
                        },
                    ),
                    atime: m
                        .accessed()
                        .ok()
                        .and_then(|t| t.into_std().duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as u32),
                    mtime: m
                        .modified()
                        .ok()
                        .and_then(|t| t.into_std().duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as u32),
                    ..Default::default()
                })
            }
        } else {
            let m = if follow {
                fs::metadata(path)
            } else {
                fs::symlink_metadata(path)
            }
            .map_err(status)?;
            Ok((&m).into())
        }
    }

    fn stat_path(&self, path: &Path, follow: bool) -> FxResult<FileAttributes> {
        if !self.mode.write_only() {
            return self.metadata(path, follow);
        }
        if let Some(actual) = self.wrote.get(path) {
            return self.metadata(actual, follow);
        }
        if self.mode == FileMode::WriteOnly && path != Path::new(".") {
            return Err(StatusCode::NoSuchFile);
        }
        match self.metadata(path, follow) {
            Ok(m) if m.is_dir() => Ok(m),
            _ => Err(StatusCode::NoSuchFile),
        }
    }

    fn open_file(&self, path: &Path, flags: OpenFlags, exclusive: bool) -> io::Result<fs::File> {
        let mut options = OpenOptions::new();
        options
            .read(flags.contains(OpenFlags::READ))
            .write(flags.contains(OpenFlags::WRITE))
            .append(!exclusive && flags.contains(OpenFlags::APPEND))
            .create(!exclusive && flags.contains(OpenFlags::CREATE))
            .truncate(!exclusive && flags.contains(OpenFlags::TRUNCATE))
            .create_new(exclusive || flags.contains(OpenFlags::EXCLUDE));
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(0o644);
        }
        if let Some(root) = &self.root {
            root.open_with(path, &options).map(|f| f.into_std())
        } else {
            let mut options = fs::OpenOptions::new();
            options
                .read(flags.contains(OpenFlags::READ))
                .write(flags.contains(OpenFlags::WRITE))
                .append(flags.contains(OpenFlags::APPEND))
                .create(flags.contains(OpenFlags::CREATE))
                .truncate(flags.contains(OpenFlags::TRUNCATE))
                .create_new(flags.contains(OpenFlags::EXCLUDE));
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o644);
            }
            options.open(path)
        }
    }

    fn open(&mut self, id: u32, filename: &str, flags: OpenFlags) -> FxResult<Packet> {
        let mutating = flags.intersects(
            OpenFlags::WRITE
                | OpenFlags::APPEND
                | OpenFlags::CREATE
                | OpenFlags::TRUNCATE
                | OpenFlags::EXCLUDE,
        );
        if self.mode == FileMode::ReadOnly && mutating {
            return Err(StatusCode::PermissionDenied);
        }
        let requested = self.path(filename)?;
        let mut actual = requested.clone();
        let file = if self.mode.write_only() {
            if flags.contains(OpenFlags::READ)
                || !flags.contains(OpenFlags::WRITE | OpenFlags::CREATE)
            {
                return Err(StatusCode::PermissionDenied);
            }
            if self.mode == FileMode::WriteOnly {
                if requested == Path::new(".") || requested.components().count() != 1 {
                    return Err(StatusCode::PermissionDenied);
                }
                actual = unique_path(&requested);
            }
            let result = self.open_file(&actual, OpenFlags::WRITE | OpenFlags::CREATE, true);
            let file = match result {
                Err(e)
                    if self.mode == FileMode::WriteOnlyPlus
                        && e.kind() == io::ErrorKind::AlreadyExists =>
                {
                    actual = unique_path(&requested);
                    self.open_file(&actual, OpenFlags::WRITE | OpenFlags::CREATE, true)
                        .map_err(status)?
                }
                other => other.map_err(status)?,
            };
            self.wrote.insert(requested, actual);
            file
        } else {
            self.open_file(&actual, flags, false).map_err(status)?
        };
        Ok(self.add_handle(
            id,
            OpenHandle::File {
                file,
                readable: flags.contains(OpenFlags::READ),
                writable: flags.contains(OpenFlags::WRITE),
            },
        ))
    }

    fn add_handle(&mut self, id: u32, handle: OpenHandle) -> Packet {
        self.next_handle += 1;
        let name = self.next_handle.to_string();
        self.handles.insert(name.clone(), handle);
        p::Handle { id, handle: name }.into()
    }

    fn opendir(&mut self, id: u32, path: &str) -> FxResult<Packet> {
        if self.mode.write_only() {
            return Err(StatusCode::PermissionDenied);
        }
        let path = self.path(path)?;
        let mut entries = Vec::new();
        if let Some(root) = &self.root {
            for entry in root.read_dir(&path).map_err(status)? {
                let entry = entry.map_err(status)?;
                let name = entry.file_name();
                entries.push(p::File::new(
                    name.to_string_lossy(),
                    self.metadata(&path.join(&name), false)?,
                ));
            }
        } else {
            for entry in fs::read_dir(path).map_err(status)? {
                let entry = entry.map_err(status)?;
                entries.push(p::File::new(
                    entry.file_name().to_string_lossy(),
                    (&fs::symlink_metadata(entry.path()).map_err(status)?).into(),
                ));
            }
        }
        entries.sort_by(|a, b| a.filename.cmp(&b.filename));
        Ok(self.add_handle(id, OpenHandle::Directory { entries, next: 0 }))
    }

    fn setstat_path(&self, path: &Path, attrs: &FileAttributes) -> FxResult<()> {
        if self.mode == FileMode::ReadOnly {
            return Err(StatusCode::PermissionDenied);
        }
        let path = if self.mode.write_only() {
            self.wrote
                .get(path)
                .ok_or(StatusCode::PermissionDenied)?
                .as_path()
        } else {
            path
        };
        if let Some(root) = &self.root {
            if let Some(mode) = attrs.permissions {
                #[cfg(unix)]
                {
                    use cap_std::fs::PermissionsExt;
                    root.set_permissions(path, cap_std::fs::Permissions::from_mode(mode & 0o777))
                        .map_err(status)?;
                }
                #[cfg(not(unix))]
                {
                    let mut perm = root.metadata(path).map_err(status)?.permissions();
                    perm.set_readonly(mode & 0o200 == 0);
                    root.set_permissions(path, perm).map_err(status)?;
                }
            }
            let time = |n: u32| {
                SystemTimeSpec::Absolute(cap_std::time::SystemTime::from_std(
                    UNIX_EPOCH + Duration::from_secs(n as u64),
                ))
            };
            if attrs.atime.is_some() || attrs.mtime.is_some() {
                root.set_times(path, attrs.atime.map(time), attrs.mtime.map(time))
                    .map_err(status)?;
            }
            if let Some(size) = attrs.size {
                root.open_with(path, OpenOptions::new().write(true))
                    .map_err(status)?
                    .set_len(size)
                    .map_err(status)?;
            }
        } else {
            if let Some(size) = attrs.size {
                fs::OpenOptions::new()
                    .write(true)
                    .open(path)
                    .map_err(status)?
                    .set_len(size)
                    .map_err(status)?;
            }
            if let Some(mode) = attrs.permissions {
                set_permissions_path(path, mode).map_err(status)?;
            }
            if attrs.atime.is_some() || attrs.mtime.is_some() {
                set_ambient_times(path, attrs).map_err(status)?;
            }
            if attrs.uid.is_some() || attrs.gid.is_some() {
                set_ambient_owner(path, attrs).map_err(status)?;
            }
        }
        Ok(())
    }

    fn require_rw(&self) -> FxResult<()> {
        if self.mode == FileMode::ReadWrite {
            Ok(())
        } else {
            Err(StatusCode::PermissionDenied)
        }
    }

    pub(super) fn process(&mut self, packet: Packet) -> Packet {
        let id = packet.get_request_id();
        self.dispatch(packet)
            .unwrap_or_else(|s| Packet::error(id, s))
    }

    fn dispatch(&mut self, packet: Packet) -> FxResult<Packet> {
        if !matches!(packet, Packet::Init(_)) && !self.initialized {
            return Err(StatusCode::BadMessage);
        }
        let id = packet.get_request_id();
        match packet {
            Packet::Init(_) => {
                if self.initialized {
                    return Err(StatusCode::BadMessage);
                }
                self.initialized = true;
                let mut version = p::Version::new();
                version
                    .extensions
                    .insert("posix-rename@openssh.com".into(), "1".into());
                version
                    .extensions
                    .insert("hardlink@openssh.com".into(), "1".into());
                version
                    .extensions
                    .insert("fsync@openssh.com".into(), "1".into());
                #[cfg(unix)]
                if self.root.is_none() {
                    version
                        .extensions
                        .insert("statvfs@openssh.com".into(), "2".into());
                }
                return Ok(version.into());
            }
            Packet::Open(r) => return self.open(id, &r.filename, r.pflags),
            Packet::Close(r) => {
                self.handles.remove(&r.handle).ok_or(StatusCode::Failure)?;
            }
            Packet::Read(r) => {
                if self.mode.write_only() {
                    return Err(StatusCode::PermissionDenied);
                }
                let Some(OpenHandle::File {
                    file,
                    readable: true,
                    ..
                }) = self.handles.get_mut(&r.handle)
                else {
                    return Err(StatusCode::PermissionDenied);
                };
                file.seek(SeekFrom::Start(r.offset)).map_err(status)?;
                let mut data = vec![0; (r.len as usize).min(256 * 1024)];
                let n = file.read(&mut data).map_err(status)?;
                if n == 0 {
                    return Err(StatusCode::Eof);
                }
                data.truncate(n);
                return Ok(p::Data { id, data }.into());
            }
            Packet::Write(r) => {
                let Some(OpenHandle::File {
                    file,
                    writable: true,
                    ..
                }) = self.handles.get_mut(&r.handle)
                else {
                    return Err(StatusCode::PermissionDenied);
                };
                file.seek(SeekFrom::Start(r.offset)).map_err(status)?;
                file.write_all(&r.data).map_err(status)?;
            }
            Packet::Fstat(r) => {
                let Some(OpenHandle::File { file, .. }) = self.handles.get(&r.handle) else {
                    return Err(StatusCode::Failure);
                };
                return Ok(p::Attrs {
                    id,
                    attrs: (&file.metadata().map_err(status)?).into(),
                }
                .into());
            }
            Packet::Stat(r) => {
                return Ok(p::Attrs {
                    id,
                    attrs: self.stat_path(&self.path(&r.path)?, true)?,
                }
                .into());
            }
            Packet::Lstat(r) => {
                return Ok(p::Attrs {
                    id,
                    attrs: self.stat_path(&self.path(&r.path)?, false)?,
                }
                .into());
            }
            Packet::SetStat(r) => self.setstat_path(&self.path(&r.path)?, &r.attrs)?,
            Packet::FSetStat(r) => {
                if self.mode == FileMode::ReadOnly {
                    return Err(StatusCode::PermissionDenied);
                }
                let Some(OpenHandle::File { file, writable, .. }) = self.handles.get(&r.handle)
                else {
                    return Err(StatusCode::Failure);
                };
                if self.mode.write_only() && !writable {
                    return Err(StatusCode::PermissionDenied);
                }
                set_file_attrs(file, &r.attrs, self.root.is_none()).map_err(status)?;
            }
            Packet::OpenDir(r) => return self.opendir(id, &r.path),
            Packet::ReadDir(r) => {
                let Some(OpenHandle::Directory { entries, next }) = self.handles.get_mut(&r.handle)
                else {
                    return Err(StatusCode::Failure);
                };
                if *next == entries.len() {
                    return Err(StatusCode::Eof);
                }
                let end = (*next + 64).min(entries.len());
                let files = entries[*next..end].to_vec();
                *next = end;
                return Ok(p::Name { id, files }.into());
            }
            Packet::RealPath(r) => {
                let path = self.path(&r.path)?;
                let name = if self.root.is_some() {
                    if path == Path::new(".") {
                        "/".to_owned()
                    } else {
                        format!("/{}", sftp_path(&path))
                    }
                } else {
                    sftp_path(&clean_path(&path))
                };
                return Ok(p::Name {
                    id,
                    files: vec![p::File::dummy(name)],
                }
                .into());
            }
            Packet::MkDir(r) => {
                if matches!(self.mode, FileMode::ReadOnly | FileMode::WriteOnly) {
                    return Err(StatusCode::PermissionDenied);
                }
                let path = self.path(&r.path)?;
                if let Some(root) = &self.root {
                    let mut builder = cap_std::fs::DirBuilder::new();
                    #[cfg(unix)]
                    {
                        use cap_std::fs::DirBuilderExt;
                        builder.mode(0o755);
                    }
                    root.create_dir_with(&path, &builder).map_err(status)?;
                } else {
                    let mut builder = fs::DirBuilder::new();
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::DirBuilderExt;
                        builder.mode(0o755);
                    }
                    builder.create(&path).map_err(status)?;
                }
                if self.mode.write_only() {
                    self.wrote.insert(path.clone(), path);
                }
            }
            Packet::Remove(r) => {
                self.require_rw()?;
                let path = self.path(&r.filename)?;
                if let Some(root) = &self.root {
                    root.remove_file_or_symlink(path).map_err(status)?;
                } else {
                    fs::remove_file(path).map_err(status)?;
                }
            }
            Packet::RmDir(r) => {
                self.require_rw()?;
                let path = self.path(&r.path)?;
                if let Some(root) = &self.root {
                    root.remove_dir(path).map_err(status)?;
                } else {
                    fs::remove_dir(path).map_err(status)?;
                }
            }
            Packet::Rename(r) => self.rename(&r.oldpath, &r.newpath)?,
            Packet::ReadLink(r) => {
                if self.mode.write_only() {
                    return Err(StatusCode::PermissionDenied);
                }
                let path = self.path(&r.path)?;
                let target = if let Some(root) = &self.root {
                    root.read_link_contents(path)
                } else {
                    fs::read_link(path)
                }
                .map_err(status)?;
                return Ok(p::Name {
                    id,
                    files: vec![p::File::dummy(target.to_string_lossy())],
                }
                .into());
            }
            Packet::Symlink(r) => {
                self.require_rw()?;
                // OpenSSH uses the original (target) path first, contrary to
                // the v3 draft's field names. russh-sftp exposes wire order.
                let target = if self.root.is_some() {
                    relative(&r.linkpath)?
                } else {
                    self.path(&r.linkpath)?
                };
                let link = self.path(&r.targetpath)?;
                if let Some(root) = &self.root {
                    DirExt::symlink(root.as_ref(), target, link).map_err(status)?;
                } else {
                    ambient_symlink(&target, &link).map_err(status)?;
                }
            }
            Packet::Extended(r) => {
                let mut bytes = r.data.as_slice();
                let first = read_string(&mut bytes)?;
                match r.request.as_str() {
                    "posix-rename@openssh.com" => {
                        let second = read_string(&mut bytes)?;
                        self.rename(&first, &second)?;
                    }
                    "hardlink@openssh.com" => {
                        self.require_rw()?;
                        let src = self.path(&first)?;
                        let dst = self.path(&read_string(&mut bytes)?)?;
                        if let Some(root) = &self.root {
                            root.hard_link(src, root, dst).map_err(status)?;
                        } else {
                            fs::hard_link(src, dst).map_err(status)?;
                        }
                    }
                    "fsync@openssh.com" => {
                        let Some(OpenHandle::File { file, .. }) = self.handles.get(&first) else {
                            return Err(StatusCode::Failure);
                        };
                        file.sync_all().map_err(status)?;
                    }
                    #[cfg(unix)]
                    "statvfs@openssh.com" if self.root.is_none() => {
                        return Ok(p::ExtendedReply {
                            id,
                            data: ambient_statvfs(&self.path(&first)?).map_err(status)?,
                        }
                        .into());
                    }
                    _ => return Err(StatusCode::OpUnsupported),
                }
            }
            _ => return Err(StatusCode::OpUnsupported),
        }
        Ok(Packet::status(id, StatusCode::Ok, "Ok", "en-US"))
    }

    fn rename(&self, old: &str, new: &str) -> FxResult<()> {
        self.require_rw()?;
        let old = self.path(old)?;
        let new = self.path(new)?;
        if let Some(root) = &self.root {
            root.rename(old, root, new).map_err(status)
        } else {
            fs::rename(old, new).map_err(status)
        }
    }
}

fn read_string(bytes: &mut &[u8]) -> FxResult<String> {
    if bytes.len() < 4 {
        return Err(StatusCode::BadMessage);
    }
    let n = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    *bytes = &bytes[4..];
    if bytes.len() < n {
        return Err(StatusCode::BadMessage);
    }
    let s = std::str::from_utf8(&bytes[..n])
        .map_err(|_| StatusCode::BadMessage)?
        .to_owned();
    *bytes = &bytes[n..];
    Ok(s)
}

fn set_file_attrs(
    file: &fs::File,
    attrs: &FileAttributes,
    full_filesystem: bool,
) -> io::Result<()> {
    if full_filesystem && let Some(n) = attrs.size {
        file.set_len(n)?;
    }
    if let Some(mode) = attrs.permissions {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(mode & 0o777))?;
        }
        #[cfg(not(unix))]
        {
            let mut perms = file.metadata()?.permissions();
            perms.set_readonly(mode & 0o200 == 0);
            file.set_permissions(perms)?;
        }
    }
    if attrs.atime.is_some() || attrs.mtime.is_some() {
        let mut times = fs::FileTimes::new();
        if let Some(t) = attrs.atime {
            times = times.set_accessed(UNIX_EPOCH + Duration::from_secs(t as u64));
        }
        if let Some(t) = attrs.mtime {
            times = times.set_modified(UNIX_EPOCH + Duration::from_secs(t as u64));
        }
        file.set_times(times)?;
    }
    if !full_filesystem && let Some(n) = attrs.size {
        file.set_len(n)?;
    }
    if full_filesystem && (attrs.uid.is_some() || attrs.gid.is_some()) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe {
                libc::fchown(
                    file.as_raw_fd(),
                    attrs.uid.unwrap_or(u32::MAX),
                    attrs.gid.unwrap_or(u32::MAX),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        #[cfg(not(unix))]
        return Err(io::ErrorKind::Unsupported.into());
    }
    Ok(())
}

fn set_ambient_owner(path: &Path, attrs: &FileAttributes) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::chown(path, attrs.uid, attrs.gid)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, attrs);
        Err(io::ErrorKind::Unsupported.into())
    }
}

fn set_ambient_times(path: &Path, attrs: &FileAttributes) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
        let time = |value: Option<u32>| libc::timespec {
            tv_sec: value.unwrap_or(0) as libc::time_t,
            tv_nsec: if value.is_some() { 0 } else { libc::UTIME_OMIT },
        };
        let times = [time(attrs.atime), time(attrs.mtime)];
        if unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let file = fs::File::open(path)?;
        let mut times = fs::FileTimes::new();
        if let Some(t) = attrs.atime {
            times = times.set_accessed(UNIX_EPOCH + Duration::from_secs(t as u64));
        }
        if let Some(t) = attrs.mtime {
            times = times.set_modified(UNIX_EPOCH + Duration::from_secs(t as u64));
        }
        file.set_times(times)
    }
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)] // statvfs integer widths differ across Unix targets.
fn ambient_statvfs(path: &Path) -> io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let s = unsafe { stats.assume_init() };
    let flags = u64::from(s.f_flag & libc::ST_RDONLY != 0)
        | (u64::from(s.f_flag & libc::ST_NOSUID != 0) << 1);
    let fields = [
        s.f_bsize as u64,
        s.f_frsize as u64,
        s.f_blocks as u64,
        s.f_bfree as u64,
        s.f_bavail as u64,
        s.f_files as u64,
        s.f_ffree as u64,
        s.f_favail as u64,
        s.f_fsid as u64,
        flags,
        s.f_namemax as u64,
    ];
    Ok(fields.into_iter().flat_map(u64::to_be_bytes).collect())
}

fn set_permissions_path(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))
    }
    #[cfg(not(unix))]
    {
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_readonly(mode & 0o200 == 0);
        fs::set_permissions(path, perms)
    }
}

fn ambient_symlink(target: &Path, link: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        if target.is_dir() {
            std::os::windows::fs::symlink_dir(target, link)
        } else {
            std::os::windows::fs::symlink_file(target, link)
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        Err(io::ErrorKind::Unsupported.into())
    }
}
