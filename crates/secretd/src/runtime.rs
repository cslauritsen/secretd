//! Process-level plumbing: socket binding, systemd socket activation,
//! privilege dropping.

use std::io;
use std::os::fd::FromRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::net::UnixListener;

/// Sockets inherited from systemd, by role.
#[derive(Default)]
pub struct Activated {
    pub client: Option<UnixListener>,
    pub admin: Option<UnixListener>,
}

/// Parse `LISTEN_PID`/`LISTEN_FDS`/`LISTEN_FDNAMES` (sd_listen_fds protocol).
/// Must be called inside a tokio runtime. Without names, fd 3 is the client
/// socket; with names, `secretd` is the client socket and `admin` the admin one.
pub fn systemd_sockets() -> io::Result<Activated> {
    let mut out = Activated::default();
    let pid_ok = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|p| p.parse::<u32>().ok())
        == Some(std::process::id());
    if !pid_ok {
        return Ok(out);
    }
    let n: i32 = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let names: Vec<String> = std::env::var("LISTEN_FDNAMES")
        .map(|v| v.split(':').map(str::to_string).collect())
        .unwrap_or_default();
    for i in 0..n {
        let fd = 3 + i;
        let name = names.get(i as usize).map(String::as_str);
        let role_client = match name {
            Some("admin") => false,
            Some(_) => true,
            None => i == 0,
        };
        // SAFETY: systemd passed us this descriptor and we take sole ownership.
        let std_l = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
        std_l.set_nonblocking(true)?;
        let l = UnixListener::from_std(std_l)?;
        if role_client {
            if out.client.is_none() {
                out.client = Some(l);
            }
        } else if out.admin.is_none() {
            out.admin = Some(l);
        }
    }
    Ok(out)
}

/// Bind a Unix socket at `path` with the given mode. A stale socket file is
/// replaced; anything else at the path is an error.
pub fn bind_unix(path: &Path, mode: u32) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))?;
        }
    }
    if let Ok(md) = std::fs::symlink_metadata(path) {
        use std::os::unix::fs::FileTypeExt;
        if md.file_type().is_socket() {
            std::fs::remove_file(path)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
    }
    // SAFETY: umask is a trivial syscall; restored immediately below.
    let old = unsafe { libc::umask(0o177) };
    let l = UnixListener::bind(path);
    // SAFETY: as above.
    unsafe {
        libc::umask(old);
    }
    let l = l?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(l)
}

pub fn chown_to_user(path: &Path, user: &str) -> io::Result<()> {
    let u = nix::unistd::User::from_name(user)
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other(format!("no such user {user:?}")))?;
    nix::unistd::chown(path, Some(u.uid), Some(u.gid)).map_err(io::Error::other)
}

/// If running as root, drop to `user` (supplementary groups included) and
/// verify root cannot be regained. No-op when already unprivileged.
pub fn drop_privileges(user: &str) -> io::Result<()> {
    if !nix::unistd::geteuid().is_root() {
        return Ok(());
    }
    let u = nix::unistd::User::from_name(user)
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other(format!("no such user {user:?}")))?;
    if u.uid.is_root() {
        return Ok(());
    }
    let cname = std::ffi::CString::new(user).map_err(io::Error::other)?;
    nix::unistd::initgroups(&cname, u.gid).map_err(io::Error::other)?;
    nix::unistd::setgid(u.gid).map_err(io::Error::other)?;
    nix::unistd::setuid(u.uid).map_err(io::Error::other)?;
    if nix::unistd::setuid(nix::unistd::Uid::from_raw(0)).is_ok() {
        return Err(io::Error::other("privilege drop did not stick"));
    }
    Ok(())
}
