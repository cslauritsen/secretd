//! Process-level plumbing: socket binding, socket activation (systemd on
//! Linux, launchd on macOS), privilege dropping.

use std::io;
use std::os::fd::FromRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::net::UnixListener;

/// Sockets inherited from the service manager, by role.
#[derive(Default)]
pub struct Activated {
    pub client: Option<UnixListener>,
    pub admin: Option<UnixListener>,
}

/// Sockets handed over by the service manager of this OS: systemd
/// (`LISTEN_FDS`) on Linux, launchd (`launch_activate_socket`) on macOS.
/// Empty when the daemon was not socket activated, in which case it binds its
/// own sockets. Must be called inside a tokio runtime.
pub fn activated_sockets() -> io::Result<Activated> {
    #[cfg(target_os = "linux")]
    {
        systemd_sockets()
    }
    #[cfg(target_os = "macos")]
    {
        launchd_sockets()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Ok(Activated::default())
    }
}

/// Adopt an inherited listening descriptor.
fn listener_from_fd(fd: std::os::fd::RawFd) -> io::Result<UnixListener> {
    // SAFETY: the service manager passed us this descriptor and we take sole
    // ownership of it.
    let std_l = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    std_l.set_nonblocking(true)?;
    UnixListener::from_std(std_l)
}

/// launchd: the `Sockets` entries named `secretd` (client) and `admin` of the
/// job's plist. Not started by launchd, or no such entry, is not an error: the
/// daemon then binds its own sockets (the default on macOS, see
/// `packaging/launchd/`). Entries carry their own mode and owner in the plist.
#[cfg(target_os = "macos")]
fn launchd_sockets() -> io::Result<Activated> {
    let mut out = Activated::default();
    for (name, is_client) in [("secretd", true), ("admin", false)] {
        let fds = match crate::macos::launchd_sockets(name) {
            Ok(f) => f,
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ESRCH) | Some(libc::ENOENT) | Some(libc::EALREADY)
                ) =>
            {
                continue
            }
            Err(e) => return Err(e),
        };
        for fd in fds {
            let l = listener_from_fd(fd)?;
            let slot = if is_client {
                &mut out.client
            } else {
                &mut out.admin
            };
            if slot.is_none() {
                *slot = Some(l);
            }
        }
    }
    Ok(out)
}

/// Parse `LISTEN_PID`/`LISTEN_FDS`/`LISTEN_FDNAMES` (sd_listen_fds protocol).
/// Must be called inside a tokio runtime. Without names, fd 3 is the client
/// socket; with names, `secretd` is the client socket and `admin` the admin one.
#[cfg(target_os = "linux")]
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
        let l = listener_from_fd(fd)?;
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

/// Give `path` to `user`, and to `group` if given (else the user's primary
/// group). The client socket uses a dedicated group so that connecting to it
/// does not imply any access to the daemon's credential files.
pub fn chown_to_user(path: &Path, user: &str, group: Option<&str>) -> io::Result<()> {
    let u = nix::unistd::User::from_name(user)
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other(format!("no such user {user:?}")))?;
    let gid = match group {
        Some(g) => {
            nix::unistd::Group::from_name(g)
                .map_err(io::Error::other)?
                .ok_or_else(|| io::Error::other(format!("no such group {g:?}")))?
                .gid
        }
        None => u.gid,
    };
    nix::unistd::chown(path, Some(u.uid), Some(gid)).map_err(io::Error::other)
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
    // nix has no initgroups on macOS; secret_proto::sys wraps the libc call.
    secret_proto::sys::init_groups(user, u.gid.as_raw())?;
    nix::unistd::setgid(u.gid).map_err(io::Error::other)?;
    nix::unistd::setuid(u.uid).map_err(io::Error::other)?;
    if nix::unistd::setuid(nix::unistd::Uid::from_raw(0)).is_ok() {
        return Err(io::Error::other("privilege drop did not stick"));
    }
    Ok(())
}
