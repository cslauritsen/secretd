//! Peer credentials of an accepted Unix connection.
//!
//! Linux: `SO_PEERCRED` (`struct ucred`: pid, uid, gid) via tokio's
//! `UnixStream::peer_cred`, plus `SO_PEERPIDFD` where the kernel has it.
//!
//! macOS: uid and gid from `getpeereid` (the `LOCAL_PEERCRED` credentials,
//! which is what tokio's `peer_cred` returns there) and the pid from
//! `LOCAL_PEERPID`, the process that called `connect`. tokio itself would
//! report `LOCAL_PEEREPID`, the *effective* pid, which differs from the
//! connecting process for delegated sockets, so the pid is read here. macOS
//! has no pidfd: a recycled pid is caught by the start time only.
//!
//! Tests inject a [`StaticPeerCred`] so uid logic can be exercised without
//! multiple real users.

use std::io;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::sync::Mutex;
use tokio::net::UnixStream;

/// `SO_PEERPIDFD` (Linux 6.5+): a pidfd for the process that created the
/// peer socket. Not exported by every libc version, so spelled out here.
#[cfg(target_os = "linux")]
const SO_PEERPIDFD: libc::c_int = 77;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

pub trait PeerCredProvider: Send + Sync {
    fn peer_cred(&self, stream: &UnixStream) -> io::Result<PeerCred>;

    /// A pidfd for the peer (`SO_PEERPIDFD`), if the kernel supports it.
    /// With it a recycled pid can be told apart from the original process.
    /// `None` is the graceful fallback on older kernels and on macOS.
    fn peer_pidfd(&self, _stream: &UnixStream) -> Option<OwnedFd> {
        None
    }
}

/// `getsockopt(SO_PEERPIDFD)`; `None` when unsupported (ENOPROTOOPT, EINVAL).
#[cfg(target_os = "linux")]
pub fn peer_pidfd(stream: &UnixStream) -> Option<OwnedFd> {
    let mut fd: libc::c_int = -1;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd`/`len` are valid for writes of the sizes passed; the socket
    // descriptor is valid for the duration of the call.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            (&mut fd as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc != 0 || fd < 0 {
        return None;
    }
    // SAFETY: the kernel just installed `fd` for us; we own it exclusively.
    Some(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// True while the process behind `fd` has not exited (signal 0 probe).
#[cfg(target_os = "linux")]
pub fn pidfd_alive(fd: BorrowedFd<'_>) -> bool {
    // SAFETY: pidfd_send_signal(fd, 0, NULL, 0) only probes for existence.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    rc == 0
}

/// The pid a pidfd refers to, from `/proc/self/fdinfo/<fd>`.
#[cfg(target_os = "linux")]
pub fn pidfd_pid(fd: BorrowedFd<'_>) -> Option<u32> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).ok()?;
    info.lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .and_then(|v| v.trim().parse().ok())
}

/// No pidfds off Linux, so nothing can be named by one and nothing is alive.
/// Unreachable in practice, because [`PeerCredProvider::peer_pidfd`] never
/// returns a descriptor there; failing closed keeps it safe regardless.
#[cfg(not(target_os = "linux"))]
pub fn pidfd_alive(_fd: BorrowedFd<'_>) -> bool {
    false
}

/// See [`pidfd_alive`]: no pidfds off Linux.
#[cfg(not(target_os = "linux"))]
pub fn pidfd_pid(_fd: BorrowedFd<'_>) -> Option<u32> {
    None
}

/// macOS: the pid of the process that connected,
/// `getsockopt(SOL_LOCAL, LOCAL_PEERPID)`.
#[cfg(target_os = "macos")]
pub fn local_peerpid(stream: &UnixStream) -> io::Result<u32> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: `pid`/`len` are valid for writes of the sizes passed; the socket
    // descriptor is valid for the duration of the call.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    u32::try_from(pid)
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| io::Error::other("peer pid unavailable"))
}

/// Reads the kernel-verified credentials (`SO_PEERCRED` on Linux,
/// `LOCAL_PEERCRED` and `LOCAL_PEERPID` on macOS).
pub struct RealPeerCred;

impl PeerCredProvider for RealPeerCred {
    #[cfg(target_os = "macos")]
    fn peer_cred(&self, stream: &UnixStream) -> io::Result<PeerCred> {
        let c = stream.peer_cred()?; // getpeereid: uid and effective gid
        Ok(PeerCred {
            uid: c.uid(),
            gid: c.gid(),
            pid: local_peerpid(stream)?,
        })
    }

    #[cfg(not(target_os = "macos"))]
    fn peer_cred(&self, stream: &UnixStream) -> io::Result<PeerCred> {
        let c = stream.peer_cred()?;
        let pid = c
            .pid()
            .and_then(|p| u32::try_from(p).ok())
            .ok_or_else(|| io::Error::other("peer pid unavailable"))?;
        Ok(PeerCred {
            uid: c.uid(),
            gid: c.gid(),
            pid,
        })
    }

    #[cfg(target_os = "linux")]
    fn peer_pidfd(&self, stream: &UnixStream) -> Option<OwnedFd> {
        peer_pidfd(stream)
    }
}

/// Returns whatever credentials were last set; for tests.
pub struct StaticPeerCred(Mutex<PeerCred>);

impl StaticPeerCred {
    pub fn new(cred: PeerCred) -> Self {
        StaticPeerCred(Mutex::new(cred))
    }
    pub fn set(&self, cred: PeerCred) {
        *self.0.lock().unwrap() = cred;
    }
}

impl PeerCredProvider for StaticPeerCred {
    fn peer_cred(&self, _stream: &UnixStream) -> io::Result<PeerCred> {
        Ok(*self.0.lock().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_peer_cred_of_a_socketpair_is_this_process() {
        let (a, _b) = UnixStream::pair().unwrap();
        let c = RealPeerCred.peer_cred(&a).unwrap();
        assert_eq!(c.pid, std::process::id());
        // SAFETY: plain syscalls that cannot fail.
        assert_eq!(c.uid, unsafe { libc::geteuid() });
        assert_eq!(c.gid, unsafe { libc::getegid() });
        assert!(RealPeerCred.peer_pidfd(&a).is_none(), "macOS has no pidfd");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pidfd_of_a_socketpair_peer_is_this_process_when_supported() {
        use std::os::fd::AsFd;
        let (a, _b) = UnixStream::pair().unwrap();
        match RealPeerCred.peer_pidfd(&a) {
            Some(fd) => {
                assert_eq!(pidfd_pid(fd.as_fd()), Some(std::process::id()));
                assert!(pidfd_alive(fd.as_fd()));
            }
            None => eprintln!("SO_PEERPIDFD unsupported here; fallback path"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_liveness_tracks_the_process() {
        use std::os::fd::AsFd;
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        // SAFETY: plain syscall; result checked.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0) };
        if raw < 0 {
            eprintln!("pidfd_open unsupported; skipping");
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
        // SAFETY: freshly returned descriptor, owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        assert!(pidfd_alive(fd.as_fd()));
        assert_eq!(pidfd_pid(fd.as_fd()), Some(child.id()));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!pidfd_alive(fd.as_fd()), "a reaped process is gone");
    }
}
