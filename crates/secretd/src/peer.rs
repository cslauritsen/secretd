//! Peer credentials of an accepted Unix connection.
//!
//! The real provider reads `SO_PEERCRED` (`getsockopt`, `struct ucred`) via
//! tokio's `UnixStream::peer_cred`.  Tests inject a [`StaticPeerCred`] so uid
//! logic can be exercised without multiple real users.

use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
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
    /// `None` is the graceful fallback on older kernels.
    fn peer_pidfd(&self, _stream: &UnixStream) -> Option<OwnedFd> {
        None
    }
}

/// `getsockopt(SO_PEERPIDFD)`; `None` when unsupported (ENOPROTOOPT, EINVAL).
/// macOS has no pidfd: always `None`, callers fall back to start-time checks.
#[cfg(not(target_os = "linux"))]
pub fn peer_pidfd(_stream: &UnixStream) -> Option<OwnedFd> {
    None
}

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

#[cfg(not(target_os = "linux"))]
pub fn pidfd_alive(_fd: BorrowedFd<'_>) -> bool {
    true
}

#[cfg(not(target_os = "linux"))]
pub fn pidfd_pid(_fd: BorrowedFd<'_>) -> Option<u32> {
    None
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

/// Reads the kernel-verified credentials with `SO_PEERCRED`.
pub struct RealPeerCred;

impl PeerCredProvider for RealPeerCred {
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pidfd_of_a_socketpair_peer_is_this_process_when_supported() {
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
