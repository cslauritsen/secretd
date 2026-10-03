//! Peer credentials of an accepted Unix connection.
//!
//! The real provider reads `SO_PEERCRED` (`getsockopt`, `struct ucred`) via
//! tokio's `UnixStream::peer_cred`.  Tests inject a [`StaticPeerCred`] so uid
//! logic can be exercised without multiple real users.

use std::io;
use std::sync::Mutex;
use tokio::net::UnixStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

pub trait PeerCredProvider: Send + Sync {
    fn peer_cred(&self, stream: &UnixStream) -> io::Result<PeerCred>;
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
