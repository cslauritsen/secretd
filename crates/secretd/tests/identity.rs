//! Caller identity capture: snapshot at accept, re-check when `secret.get`
//! arrives, pidfd liveness and the order of capture vs connection caps.
mod common;
use common::*;
use secretd::peer::{PeerCred, PeerCredProvider, StaticPeerCred};
use secretd::procinfo::{ProcInfo, ProcReader};
use serde_json::json;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::UnixStream;

#[tokio::test]
async fn exec_between_accept_and_get_is_caught_at_request_time() {
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    c.call("server.ping", json!({})).await; // the accept snapshot is taken
                                            // Accept snapshot said "psql"; before the first request the process
                                            // (or whoever holds the connection) turns into something else.
    let mut p = psql_proc();
    p.exe = "/opt/test/bin/evil".into();
    h.procs.set(PID, p);
    c.send("secret.get", json!({"name": "db-password"})).await;
    assert_eq!(err_kind(&c.recv().await.unwrap()), "CALLER_CHANGED");
    assert_eq!(
        h.notifier.count(),
        0,
        "no notification for a changed caller"
    );
    assert_eq!(h.core.pending_count(), 0);
    assert!(h.audit_events().contains(&"caller_changed".to_string()));
}

#[tokio::test]
async fn pid_reuse_or_exit_between_accept_and_get_is_caught() {
    for mutate in [
        Box::new(|h: &Harness| {
            let mut p = psql_proc();
            p.start_time += 1;
            h.procs.set(PID, p);
        }) as Box<dyn Fn(&Harness)>,
        Box::new(|h: &Harness| h.procs.remove(PID)),
    ] {
        let h = Harness::start(Opts::default()).await;
        let mut c = h.connect().await;
        c.call("server.ping", json!({})).await;
        mutate(&h);
        assert_eq!(err_kind(&c.get("db-password").await), "CALLER_CHANGED");
        assert_eq!(h.notifier.count(), 0);
    }
}

#[tokio::test]
async fn list_hides_names_from_a_changed_caller() {
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    let r = c.call("secret.list", json!({})).await;
    assert!(!r.result.unwrap()["names"].as_array().unwrap().is_empty());
    h.procs.remove(PID);
    let r = c.call("secret.list", json!({})).await;
    assert!(r.result.unwrap()["names"].as_array().unwrap().is_empty());
}

/// Counts `/proc` reads so tests can see that capture happens even for
/// connections that are then refused by a cap.
struct Counting {
    inner: Arc<dyn ProcReader>,
    reads: Arc<AtomicUsize>,
}
impl ProcReader for Counting {
    fn read(&self, pid: u32) -> io::Result<ProcInfo> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.read(pid)
    }
}

#[tokio::test]
async fn identity_is_captured_before_the_connection_cap_is_checked() {
    let reads = Arc::new(AtomicUsize::new(0));
    let inner = Arc::new(secretd::procinfo::StaticProcReader::new());
    inner.set(PID, psql_proc());
    let h = Harness::start(Opts {
        limits: "max_conns_per_uid = 1".into(),
        procs: Some(Arc::new(Counting {
            inner,
            reads: reads.clone(),
        })),
        ..Opts::default()
    })
    .await;
    let _a = h.connect().await;
    let mut b = h.connect().await; // over the cap
    assert_eq!(err_kind(&b.recv().await.unwrap()), "RATE_LIMITED");
    assert_eq!(
        reads.load(Ordering::SeqCst),
        2,
        "both accepts were snapshotted"
    );
}

/// Provider that reports a pidfd for a given child process.
struct WithPidfd {
    base: StaticPeerCred,
    fd: std::os::fd::RawFd,
}
impl PeerCredProvider for WithPidfd {
    fn peer_cred(&self, s: &UnixStream) -> io::Result<PeerCred> {
        self.base.peer_cred(s)
    }
    fn peer_pidfd(&self, _s: &UnixStream) -> Option<OwnedFd> {
        // SAFETY: dup of a descriptor owned by the test for its whole duration.
        let d = unsafe { libc::dup(self.fd) };
        (d >= 0).then(|| unsafe { OwnedFd::from_raw_fd(d) })
    }
}

#[tokio::test]
async fn a_dead_pidfd_means_the_caller_changed() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    // SAFETY: plain syscall, result checked.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0) };
    if raw < 0 {
        eprintln!("pidfd_open unsupported; skipping");
        let _ = child.kill();
        let _ = child.wait();
        return;
    }
    let pid = child.id();
    let procs = Arc::new(secretd::procinfo::StaticProcReader::new());
    procs.set(pid, psql_proc());
    let h = Harness::start(Opts {
        peer: Some(Arc::new(WithPidfd {
            base: StaticPeerCred::new(PeerCred {
                uid: 1000,
                gid: 100,
                pid,
            }),
            fd: raw as i32,
        })),
        procs: Some(procs),
        ..Opts::default()
    })
    .await;
    let mut c = h.connect().await;
    // Alive: ordinary request waits for the owner.
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = h.notifier.wait_for(1).await;
    h.core.deny(&n[0].request_id, secretd::core::Source::Admin);
    assert_eq!(err_kind(&c.recv().await.unwrap()), "DENIED");
    // The process dies; /proc still (wrongly, as after pid reuse) looks the same.
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(err_kind(&c.get("second").await), "CALLER_CHANGED");
}
