//! Named-pipe secrets (spec 20.6): reader detection, delivery, identity and
//! ACL rules, re-verification, limits and cool-down, write deadline.
mod common;
use common::*;
use secret_proto::config::FifoCfg;
use secret_proto::store::{self, Entry};
use secretd::core::{ApproveOutcome, DenyOutcome, Source};
use secretd::fifo::{self, FifoHandle, ProcScanner, ReaderIdent, ReaderScanner};
use secretd::procinfo::{ProcInfo, ProcInfoReader, RealProcReader};
use std::collections::VecDeque;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SECRET: &[u8] = b"hunter2-secret-value";

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}
fn egid() -> u32 {
    unsafe { libc::getegid() }
}

/// A scanner whose answers the test scripts: per-call answers first, then the default.
struct Script {
    queue: Mutex<VecDeque<Vec<ReaderIdent>>>,
    default: Mutex<Vec<ReaderIdent>>,
    calls: AtomicUsize,
    /// Make the `n`th call (1-based) take this long.
    slow: Mutex<Option<(usize, Duration)>>,
}

impl Script {
    fn new(default: Vec<ReaderIdent>) -> Arc<Script> {
        Arc::new(Script {
            queue: Mutex::new(VecDeque::new()),
            default: Mutex::new(default),
            calls: AtomicUsize::new(0),
            slow: Mutex::new(None),
        })
    }
    fn set_default(&self, v: Vec<ReaderIdent>) {
        *self.default.lock().unwrap() = v;
    }
    fn slow_call(&self, n: usize, d: Duration) {
        *self.slow.lock().unwrap() = Some((n, d));
    }
    fn then(&self, v: Vec<ReaderIdent>) {
        self.queue.lock().unwrap().push_back(v);
    }
}

impl ReaderScanner for Script {
    fn readers(&self, _dev: u64, _ino: u64) -> std::io::Result<Vec<ReaderIdent>> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let slow = *self.slow.lock().unwrap();
        if let Some((at, d)) = slow {
            if at == n {
                std::thread::sleep(d);
            }
        }
        Ok(self
            .queue
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| self.default.lock().unwrap().clone()))
    }
}

/// The reader that satisfies the harness ACL of `db-password`.
fn psql_reader(pid: u32) -> ReaderIdent {
    ReaderIdent {
        pid,
        uid: 1000,
        gid: 100,
        proc: Some(ProcInfo {
            exe: PSQL.into(),
            cmdline: "psql -h db".into(),
            start_time: 1111,
        }),
    }
}

fn fifo_cfg(h: &Harness, name: &str, secret: &str) -> FifoCfg {
    FifoCfg {
        path: h.dir.path().join("pipes").join(name),
        secret: secret.into(),
        owner: None,
        gid: egid(),
        mode: 0o640,
        enforce_acl: false,
        attempts_per_min: 10,
        cooldown_secs: 0,
        write_deadline_secs: 5,
    }
}

fn start(h: &Harness, scan: Arc<dyn ReaderScanner>, cfgs: &[FifoCfg]) -> FifoHandle {
    fifo::start(h.core.clone(), scan, cfgs, euid()).expect("fifo setup")
}

/// Open the pipe for reading in a blocking thread and read it to EOF.
fn read_pipe(path: PathBuf) -> tokio::task::JoinHandle<std::io::Result<Vec<u8>>> {
    tokio::task::spawn_blocking(move || {
        let mut f = std::fs::File::open(&path)?;
        let mut v = Vec::new();
        f.read_to_end(&mut v)?;
        Ok(v)
    })
}

async fn wait_audit(h: &Harness, what: &str, f: impl Fn(&serde_json::Value) -> bool) {
    for _ in 0..600 {
        if h.audit_lines().iter().any(&f) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for audit {what}: {:?}", h.audit_lines());
}

fn ev(h: &Harness, name: &str) -> Vec<serde_json::Value> {
    h.audit_lines()
        .into_iter()
        .filter(|l| l["event"] == name)
        .collect()
}

fn assert_no_secret_in_audit(h: &Harness) {
    let raw = h.audit_raw();
    for bad in ["hunter2", PASS, "not-yours", "second-value"] {
        assert!(!raw.contains(bad), "audit leaks {bad}");
    }
}

async fn put_secret(h: &Harness, name: &str, bytes: &[u8]) {
    let mut s = store::load(&h.store, &pw(PASS)).unwrap();
    s.insert(name, Entry::from_bytes(bytes));
    store::save(&h.store, &pw(PASS), &s, WF).unwrap();
}

#[tokio::test]
async fn reader_triggers_notification_and_approval_delivers_bytes_then_eof() {
    let h = Harness::start(Opts::default()).await;
    let cfg = fifo_cfg(&h, "db", "db-password");
    let path = cfg.path.clone();
    let scan = Script::new(vec![psql_reader(777)]);
    let handle = start(&h, scan.clone(), &[cfg]);
    // The pipe exists with the configured mode.
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let md = std::fs::symlink_metadata(&path).unwrap();
    assert!(md.file_type().is_fifo());
    assert_eq!(md.mode() & 0o7777, 0o640);

    // No reader, no request.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(h.notifier.count(), 0);
    assert_eq!(h.core.pending_count(), 0);
    assert_eq!(scan.calls.load(Ordering::SeqCst), 0);

    // A reader opens the pipe: a request appears, identity and "via" included.
    let reader = read_pipe(path.clone());
    let n = h.notifier.wait_for(1).await;
    let n = &n[0];
    assert_eq!(
        n.via.as_deref(),
        Some(format!("via FIFO {}", path.display()).as_str())
    );
    assert_eq!(n.secret_name, "db-password");
    assert_eq!((n.uid, n.pid, n.exe.as_str()), (1000, 777, PSQL));
    assert!(n.identified);
    assert_eq!(
        n.reason.as_deref(),
        Some(format!("read of {}", path.display()).as_str())
    );
    // The reader is still blocked: nothing arrives before the approval.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!reader.is_finished());

    assert_eq!(
        h.core.approve(&n.request_id, pw(PASS), Source::Admin).await,
        ApproveOutcome::Released
    );
    assert_eq!(
        reader.await.unwrap().unwrap(),
        SECRET,
        "exact bytes, then EOF"
    );
    // The one approval served exactly one open: the pipe is quiet again.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(h.notifier.count(), 1);
    let released = ev(&h, "released");
    assert_eq!(released.len(), 1);
    assert_eq!(released[0]["fifo"], path.display().to_string().as_str());
    let rr = ev(&h, "request_received");
    assert_eq!(rr[0]["fifo"], path.display().to_string().as_str());
    assert_eq!(rr[0]["pid"], 777);
    assert_no_secret_in_audit(&h);
    handle.shutdown().await;
    assert!(!path.exists(), "removed on shutdown");
}

#[tokio::test]
async fn deny_and_timeout_give_eof_without_data() {
    let h = Harness::start(Opts {
        timeout_secs: 2,
        ..Opts::default()
    })
    .await;
    let cfg = fifo_cfg(&h, "db", "db-password");
    let path = cfg.path.clone();
    let _handle = start(&h, Script::new(vec![psql_reader(777)]), &[cfg]);

    let reader = read_pipe(path.clone());
    let n = h.notifier.wait_for(1).await;
    assert_eq!(
        h.core.deny(&n[0].request_id, Source::Admin),
        DenyOutcome::Denied
    );
    assert_eq!(reader.await.unwrap().unwrap(), b"", "denied: EOF, no data");

    // Timeout (no cool-down configured, so the pipe is armed again at once).
    let reader = read_pipe(path.clone());
    let t0 = Instant::now();
    assert_eq!(
        reader.await.unwrap().unwrap(),
        b"",
        "timed out: EOF, no data"
    );
    assert!(t0.elapsed() >= Duration::from_millis(1500));
    assert_eq!(ev(&h, "timeout").len(), 1);
    assert_eq!(ev(&h, "denied").len(), 1);
    assert!(ev(&h, "released").is_empty());
    assert_no_secret_in_audit(&h);
}

#[tokio::test]
async fn reader_that_exits_before_approval_aborts_and_nothing_is_written() {
    let h = Harness::start(Opts::default()).await;
    let cfg = fifo_cfg(&h, "db", "db-password");
    let path = cfg.path.clone();
    let _handle = start(&h, Script::new(vec![psql_reader(777)]), &[cfg]);
    // Open and close without reading.
    let p2 = path.clone();
    let quitter = tokio::task::spawn_blocking(move || {
        let f = std::fs::File::open(&p2).unwrap();
        std::thread::sleep(Duration::from_millis(400));
        drop(f);
    });
    let n = h.notifier.wait_for(1).await;
    quitter.await.unwrap();
    wait_audit(&h, "client_disconnected", |l| {
        l["event"] == "client_disconnected" && l["outcome"] == "reader_gone"
    })
    .await;
    assert_eq!(h.core.pending_count(), 0);
    // A late approval finds nothing and nothing was released.
    assert_eq!(
        h.core
            .approve(&n[0].request_id, pw(PASS), Source::Admin)
            .await,
        ApproveOutcome::Gone
    );
    assert!(ev(&h, "released").is_empty());
    assert_no_secret_in_audit(&h);
}

#[tokio::test]
async fn identity_of_a_real_reader_is_captured() {
    let h = Harness::start(Opts::default()).await;
    let cfg = fifo_cfg(&h, "db", "db-password");
    let path = cfg.path.clone();
    let scan = Arc::new(ProcScanner::new(Arc::new(RealProcReader)));
    let _handle = start(&h, scan, &[cfg]);
    let child = std::process::Command::new("cat")
        .arg(&path)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let n = h.notifier.wait_for(1).await;
    let n = &n[0];
    assert_eq!(n.pid, pid, "the cat process, not the daemon");
    assert_eq!(n.uid, euid());
    assert_eq!(n.exe, exe_of(pid));
    assert!(
        n.cmdline.contains(&path.display().to_string()),
        "{}",
        n.cmdline
    );
    assert!(n.identified && n.via.is_some());
    assert_eq!(
        h.core.approve(&n.request_id, pw(PASS), Source::Admin).await,
        ApproveOutcome::Released
    );
    let out = tokio::task::spawn_blocking(move || child.wait_with_output().unwrap())
        .await
        .unwrap();
    assert_eq!(out.stdout, SECRET);
    assert_no_secret_in_audit(&h);
}

/// The executable of a live process as the OS reports it (`/proc/<pid>/exe` on
/// Linux, `proc_pidpath` on macOS).
fn exe_of(pid: u32) -> String {
    RealProcReader.read(pid).unwrap().exe
}

/// Path of the executable `cat` really is (as the OS reports it).
fn cat_exe() -> String {
    let mut c = std::process::Command::new("cat")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let exe = exe_of(c.id());
    let _ = c.kill();
    let _ = c.wait();
    exe
}

#[tokio::test]
async fn enforce_acl_with_real_readers_allow_and_deny() {
    let extra = format!(
        "\n[[secret]]\nname = \"catsecret\"\nallow_uids = [{}]\nallow_exes = [\"{}\"]\n",
        euid(),
        cat_exe()
    );
    let h = Harness::start(Opts {
        extra,
        ..Opts::default()
    })
    .await;
    put_secret(&h, "catsecret", b"cat-secret-value").await;
    let mut ok = fifo_cfg(&h, "allowed", "catsecret");
    ok.enforce_acl = true;
    let mut bad = fifo_cfg(&h, "denied", "db-password"); // ACL wants psql, not cat
    bad.enforce_acl = true;
    let (ok_path, bad_path) = (ok.path.clone(), bad.path.clone());
    let scan = Arc::new(ProcScanner::new(Arc::new(RealProcReader)));
    let _handle = start(&h, scan, &[ok, bad]);

    // A reader that fails the ACL: no notification, EOF, audited.
    let denied = tokio::task::spawn_blocking({
        let p = bad_path.clone();
        move || {
            std::process::Command::new("cat")
                .arg(&p)
                .output()
                .unwrap()
                .stdout
        }
    });
    assert_eq!(denied.await.unwrap(), b"");
    assert_eq!(h.notifier.count(), 0);
    wait_audit(&h, "acl_denied", |l| {
        l["event"] == "acl_denied"
            && l["outcome"] == "fifo_acl"
            && l["fifo"] == bad_path.display().to_string().as_str()
    })
    .await;

    // A reader that passes it is announced and served.
    let child = std::process::Command::new("cat")
        .arg(&ok_path)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let n = h.notifier.wait_for(1).await;
    assert_eq!(n[0].secret_name, "catsecret");
    assert_eq!(
        h.core
            .approve(&n[0].request_id, pw(PASS), Source::Admin)
            .await,
        ApproveOutcome::Released
    );
    let out = tokio::task::spawn_blocking(move || child.wait_with_output().unwrap())
        .await
        .unwrap();
    assert_eq!(out.stdout, b"cat-secret-value");
}

#[tokio::test]
async fn unknown_reader_and_two_readers() {
    let h = Harness::start(Opts::default()).await;
    // enforce_acl: nobody identified -> fifo_reader_unknown, EOF.
    let mut strict = fifo_cfg(&h, "strict", "db-password");
    strict.enforce_acl = true;
    let strict_path = strict.path.clone();
    let scan = Script::new(vec![]);
    let handle = start(&h, scan.clone(), &[strict]);
    assert_eq!(read_pipe(strict_path.clone()).await.unwrap().unwrap(), b"");
    wait_audit(&h, "fifo_reader_unknown", |l| {
        l["event"] == "fifo_reader_unknown"
    })
    .await;
    assert_eq!(h.notifier.count(), 0);
    handle.shutdown().await;

    // Informational mode: the unidentified reader is announced as such and served.
    let lax = fifo_cfg(&h, "lax", "db-password");
    let lax_path = lax.path.clone();
    let _handle = start(&h, scan.clone(), &[lax]);
    let reader = read_pipe(lax_path);
    let n = h.notifier.wait_for(1).await;
    assert!(!n[0].identified);
    assert!(n[0].via.is_some());
    assert_eq!(
        h.core
            .approve(&n[0].request_id, pw(PASS), Source::Admin)
            .await,
        ApproveOutcome::Released
    );
    assert_eq!(reader.await.unwrap().unwrap(), SECRET);

    // Two distinct readers at request time: denied as ambiguous.
    let two = fifo_cfg(&h, "two", "db-password");
    let two_path = two.path.clone();
    let scan2 = Script::new(vec![psql_reader(1), psql_reader(2)]);
    let _h2 = start(&h, scan2, &[two]);
    assert_eq!(read_pipe(two_path).await.unwrap().unwrap(), b"");
    wait_audit(&h, "fifo_ambiguous", |l| {
        l["event"] == "fifo_ambiguous" && l["outcome"] == "at_request"
    })
    .await;
    assert_eq!(h.notifier.count(), 1, "no second notification");
    assert_no_secret_in_audit(&h);
}

#[tokio::test]
async fn reader_set_change_between_request_and_release_aborts() {
    for second in [
        vec![psql_reader(778)],                   // a different process
        vec![],                                   // nobody left
        vec![psql_reader(777), psql_reader(778)], // a second reader joined
    ] {
        let ambiguous = second.len() > 1;
        let h = Harness::start(Opts::default()).await;
        let cfg = fifo_cfg(&h, "db", "db-password");
        let path = cfg.path.clone();
        let scan = Script::new(vec![psql_reader(777)]);
        let handle = start(&h, scan.clone(), &[cfg]);
        let reader = read_pipe(path);
        let n = h.notifier.wait_for(1).await;
        // The release-time scan sees something else.
        scan.then(second);
        assert_eq!(
            h.core
                .approve(&n[0].request_id, pw(PASS), Source::Admin)
                .await,
            ApproveOutcome::CallerChanged
        );
        assert_eq!(reader.await.unwrap().unwrap(), b"", "nothing written");
        let want = if ambiguous {
            "fifo_ambiguous"
        } else {
            "caller_changed"
        };
        let found = ev(&h, want);
        assert_eq!(found.len(), 1, "{want}: {:?}", h.audit_lines());
        assert_eq!(found[0]["outcome"], "at_release");
        assert!(ev(&h, "released").is_empty());
        assert_no_secret_in_audit(&h);
        handle.shutdown().await;
    }
}

#[tokio::test]
async fn cooldown_and_attempt_limits() {
    // Cool-down: the pipe is not re-armed for `cooldown_secs` after a request ends.
    let h = Harness::start(Opts::default()).await;
    let mut cfg = fifo_cfg(&h, "db", "db-password");
    cfg.cooldown_secs = 1;
    let path = cfg.path.clone();
    let _handle = start(&h, Script::new(vec![psql_reader(777)]), &[cfg]);
    let r1 = read_pipe(path.clone());
    let n = h.notifier.wait_for(1).await;
    h.core.deny(&n[0].request_id, Source::Admin);
    let denied_at = Instant::now();
    assert_eq!(r1.await.unwrap().unwrap(), b"");
    // A program retrying in a loop: the next open blocks until the pipe is armed again.
    let r2 = read_pipe(path.clone());
    let n2 = h.notifier.wait_for(2).await;
    let waited = denied_at.elapsed();
    assert!(
        waited >= Duration::from_millis(800),
        "cool-down not honoured: {waited:?}"
    );
    assert!(waited < Duration::from_secs(4));
    h.core.deny(&n2[1].request_id, Source::Admin);
    r2.await.unwrap().unwrap();

    // Per-pipe attempt limit.
    let h = Harness::start(Opts::default()).await;
    let mut cfg = fifo_cfg(&h, "db", "db-password");
    cfg.attempts_per_min = 2;
    let path = cfg.path.clone();
    let _handle = start(&h, Script::new(vec![psql_reader(777)]), &[cfg]);
    for i in 1..=2 {
        let r = read_pipe(path.clone());
        let n = h.notifier.wait_for(i).await;
        h.core.deny(&n[i - 1].request_id, Source::Admin);
        r.await.unwrap().unwrap();
    }
    assert_eq!(
        read_pipe(path.clone()).await.unwrap().unwrap(),
        b"",
        "third attempt refused"
    );
    assert_eq!(h.notifier.count(), 2);
    wait_audit(&h, "rate_limited", |l| {
        l["event"] == "rate_limited" && l["outcome"] == "fifo_attempt_rate"
    })
    .await;
}

#[tokio::test]
async fn global_pending_cap_applies_to_pipes() {
    let h = Harness::start(Opts {
        limits: "max_pending_total = 1".into(),
        ..Opts::default()
    })
    .await;
    let a = fifo_cfg(&h, "a", "db-password");
    let b = fifo_cfg(&h, "b", "second");
    let (pa, pb) = (a.path.clone(), b.path.clone());
    let _handle = start(&h, Script::new(vec![psql_reader(777)]), &[a, b]);
    let ra = read_pipe(pa);
    let n = h.notifier.wait_for(1).await;
    // The second pipe's reader is refused while the first request is pending.
    assert_eq!(read_pipe(pb).await.unwrap().unwrap(), b"");
    wait_audit(&h, "rate_limited", |l| {
        l["event"] == "rate_limited" && l["outcome"] == "pending_total"
    })
    .await;
    assert_eq!(h.notifier.count(), 1);
    h.core.deny(&n[0].request_id, Source::Admin);
    ra.await.unwrap().unwrap();
}

#[tokio::test]
async fn binary_and_large_secrets_are_written_raw_and_in_full() {
    let extra =
        format!("\n[[secret]]\nname = \"large\"\nallow_uids = [1000]\nallow_exes = [\"{PSQL}\"]\n");
    let h = Harness::start(Opts {
        extra,
        ..Opts::default()
    })
    .await;
    let big: Vec<u8> = (0..300_000u32).map(|i| b'a' + (i % 26) as u8).collect();
    put_secret(&h, "large", &big).await;
    let blob = fifo_cfg(&h, "blob", "blob");
    let large = fifo_cfg(&h, "large", "large");
    let (pb, pl) = (blob.path.clone(), large.path.clone());
    let _handle = start(&h, Script::new(vec![psql_reader(777)]), &[blob, large]);

    // Binary: decoded from base64 storage, no newline added.
    let r = read_pipe(pb);
    let n = h.notifier.wait_for(1).await;
    assert_eq!(
        h.core
            .approve(&n[0].request_id, pw(PASS), Source::Admin)
            .await,
        ApproveOutcome::Released
    );
    assert_eq!(
        r.await.unwrap().unwrap(),
        vec![0xde, 0xad, 0xbe, 0xef, 0x00]
    );

    // Larger than the pipe buffer: the write loop pushes all of it.
    let r = read_pipe(pl);
    let n = h.notifier.wait_for(2).await;
    assert_eq!(
        h.core
            .approve(&n[1].request_id, pw(PASS), Source::Admin)
            .await,
        ApproveOutcome::Released
    );
    let got = r.await.unwrap().unwrap();
    assert_eq!(got.len(), big.len());
    assert!(got == big);
    assert_eq!(ev(&h, "released").len(), 2);
    assert_no_secret_in_audit(&h);
}

#[tokio::test]
async fn stuck_reader_hits_the_write_deadline() {
    let extra =
        format!("\n[[secret]]\nname = \"large\"\nallow_uids = [1000]\nallow_exes = [\"{PSQL}\"]\n");
    let h = Harness::start(Opts {
        extra,
        ..Opts::default()
    })
    .await;
    let big = vec![b'x'; 300_000];
    put_secret(&h, "large", &big).await;
    let mut cfg = fifo_cfg(&h, "large", "large");
    cfg.write_deadline_secs = 1;
    let path = cfg.path.clone();
    let _handle = start(&h, Script::new(vec![psql_reader(777)]), &[cfg]);
    // A reader that opens the pipe and then never reads.
    let (hold_tx, hold_rx) = std::sync::mpsc::channel::<()>();
    let p2 = path.clone();
    let (opened_tx, opened_rx) = std::sync::mpsc::channel::<()>();
    let stuck = std::thread::spawn(move || {
        let f = std::fs::File::open(&p2).unwrap();
        opened_tx.send(()).unwrap();
        let _ = hold_rx.recv_timeout(Duration::from_secs(20));
        f
    });
    let n = h.notifier.wait_for(1).await;
    opened_rx.recv().unwrap();
    let t0 = Instant::now();
    assert_eq!(
        h.core
            .approve(&n[0].request_id, pw(PASS), Source::Admin)
            .await,
        ApproveOutcome::Aborted
    );
    let took = t0.elapsed();
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_secs(5),
        "{took:?}"
    );
    let aborted = ev(&h, "aborted");
    assert_eq!(aborted.len(), 1, "{:?}", h.audit_lines());
    assert_eq!(aborted[0]["outcome"], "write_timeout");
    let detail = aborted[0]["detail"].as_str().unwrap();
    assert!(
        detail.starts_with("wrote ") && detail.ends_with(" of 300000 bytes"),
        "{detail}"
    );
    assert!(
        ev(&h, "released").is_empty(),
        "never released on a partial write"
    );
    // The pipe was closed: the stuck reader drains what fitted, then sees EOF.
    hold_tx.send(()).unwrap();
    let f = stuck.join().unwrap();
    let got = tokio::task::spawn_blocking(move || {
        let mut v = Vec::new();
        let mut f = f;
        f.read_to_end(&mut v).unwrap();
        v
    })
    .await
    .unwrap();
    assert!(
        !got.is_empty() && got.len() < big.len(),
        "partial: {}",
        got.len()
    );
    assert_no_secret_in_audit(&h);
}

#[tokio::test]
async fn shutdown_cancels_the_wait_and_removes_the_pipes() {
    let h = Harness::start(Opts::default()).await;
    let a = fifo_cfg(&h, "a", "db-password");
    let b = fifo_cfg(&h, "b", "second");
    let (pa, pb) = (a.path.clone(), b.path.clone());
    let handle = start(&h, Script::new(vec![psql_reader(777)]), &[a, b]);
    assert!(pa.exists() && pb.exists());
    let t0 = Instant::now();
    handle.shutdown().await;
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "armed waits are cancellable"
    );
    assert!(!pa.exists() && !pb.exists());

    // With a request in flight the wait is cancelled too: the reader gets EOF.
    let cfg = fifo_cfg(&h, "c", "db-password");
    let pc = cfg.path.clone();
    let handle = start(&h, Script::new(vec![psql_reader(777)]), &[cfg]);
    let r = read_pipe(pc.clone());
    h.notifier.wait_for(1).await;
    let t0 = Instant::now();
    handle.shutdown().await;
    assert!(t0.elapsed() < Duration::from_secs(3));
    assert_eq!(r.await.unwrap().unwrap(), b"");
    assert_eq!(h.core.pending_count(), 0);
    assert!(!pc.exists());
}

#[tokio::test]
async fn two_pipes_may_share_one_secret() {
    let h = Harness::start(Opts::default()).await;
    let a = fifo_cfg(&h, "a", "db-password");
    let b = fifo_cfg(&h, "b", "db-password");
    let (pa, pb) = (a.path.clone(), b.path.clone());
    let _handle = start(&h, Script::new(vec![psql_reader(777)]), &[a, b]);
    let (ra, rb) = (read_pipe(pa), read_pipe(pb));
    let n = h.notifier.wait_for(2).await;
    for x in &n {
        assert_eq!(
            h.core.approve(&x.request_id, pw(PASS), Source::Admin).await,
            ApproveOutcome::Released
        );
    }
    assert_eq!(ra.await.unwrap().unwrap(), SECRET);
    assert_eq!(rb.await.unwrap().unwrap(), SECRET);
}

#[tokio::test]
async fn refused_openers_do_not_use_up_the_attempt_budget() {
    let h = Harness::start(Opts::default()).await;
    let mut cfg = fifo_cfg(&h, "db", "db-password");
    cfg.attempts_per_min = 1;
    cfg.enforce_acl = true;
    let path = cfg.path.clone();
    // Nobody can be identified: with enforce_acl every opener is refused.
    let scan = Script::new(vec![]);
    let _handle = start(&h, scan.clone(), &[cfg]);
    for _ in 0..3 {
        assert_eq!(read_pipe(path.clone()).await.unwrap().unwrap(), b"");
    }
    assert!(!ev(&h, "fifo_reader_unknown").is_empty());
    assert!(
        ev(&h, "rate_limited").is_empty(),
        "refused openers were counted: {:?}",
        h.audit_lines()
    );
    // The legitimate reader still gets through (budget of one per minute).
    scan.set_default(vec![psql_reader(777)]);
    let reader = read_pipe(path.clone());
    let n = h.notifier.wait_for(1).await;
    assert_eq!(
        h.core
            .approve(&n[0].request_id, pw(PASS), Source::Admin)
            .await,
        ApproveOutcome::Released
    );
    assert_eq!(reader.await.unwrap().unwrap(), SECRET);
}

#[tokio::test]
async fn release_time_check_notices_that_the_reader_has_left() {
    // The scanner keeps reporting the same reader, but by the time of the
    // release-time scan nobody holds the read end any more: the pipe's own
    // POLLERR state must make the release fail closed (nothing written).
    let h = Harness::start(Opts::default()).await;
    let cfg = fifo_cfg(&h, "db", "db-password");
    let path = cfg.path.clone();
    let scan = Script::new(vec![psql_reader(777)]);
    scan.slow_call(2, Duration::from_millis(800)); // the release-time scan
    let _handle = start(&h, scan.clone(), &[cfg]);
    let (quit_tx, quit_rx) = std::sync::mpsc::channel::<()>();
    let p2 = path.clone();
    let reader = tokio::task::spawn_blocking(move || {
        let f = std::fs::File::open(&p2).unwrap();
        let _ = quit_rx.recv_timeout(Duration::from_secs(20));
        drop(f);
    });
    let n = h.notifier.wait_for(1).await;
    let id = n[0].request_id.clone();
    let core = h.core.clone();
    let approve = tokio::spawn(async move { core.approve(&id, pw(PASS), Source::Admin).await });
    // Wait until the release-time scan has started, then let the reader go.
    for _ in 0..500 {
        if scan.calls.load(Ordering::SeqCst) >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    quit_tx.send(()).unwrap();
    reader.await.unwrap();
    assert_eq!(approve.await.unwrap(), ApproveOutcome::CallerChanged);
    let changed = ev(&h, "caller_changed");
    assert_eq!(changed.len(), 1, "{:?}", h.audit_lines());
    assert_eq!(changed[0]["outcome"], "at_release");
    assert!(ev(&h, "released").is_empty() && ev(&h, "aborted").is_empty());
    assert_no_secret_in_audit(&h);
}

#[tokio::test]
async fn a_reader_blocked_in_open_while_the_pipe_is_not_armed_is_released_at_shutdown() {
    // During the cool-down the pipe is not probed, so a reader that arrives
    // then sits in open(2). Removing the pipe must not strand it forever.
    let h = Harness::start(Opts::default()).await;
    let mut cfg = fifo_cfg(&h, "db", "db-password");
    cfg.cooldown_secs = 30;
    let path = cfg.path.clone();
    let handle = start(&h, Script::new(vec![psql_reader(777)]), &[cfg]);
    let first = read_pipe(path.clone());
    let n = h.notifier.wait_for(1).await;
    h.core.deny(&n[0].request_id, Source::Admin);
    assert_eq!(first.await.unwrap().unwrap(), b"");
    // Cool-down: this reader blocks in open().
    let second = read_pipe(path.clone());
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(!second.is_finished(), "should still be blocked in open");
    assert_eq!(h.notifier.count(), 1);
    handle.shutdown().await;
    let got = tokio::time::timeout(Duration::from_secs(3), second)
        .await
        .expect("the reader is stuck in open() after shutdown")
        .unwrap()
        .unwrap();
    assert_eq!(got, b"", "EOF, nothing written");
    assert!(!path.exists());
}

#[tokio::test]
async fn shutdown_removes_the_pipe_even_if_a_task_is_still_busy() {
    let extra =
        format!("\n[[secret]]\nname = \"large\"\nallow_uids = [1000]\nallow_exes = [\"{PSQL}\"]\n");
    let h = Harness::start(Opts {
        extra,
        ..Opts::default()
    })
    .await;
    put_secret(&h, "large", &vec![b'x'; 300_000]).await;
    let mut cfg = fifo_cfg(&h, "large", "large");
    cfg.write_deadline_secs = 30;
    let path = cfg.path.clone();
    let handle = start(&h, Script::new(vec![psql_reader(777)]), &[cfg]);
    // A reader that opens the pipe and never reads: the write stalls.
    let (hold_tx, hold_rx) = std::sync::mpsc::channel::<()>();
    let p2 = path.clone();
    let stuck = std::thread::spawn(move || {
        let f = std::fs::File::open(&p2).unwrap();
        let _ = hold_rx.recv_timeout(Duration::from_secs(20));
        f
    });
    let n = h.notifier.wait_for(1).await;
    let id = n[0].request_id.clone();
    let core = h.core.clone();
    let _approve = tokio::spawn(async move { core.approve(&id, pw(PASS), Source::Admin).await });
    tokio::time::sleep(Duration::from_millis(500)).await; // the write is stuck
    let t0 = Instant::now();
    handle.shutdown_within(Duration::from_millis(300)).await;
    assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    assert!(!path.exists(), "pipe left behind by a busy task");
    hold_tx.send(()).unwrap();
    let _ = stuck.join();
}

// ------------------------------------------------------------- the scanner

mod scanner {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};

    /// A fresh FIFO (no daemon involved) and its (dev, ino).
    fn new_pipe(d: &tempfile::TempDir) -> (PathBuf, u64, u64) {
        let p = d.path().join("probe");
        let c = CString::new(p.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let md = std::fs::metadata(&p).unwrap();
        (p, md.dev(), md.ino())
    }

    /// A process that holds `path` open with `flags` (no CLOEXEC) and sleeps.
    fn holder(path: &std::path::Path, flags: i32) -> Child {
        let c = CString::new(path.to_str().unwrap()).unwrap();
        let mut cmd = Command::new("sleep");
        cmd.arg("60").stdout(Stdio::null()).stderr(Stdio::null());
        // SAFETY: the closure only calls open(2) (async-signal-safe) on a
        // CString prepared before the fork.
        unsafe {
            cmd.pre_exec(move || {
                if libc::open(c.as_ptr(), flags) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd.spawn().expect("spawn holder")
    }

    fn scanner() -> ProcScanner {
        ProcScanner::new(Arc::new(RealProcReader))
    }

    struct Kill(Vec<Child>);
    impl Drop for Kill {
        fn drop(&mut self) {
            for c in &mut self.0 {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    #[test]
    fn a_reader_is_found_with_its_identity() {
        let d = tempfile::tempdir().unwrap();
        let (p, dev, ino) = new_pipe(&d);
        let child = holder(&p, libc::O_RDONLY | libc::O_NONBLOCK);
        let pid = child.id();
        let _k = Kill(vec![child]);
        let found = scanner().readers(dev, ino).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].pid, pid);
        assert_eq!(found[0].uid, euid());
        assert_eq!(found[0].proc.as_ref().unwrap().exe, exe_of(pid));
    }

    #[test]
    fn write_only_descriptors_are_not_readers() {
        let d = tempfile::tempdir().unwrap();
        let (p, dev, ino) = new_pipe(&d);
        // This process keeps a read end open so that a write-only open works
        // (the scanner never reports its own process).
        let mine = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&p)
            .unwrap();
        let writer = holder(&p, libc::O_WRONLY | libc::O_NONBLOCK);
        let wpid = writer.id();
        let mut k = Kill(vec![writer]);
        assert!(
            scanner().readers(dev, ino).unwrap().is_empty(),
            "a write-only descriptor made a reader"
        );
        // A read-write descriptor does count (positive control).
        let rw = holder(&p, libc::O_RDWR | libc::O_NONBLOCK);
        let rpid = rw.id();
        k.0.push(rw);
        let found = scanner().readers(dev, ino).unwrap();
        assert_eq!(found.iter().map(|r| r.pid).collect::<Vec<_>>(), vec![rpid]);
        assert_ne!(rpid, wpid);
        drop(mine);
    }

    #[test]
    fn the_scanners_own_process_is_never_a_reader() {
        let d = tempfile::tempdir().unwrap();
        let (p, dev, ino) = new_pipe(&d);
        let _mine = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&p)
            .unwrap();
        assert!(
            scanner().readers(dev, ino).unwrap().is_empty(),
            "the daemon's own descriptors must be ignored"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_o_path_descriptor_is_not_a_reader() {
        let d = tempfile::tempdir().unwrap();
        let (p, dev, ino) = new_pipe(&d);
        let path_only = holder(&p, libc::O_PATH);
        let _k = Kill(vec![path_only]);
        assert!(
            scanner().readers(dev, ino).unwrap().is_empty(),
            "an O_PATH descriptor made a reader"
        );
        // With a real reader next to it, the lone reader is still unambiguous.
        let reader = holder(&p, libc::O_RDONLY | libc::O_NONBLOCK);
        let rpid = reader.id();
        let _k2 = Kill(vec![reader]);
        let found = scanner().readers(dev, ino).unwrap();
        assert_eq!(found.iter().map(|r| r.pid).collect::<Vec<_>>(), vec![rpid]);
    }
}
