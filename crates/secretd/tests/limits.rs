mod common;
use common::*;
use secret_proto::{GetResult, Response};
use secretd::core::{ApproveOutcome, Source};
use secretd::peer::PeerCred;
use serde_json::json;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn admin() -> Source {
    Source::Admin
}

async fn pause(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

#[tokio::test]
async fn per_uid_pending_cap() {
    let h = Harness::start(Opts {
        limits: "max_pending_per_uid = 2".into(),
        ..Opts::default()
    })
    .await;
    let mut a = h.connect().await;
    let mut b = h.connect().await;
    let mut c = h.connect().await;
    a.send("secret.get", json!({"name": "db-password"})).await;
    b.send("secret.get", json!({"name": "second"})).await;
    let n = h.notifier.wait_for(2).await;
    // Third pending request from the same uid is refused without a notification.
    let r = c.get("third").await;
    assert_eq!(err_kind(&r), "RATE_LIMITED");
    assert_eq!(h.notifier.count(), 2);
    assert!(h.audit_events().contains(&"rate_limited".to_string()));
    // Another uid has its own cap.
    h.peer.set(PeerCred {
        uid: 2000,
        gid: 2000,
        pid: PID,
    });
    let mut d = h.connect().await;
    d.send("secret.get", json!({"name": "other-user-only"}))
        .await;
    h.notifier.wait_for(3).await;
    // Resolving one frees a slot.
    h.core.deny(&n[0].request_id, admin());
    assert_eq!(err_kind(&a.recv().await.unwrap()), "DENIED");
    h.peer.set(PeerCred {
        uid: 1000,
        gid: 100,
        pid: PID,
    });
    let mut e = h.connect().await;
    e.send("secret.get", json!({"name": "third"})).await;
    h.notifier.wait_for(4).await;
    for x in h.notifier.seen.lock().unwrap().iter() {
        h.core.deny(&x.request_id, admin());
    }
    let _ = (b.recv().await, d.recv().await, e.recv().await);
}

#[tokio::test]
async fn duplicate_requests_are_suppressed() {
    let h = Harness::start(Opts::default()).await;
    let mut a = h.connect().await;
    a.send("secret.get", json!({"name": "db-password"})).await;
    let n = h.notifier.wait_for(1).await;
    // Same uid + exe + secret, even from another pid/connection.
    h.procs.set(5555, psql_proc());
    h.peer.set(PeerCred {
        uid: 1000,
        gid: 100,
        pid: 5555,
    });
    let mut b = h.connect().await;
    assert_eq!(err_kind(&b.get("db-password").await), "RATE_LIMITED");
    pause(100).await;
    assert_eq!(h.notifier.count(), 1, "no second notification");
    // A different secret from the same caller is not a duplicate.
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "second"})).await;
    h.notifier.wait_for(2).await;
    // After resolution the same request is accepted again.
    h.core.deny(&n[0].request_id, admin());
    assert_eq!(err_kind(&a.recv().await.unwrap()), "DENIED");
    let mut d = h.connect().await;
    d.send("secret.get", json!({"name": "db-password"})).await;
    h.notifier.wait_for(3).await;
    for x in h.notifier.seen.lock().unwrap().iter() {
        h.core.deny(&x.request_id, admin());
    }
    let _ = (c.recv().await, d.recv().await);
}

#[tokio::test]
async fn total_pending_cap() {
    let h = Harness::start(Opts {
        limits: "max_pending_total = 2\nmax_pending_per_uid = 5".into(),
        ..Opts::default()
    })
    .await;
    let mut a = h.connect().await;
    let mut b = h.connect().await;
    a.send("secret.get", json!({"name": "db-password"})).await;
    b.send("secret.get", json!({"name": "second"})).await;
    h.notifier.wait_for(2).await;
    h.peer.set(PeerCred {
        uid: 2000,
        gid: 2000,
        pid: PID,
    });
    let mut c = h.connect().await;
    assert_eq!(err_kind(&c.get("other-user-only").await), "RATE_LIMITED");
    for x in h.notifier.seen.lock().unwrap().iter() {
        h.core.deny(&x.request_id, admin());
    }
    let _ = (a.recv().await, b.recv().await);
}

#[tokio::test]
async fn per_uid_attempt_rate_limit_applies_to_all_names() {
    let h = Harness::start(Opts {
        limits: "max_gets_per_uid_per_min = 3".into(),
        ..Opts::default()
    })
    .await;
    let mut c = h.connect().await;
    for _ in 0..3 {
        assert_eq!(err_kind(&c.get("no-such").await), "NOT_FOUND");
    }
    // Over budget: every name, known or not, gets the same RATE_LIMITED, so the
    // limiter reveals nothing about ACLs.
    assert_eq!(err_kind(&c.get("no-such").await), "RATE_LIMITED");
    assert_eq!(err_kind(&c.get("db-password").await), "RATE_LIMITED");
    assert_eq!(err_kind(&c.get("other-user-only").await), "RATE_LIMITED");
    assert_eq!(h.notifier.count(), 0);
    // Other uids are unaffected.
    h.peer.set(PeerCred {
        uid: 2000,
        gid: 2000,
        pid: PID,
    });
    let mut d = h.connect().await;
    assert_eq!(err_kind(&d.get("no-such").await), "NOT_FOUND");
}

#[tokio::test(start_paused = true)]
async fn attempt_budget_replenishes_after_a_minute() {
    let h = Harness::start(Opts {
        limits: "max_gets_per_uid_per_min = 2".into(),
        ..Opts::default()
    })
    .await;
    let mut c = h.connect().await;
    assert_eq!(err_kind(&c.get("x").await), "NOT_FOUND");
    assert_eq!(err_kind(&c.get("x").await), "NOT_FOUND");
    assert_eq!(err_kind(&c.get("x").await), "RATE_LIMITED");
    tokio::time::advance(Duration::from_secs(61)).await;
    // (the idle timeout closed the old connection; the budget is per uid)
    let mut c = h.connect().await;
    assert_eq!(err_kind(&c.get("x").await), "NOT_FOUND");
}

#[tokio::test]
async fn connection_caps() {
    let h = Harness::start(Opts {
        limits: "max_conns_per_uid = 2".into(),
        ..Opts::default()
    })
    .await;
    let mut a = h.connect().await;
    let mut b = h.connect().await;
    assert!(a.call("server.ping", json!({})).await.result.is_some());
    assert!(b.call("server.ping", json!({})).await.result.is_some());
    let mut c = h.connect().await;
    let r: Response = c.recv().await.unwrap();
    assert_eq!(err_kind(&r), "RATE_LIMITED");
    assert!(c.recv().await.is_none(), "over-cap connection is closed");
    // Another uid may still connect.
    h.peer.set(PeerCred {
        uid: 2000,
        gid: 2000,
        pid: PID,
    });
    let mut d = h.connect().await;
    assert!(d.call("server.ping", json!({})).await.result.is_some());
    // Freeing a slot lets uid 1000 back in.
    drop(a);
    h.peer.set(PeerCred {
        uid: 1000,
        gid: 100,
        pid: PID,
    });
    let mut ok = false;
    for _ in 0..100 {
        let mut e = h.connect().await;
        if let Some(r) = e.recv_timeout(50).await {
            if r.error.is_none() {
                ok = true;
            }
        } else {
            let r = e.call("server.ping", json!({})).await;
            ok = r.result.is_some();
        }
        if ok {
            break;
        }
        pause(20).await;
    }
    assert!(ok);
}

#[tokio::test]
async fn total_connection_cap() {
    let h = Harness::start(Opts {
        limits: "max_conns_total = 2".into(),
        ..Opts::default()
    })
    .await;
    let mut a = h.connect().await;
    let mut b = h.connect().await;
    assert!(a.call("server.ping", json!({})).await.result.is_some());
    assert!(b.call("server.ping", json!({})).await.result.is_some());
    h.peer.set(PeerCred {
        uid: 2000,
        gid: 2000,
        pid: PID,
    });
    let mut c = h.connect().await;
    assert_eq!(err_kind(&c.recv().await.unwrap()), "RATE_LIMITED");
}

#[tokio::test]
async fn idle_connections_are_closed_but_waiting_requests_are_not() {
    let h = Harness::start(Opts {
        limits: "idle_timeout_secs = 1".into(),
        ..Opts::default()
    })
    .await;
    let mut idle = h.connect().await;
    let mut waiting = h.connect().await;
    waiting
        .send("secret.get", json!({"name": "db-password"}))
        .await;
    let n = h.notifier.wait_for(1).await;
    pause(1500).await;
    assert!(idle.recv().await.is_none(), "idle connection was closed");
    // The connection waiting for approval is not subject to the idle timeout.
    h.core.deny(&n[0].request_id, admin());
    assert_eq!(err_kind(&waiting.recv().await.unwrap()), "DENIED");
}

async fn changed_caller(mutate: impl FnOnce(&Harness)) {
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = h.notifier.wait_for(1).await;
    mutate(&h);
    let out = h.core.approve(&n[0].request_id, pw(PASS), admin()).await;
    assert_eq!(out, ApproveOutcome::CallerChanged);
    let r = c.recv().await.unwrap();
    assert_eq!(err_kind(&r), "CALLER_CHANGED");
    assert!(r.result.is_none());
    let ev = h.audit_events();
    assert!(ev.contains(&"caller_changed".to_string()));
    assert!(!ev.contains(&"released".to_string()));
    assert!(!h.audit_raw().contains("hunter2"));
    assert_eq!(h.core.pending_count(), 0);
}

#[tokio::test]
async fn caller_exec_after_connect_is_detected() {
    changed_caller(|h| {
        let mut p = psql_proc();
        p.exe = "/opt/test/bin/evil".into();
        h.procs.set(PID, p);
    })
    .await;
}

#[tokio::test]
async fn caller_pid_reuse_is_detected() {
    changed_caller(|h| {
        let mut p = psql_proc();
        p.start_time += 1; // same exe, different process
        h.procs.set(PID, p);
    })
    .await;
}

#[tokio::test]
async fn caller_exit_is_detected() {
    changed_caller(|h| h.procs.remove(PID)).await;
}

#[tokio::test]
async fn acl_change_via_reload_applies_to_pending_requests() {
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = h.notifier.wait_for(1).await;
    // SIGHUP-style reload that removes uid 1000 from db-password.
    let text = h
        .config_text
        .replacen("allow_uids = [1000]", "allow_uids = [4000]", 1);
    struct R;
    impl secret_proto::config::NameResolver for R {
        fn uid(&self, _: &str) -> Option<u32> {
            None
        }
        fn gid(&self, _: &str) -> Option<u32> {
            None
        }
    }
    h.core
        .set_config(secret_proto::config::Config::parse(&text, &R).unwrap());
    let out = h.core.approve(&n[0].request_id, pw(PASS), admin()).await;
    assert_eq!(out, ApproveOutcome::Gone);
    assert_eq!(err_kind(&c.recv().await.unwrap()), "NOT_FOUND");
    // New requests see the new ACL.
    assert_eq!(err_kind(&c.get("db-password").await), "NOT_FOUND");
}

#[tokio::test]
async fn audit_log_format_and_event_sequence() {
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    // ACL miss: request_received + acl_denied, nothing else.
    c.get("other-user-only").await;
    // Approved request.
    c.send(
        "secret.get",
        json!({"name": "db-password", "reason": "SECRET-REASON-TEXT"}),
    )
    .await;
    let n = h.notifier.wait_for(1).await;
    h.core
        .approve(&n[0].request_id, pw("bad-pass-xyz"), admin())
        .await;
    h.core.approve(&n[0].request_id, pw(PASS), admin()).await;
    let g: GetResult = serde_json::from_value(c.recv().await.unwrap().result.unwrap()).unwrap();
    assert_eq!(g.value, "hunter2-secret-value");
    // Timeout.
    c.send("secret.get", json!({"name": "second", "timeout_secs": 1}))
        .await;
    assert_eq!(err_kind(&c.recv().await.unwrap()), "TIMEOUT");

    let ev = h.audit_events();
    assert_eq!(
        ev,
        vec![
            "request_received",
            "acl_denied",
            "request_received",
            "notified",
            "approve_attempt",
            "decrypt_failed",
            "approve_attempt",
            "approved",
            "released",
            "request_received",
            "notified",
            "timeout",
        ]
    );
    let lines = h.audit_lines();
    for l in &lines {
        let ts = l["ts"].as_str().unwrap();
        assert!(ts.ends_with('Z') && ts.contains('T'), "RFC 3339 UTC: {ts}");
        assert_eq!(l["uid"], 1000);
        assert_eq!(l["gid"], 100);
        assert_eq!(l["pid"], PID);
        assert_eq!(l["exe"], PSQL);
    }
    assert_eq!(lines[1]["outcome"], "acl");
    assert_eq!(lines[1]["secret_name"], "other-user-only");
    assert!(
        lines[2]["request_id"].is_null(),
        "request_received precedes id assignment"
    );
    assert_eq!(lines[3]["request_id"].as_str().unwrap().len(), 32);
    assert_eq!(lines[5]["outcome"], "retry");
    // Never values, passphrases, tokens or client reasons.
    let raw = h.audit_raw();
    for bad in ["hunter2", "bad-pass-xyz", PASS, "SECRET-REASON-TEXT"] {
        assert!(!raw.contains(bad), "audit leaked {bad}");
    }
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&h.audit_path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o640);
}

struct FailAfter {
    n: Arc<AtomicUsize>,
    ok_writes: usize,
}

impl Write for FailAfter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.n.fetch_add(1, Ordering::SeqCst) >= self.ok_writes {
            return Err(std::io::Error::other("disk full"));
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn audit_failure_fails_closed_at_request_time() {
    let h = Harness::start(Opts {
        audit_writer: Some(Box::new(FailAfter {
            n: Arc::new(AtomicUsize::new(0)),
            ok_writes: 0,
        })),
        ..Opts::default()
    })
    .await;
    let mut c = h.connect().await;
    assert_eq!(err_kind(&c.get("db-password").await), "INTERNAL");
    assert_eq!(h.notifier.count(), 0);
    assert_eq!(h.core.pending_count(), 0);
}

#[tokio::test]
async fn audit_failure_before_release_withholds_the_secret() {
    // Writes: request_received, notified, approve_attempt, approved succeed;
    // `released` fails.
    let h = Harness::start(Opts {
        audit_writer: Some(Box::new(FailAfter {
            n: Arc::new(AtomicUsize::new(0)),
            ok_writes: 4,
        })),
        ..Opts::default()
    })
    .await;
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = h.notifier.wait_for(1).await;
    let out = h.core.approve(&n[0].request_id, pw(PASS), admin()).await;
    assert_eq!(out, ApproveOutcome::Internal);
    let r = c.recv().await.unwrap();
    assert_eq!(err_kind(&r), "INTERNAL");
    assert!(!serde_json::to_string(&r).unwrap().contains("hunter2"));
}

#[tokio::test]
async fn audit_failure_on_approval_aborts_request() {
    let h = Harness::start(Opts {
        audit_writer: Some(Box::new(FailAfter {
            n: Arc::new(AtomicUsize::new(0)),
            ok_writes: 2,
        })),
        ..Opts::default()
    })
    .await;
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = h.notifier.wait_for(1).await;
    let out = h.core.approve(&n[0].request_id, pw(PASS), admin()).await;
    assert_eq!(out, ApproveOutcome::Internal);
    assert_eq!(err_kind(&c.recv().await.unwrap()), "INTERNAL");
}

#[tokio::test]
async fn audit_failure_on_wrong_passphrase_grants_no_further_guesses() {
    // Writes: request_received, notified, approve_attempt succeed;
    // `decrypt_failed` fails, so the retry we could not record is refused.
    let h = Harness::start(Opts {
        audit_writer: Some(Box::new(FailAfter {
            n: Arc::new(AtomicUsize::new(0)),
            ok_writes: 3,
        })),
        ..Opts::default()
    })
    .await;
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = h.notifier.wait_for(1).await;
    let out = h.core.approve(&n[0].request_id, pw("wrong"), admin()).await;
    assert_eq!(out, ApproveOutcome::Internal);
    assert_eq!(err_kind(&c.recv().await.unwrap()), "INTERNAL");
    assert_eq!(h.core.pending_count(), 0);
}
