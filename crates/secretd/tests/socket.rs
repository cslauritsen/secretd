mod common;
use common::*;
use secret_proto::{Encoding, GetResult, ListResult, PingResult};
use secretd::core::{ApproveOutcome, Source};
use secretd::peer::{PeerCred, RealPeerCred};
use serde_json::json;
use std::sync::Arc;

fn admin_src() -> Source {
    Source::Admin
}

#[tokio::test]
async fn ping_reports_sealed() {
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    let r = c.call("server.ping", json!({})).await;
    let p: PingResult = serde_json::from_value(r.result.unwrap()).unwrap();
    assert!(p.sealed);
    assert_eq!(p.version, env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn list_only_shows_acl_permitted_names() {
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    let r = c.call("secret.list", json!({})).await;
    let l: ListResult = serde_json::from_value(r.result.unwrap()).unwrap();
    assert!(l.names.contains(&"db-password".to_string()));
    assert!(l.names.contains(&"blob".to_string()));
    assert!(!l.names.contains(&"other-user-only".to_string()));
    assert!(!l.names.contains(&"wrong-exe".to_string()));
}

#[tokio::test]
async fn get_released_through_stub_approver() {
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    let id = c
        .send(
            "secret.get",
            json!({"name": "db-password", "reason": "backup"}),
        )
        .await;
    let n = h.notifier.wait_for(1).await;
    assert_eq!(n[0].secret_name, "db-password");
    assert_eq!(n[0].uid, 1000);
    assert_eq!(n[0].exe, PSQL);
    assert_eq!(n[0].reason.as_deref(), Some("backup"));
    assert!(n[0]
        .approval_url
        .starts_with("https://secretd.test/approve/"));
    // The notification never contains the secret.
    assert!(!format!("{:?}", n[0]).contains("hunter2"));

    let out = h
        .core
        .approve(&n[0].request_id, pw(PASS), admin_src())
        .await;
    assert_eq!(out, ApproveOutcome::Released);
    let r = c.recv().await.unwrap();
    assert_eq!(r.id, json!(id));
    let g: GetResult = serde_json::from_value(r.result.unwrap()).unwrap();
    assert_eq!(g.value, "hunter2-secret-value");
    assert_eq!(g.encoding, Encoding::Utf8);
    assert_eq!(g.name, "db-password");
    assert_eq!(h.core.pending_count(), 0);
}

#[tokio::test]
async fn binary_secret_is_base64() {
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "blob"})).await;
    let n = h.notifier.wait_for(1).await;
    h.core
        .approve(&n[0].request_id, pw(PASS), admin_src())
        .await;
    let g: GetResult = serde_json::from_value(c.recv().await.unwrap().result.unwrap()).unwrap();
    assert_eq!(g.encoding, Encoding::Base64);
    assert_eq!(
        secret_proto::b64::decode(&g.value).unwrap(),
        vec![0xde, 0xad, 0xbe, 0xef, 0x00]
    );
}

#[tokio::test]
async fn acl_miss_is_indistinguishable_from_unknown_name() {
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    let unknown = c.get("no-such-secret").await;
    let other_uid = c.get("other-user-only").await;
    let wrong_exe = c.get("wrong-exe").await;
    for r in [&unknown, &other_uid, &wrong_exe] {
        assert_eq!(err_kind(r), "NOT_FOUND");
    }
    let norm = |r: &secret_proto::Response| {
        let mut v = serde_json::to_value(r).unwrap();
        v["id"] = json!(0);
        v
    };
    assert_eq!(norm(&unknown), norm(&other_uid));
    assert_eq!(norm(&unknown), norm(&wrong_exe));
    // No notification was sent for ACL failures.
    assert_eq!(h.notifier.count(), 0);
}

#[tokio::test]
async fn unresolvable_proc_is_denied() {
    let h = Harness::start(Opts::default()).await;
    h.procs.remove(PID);
    let mut c = h.connect().await;
    assert_eq!(err_kind(&c.get("db-password").await), "NOT_FOUND");
    let r = c.call("secret.list", json!({})).await;
    let l: ListResult = serde_json::from_value(r.result.unwrap()).unwrap();
    assert!(l.names.is_empty());
}

#[tokio::test]
async fn deleted_exe_is_denied() {
    let h = Harness::start(Opts::default()).await;
    let mut p = psql_proc();
    p.exe = format!("{PSQL} (deleted)");
    h.procs.set(PID, p);
    let mut c = h.connect().await;
    assert_eq!(err_kind(&c.get("db-password").await), "NOT_FOUND");
}

#[tokio::test]
async fn uid_from_peer_provider_not_from_client() {
    let h = Harness::start(Opts::default()).await;
    h.peer.set(PeerCred {
        uid: 2000,
        gid: 2000,
        pid: PID,
    });
    let mut c = h.connect().await;
    // Client-supplied uid fields are ignored; uid 2000 only sees its own secret.
    let r = c.call("secret.list", json!({"uid": 1000})).await;
    let l: ListResult = serde_json::from_value(r.result.unwrap()).unwrap();
    assert_eq!(l.names, vec!["other-user-only".to_string()]);
}

#[tokio::test]
async fn protocol_errors() {
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    c.send_raw(b"this is not json\n").await;
    assert_eq!(c.recv().await.unwrap().error.unwrap().code, -32700);
    c.send_raw(b"[1,2,3]\n").await;
    assert_eq!(c.recv().await.unwrap().error.unwrap().code, -32600);
    let r = c.call("nope", json!({})).await;
    assert_eq!(r.error.unwrap().code, -32601);
    let r = c.call("secret.get", json!({"name": 5})).await;
    assert_eq!(r.error.unwrap().code, -32602);
    let r = c.call("secret.get", json!({"name": "bad name!"})).await;
    assert_eq!(r.error.unwrap().code, -32602);
    // connection still usable
    let r = c.call("server.ping", json!({})).await;
    assert!(r.result.is_some());
}

#[tokio::test]
async fn oversized_line_closes_connection() {
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    let mut big = vec![b'a'; 70 * 1024];
    big.push(b'\n');
    c.send_raw(&big).await;
    let r = c.recv().await.unwrap();
    assert_eq!(r.error.unwrap().code, -32600);
    assert!(c.recv().await.is_none());
}

#[tokio::test]
async fn waiting_request_does_not_block_other_connections() {
    let h = Harness::start(Opts::default()).await;
    let mut a = h.connect().await;
    a.send("secret.get", json!({"name": "db-password"})).await;
    h.notifier.wait_for(1).await;
    let mut b = h.connect().await;
    let r = b.call("server.ping", json!({})).await;
    assert!(r.result.is_some());
    // Finish the first request so the test ends cleanly.
    let n = h.notifier.wait_for(1).await;
    h.core.deny(&n[0].request_id, admin_src());
    assert_eq!(err_kind(&a.recv().await.unwrap()), "DENIED");
}

#[tokio::test]
async fn real_so_peercred_and_proc() {
    // Real SO_PEERCRED + real /proc: the test process is both client and ACL subject.
    let me = std::process::id();
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let exe = std::env::current_exe()
        .unwrap()
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let extra =
        format!("[[secret]]\nname = \"mine\"\nallow_uids = [{uid}]\nallow_exes = [\"{exe}\"]\n");
    let h = Harness::start(Opts {
        extra,
        peer: Some(Arc::new(RealPeerCred)),
        procs: Some(Arc::new(secretd::procinfo::RealProcReader)),
        ..Opts::default()
    })
    .await;
    // Put "mine" into the store.
    let mut s = secret_proto::store::load(&h.store, &pw(PASS)).unwrap();
    s.insert(
        "mine",
        secret_proto::store::Entry::from_bytes(b"real-value"),
    );
    secret_proto::store::save(&h.store, &pw(PASS), &s, WF).unwrap();

    let mut c = h.connect().await;
    let r = c.call("secret.list", json!({})).await;
    let l: ListResult = serde_json::from_value(r.result.unwrap()).unwrap();
    assert_eq!(l.names, vec!["mine".to_string()]);

    c.send("secret.get", json!({"name": "mine"})).await;
    let n = h.notifier.wait_for(1).await;
    assert_eq!(n[0].pid, me);
    assert_eq!(n[0].uid, uid);
    assert_eq!(n[0].exe, exe);
    let _ = gid;
    assert_eq!(
        h.core
            .approve(&n[0].request_id, pw(PASS), admin_src())
            .await,
        ApproveOutcome::Released
    );
    let g: GetResult = serde_json::from_value(c.recv().await.unwrap().result.unwrap()).unwrap();
    assert_eq!(g.value, "real-value");
}
