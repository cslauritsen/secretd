mod common;
use common::*;
use secret_proto::{GetResult, PendingInfo};
use secretd::peer::{PeerCred, StaticPeerCred};
use serde_json::json;
use std::sync::Arc;
use tokio::net::UnixListener;

async fn start_admin(h: &Harness, uid: u32) -> (std::path::PathBuf, Arc<StaticPeerCred>) {
    let path = h.dir.path().join("a.sock");
    let l = UnixListener::bind(&path).unwrap();
    let peer = Arc::new(StaticPeerCred::new(PeerCred {
        uid,
        gid: 0,
        pid: 1,
    }));
    tokio::spawn(secretd::server::serve_admin(
        h.core.clone(),
        l,
        peer.clone(),
    ));
    (path, peer)
}

#[tokio::test]
async fn admin_pending_approve_flow() {
    let h = Harness::start(Opts::default()).await;
    let (path, _) = start_admin(&h, 0).await;
    let mut client = h.connect().await;
    client
        .send(
            "secret.get",
            json!({"name": "db-password", "reason": "nightly"}),
        )
        .await;
    let n = h.notifier.wait_for(1).await;

    let mut admin = Conn::connect(&path).await;
    let r = admin.call("admin.pending", json!({})).await;
    let list: Vec<PendingInfo> =
        serde_json::from_value(r.result.unwrap()["pending"].clone()).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].request_id, n[0].request_id);
    assert_eq!(list[0].secret_name, "db-password");
    assert_eq!(list[0].uid, 1000);
    assert_eq!(list[0].exe, PSQL);
    assert_eq!(list[0].reason.as_deref(), Some("nightly"));
    // The pending listing never carries the approval token.
    assert!(!serde_json::to_string(&list)
        .unwrap()
        .contains(&n[0].approval_url[n[0].approval_url.find("?t=").unwrap() + 3..]));

    // Wrong passphrase: error with remaining attempts, request stays pending.
    let r = admin
        .call(
            "admin.approve",
            json!({"request_id": n[0].request_id, "passphrase": "wrong"}),
        )
        .await;
    let e = r.error.unwrap();
    assert_eq!(e.kind_str(), Some("DECRYPT_FAILED"));
    assert_eq!(e.data.unwrap().remaining_attempts, Some(2));
    assert_eq!(h.core.pending_count(), 1);

    let r = admin
        .call(
            "admin.approve",
            json!({"request_id": n[0].request_id, "passphrase": PASS}),
        )
        .await;
    assert!(r.error.is_none(), "{r:?}");
    let g: GetResult =
        serde_json::from_value(client.recv().await.unwrap().result.unwrap()).unwrap();
    assert_eq!(g.value, "hunter2-secret-value");

    // Resolved: unknown now.
    let r = admin
        .call(
            "admin.approve",
            json!({"request_id": n[0].request_id, "passphrase": PASS}),
        )
        .await;
    assert_eq!(r.error.unwrap().kind_str(), Some("NOT_FOUND"));
    let ev = h.audit_events();
    assert!(ev.contains(&"admin_action".to_string()));
    assert!(ev.contains(&"released".to_string()));
    assert!(!h.audit_raw().contains("wrong"));
}

#[tokio::test]
async fn admin_deny_and_three_wrong_passphrases() {
    let h = Harness::start(Opts::default()).await;
    let (path, _) = start_admin(&h, 0).await;
    let mut admin = Conn::connect(&path).await;

    let mut c1 = h.connect().await;
    c1.send("secret.get", json!({"name": "db-password"})).await;
    let n = h.notifier.wait_for(1).await;
    let r = admin
        .call("admin.deny", json!({"request_id": n[0].request_id}))
        .await;
    assert!(r.error.is_none());
    assert_eq!(err_kind(&c1.recv().await.unwrap()), "DENIED");

    let mut c2 = h.connect().await;
    c2.send("secret.get", json!({"name": "second"})).await;
    let n = h.notifier.wait_for(2).await;
    let id = n[1].request_id.clone();
    for left in [2u8, 1, 0] {
        let r = admin
            .call(
                "admin.approve",
                json!({"request_id": id, "passphrase": "bad"}),
            )
            .await;
        let e = r.error.unwrap();
        assert_eq!(e.kind_str(), Some("DECRYPT_FAILED"));
        assert_eq!(e.data.unwrap().remaining_attempts, Some(left));
    }
    assert_eq!(err_kind(&c2.recv().await.unwrap()), "DECRYPT_FAILED");
}

#[tokio::test]
async fn admin_socket_requires_uid_zero() {
    let h = Harness::start(Opts::default()).await;
    let (path, peer) = start_admin(&h, 1000).await;
    let mut admin = Conn::connect(&path).await;
    admin.send("admin.pending", json!({})).await;
    assert!(admin.recv().await.is_none(), "non-root peer is dropped");
    peer.set(PeerCred {
        uid: 0,
        gid: 0,
        pid: 1,
    });
    let mut admin = Conn::connect(&path).await;
    let r = admin.call("admin.pending", json!({})).await;
    assert!(r.error.is_none());
    let r = admin.call("admin.nope", json!({})).await;
    assert_eq!(r.error.unwrap().code, -32601);
    let r = admin.call("admin.deny", json!({"wrong": 1})).await;
    assert_eq!(r.error.unwrap().code, -32602);
}

struct Switch(Arc<std::sync::atomic::AtomicBool>);
impl std::io::Write for Switch {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.0.load(std::sync::atomic::Ordering::SeqCst) {
            Err(std::io::Error::other("disk full"))
        } else {
            Ok(b.len())
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn admin_actions_follow_audit_log_health() {
    let dead = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let h = Harness::start(Opts {
        audit_writer: Some(Box::new(Switch(dead.clone()))),
        ..Opts::default()
    })
    .await;
    let (path, _) = start_admin(&h, 0).await;
    let mut client = h.connect().await;
    client
        .send("secret.get", json!({"name": "db-password"}))
        .await;
    let n = h.notifier.wait_for(1).await;
    let id = n[0].request_id.clone();
    let mut admin = Conn::connect(&path).await;

    dead.store(true, std::sync::atomic::Ordering::SeqCst);
    // Approving and listing must not proceed without an audit trail.
    let r = admin
        .call(
            "admin.approve",
            json!({"request_id": id, "passphrase": PASS}),
        )
        .await;
    assert_eq!(err_kind(&r), "INTERNAL");
    assert_eq!(h.core.pending_count(), 1, "approve did not proceed");
    let r = admin.call("admin.pending", json!({})).await;
    assert_eq!(err_kind(&r), "INTERNAL");
    // Denying is the fail-safe direction: it happens, and says it was not logged.
    let r = admin.call("admin.deny", json!({"request_id": id})).await;
    let res = r.result.expect("deny proceeds");
    assert_eq!(res["ok"], true);
    assert!(res["warning"].as_str().unwrap().contains("audit"));
    assert_eq!(err_kind(&client.recv().await.unwrap()), "DENIED");
}
