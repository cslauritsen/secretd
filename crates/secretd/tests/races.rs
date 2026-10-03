//! Races between an owner approval (which spends the whole unseal duration
//! on a blocking thread) and deny / timeout / client disconnect.
mod common;
use common::*;
use secret_proto::GetResult;
use secretd::core::{ApproveOutcome, DenyOutcome, Source};
use serde_json::json;
use std::time::Duration;

const UNSEAL: Duration = Duration::from_millis(500);

fn admin() -> Source {
    Source::Admin
}

async fn pause(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

#[tokio::test]
async fn deny_during_unseal_cannot_contradict_the_release() {
    let h = Harness::start(Opts::default()).await;
    h.core.set_unseal_delay(UNSEAL);
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = h.notifier.wait_for(1).await;
    let id = n[0].request_id.clone();

    let core = h.core.clone();
    let id2 = id.clone();
    let approve = tokio::spawn(async move { core.approve(&id2, pw(PASS), admin()).await });
    pause(150).await; // approve is now inside the unseal window
                      // The owner cannot deny what is already being released.
    assert_eq!(h.core.deny(&id, admin()), DenyOutcome::Busy);
    assert_eq!(approve.await.unwrap(), ApproveOutcome::Released);

    let g: GetResult = serde_json::from_value(c.recv().await.unwrap().result.unwrap()).unwrap();
    assert_eq!(g.value, "hunter2-secret-value");
    let ev = h.audit_events();
    assert!(ev.contains(&"released".to_string()));
    assert!(!ev.contains(&"denied".to_string()), "{ev:?}");
    assert_eq!(h.core.pending_count(), 0);
}

#[tokio::test]
async fn timeout_during_unseal_is_reported_as_aborted_not_released() {
    let h = Harness::start(Opts::default()).await;
    h.core.set_unseal_delay(Duration::from_millis(1500));
    let mut c = h.connect().await;
    c.send(
        "secret.get",
        json!({"name": "db-password", "timeout_secs": 1}),
    )
    .await;
    let n = h.notifier.wait_for(1).await;
    let out = h.core.approve(&n[0].request_id, pw(PASS), admin()).await;
    // The client's deadline passed while the store was being opened.
    assert_eq!(out, ApproveOutcome::Aborted);
    let r = c.recv().await.unwrap();
    assert_eq!(err_kind(&r), "TIMEOUT");
    assert!(r.result.is_none());
    let ev = h.audit_events();
    assert!(ev.contains(&"timeout".to_string()), "{ev:?}");
    assert!(ev.contains(&"aborted".to_string()), "{ev:?}");
    assert!(!ev.contains(&"released".to_string()), "{ev:?}");
    assert!(!h.audit_raw().contains("hunter2"));
}

#[tokio::test]
async fn disconnect_during_unseal_is_reported_as_aborted_not_released() {
    let h = Harness::start(Opts::default()).await;
    h.core.set_unseal_delay(UNSEAL);
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = h.notifier.wait_for(1).await;
    let core = h.core.clone();
    let id = n[0].request_id.clone();
    let approve = tokio::spawn(async move { core.approve(&id, pw(PASS), admin()).await });
    pause(100).await;
    drop(c); // client goes away mid-unseal
    assert_eq!(approve.await.unwrap(), ApproveOutcome::Aborted);
    let ev = h.audit_events();
    assert!(ev.contains(&"client_disconnected".to_string()), "{ev:?}");
    assert!(ev.contains(&"aborted".to_string()), "{ev:?}");
    assert!(!ev.contains(&"released".to_string()), "{ev:?}");
    assert_eq!(h.core.pending_count(), 0);
}

#[tokio::test]
async fn concurrent_double_approve_releases_exactly_once() {
    let h = Harness::start(Opts::default()).await;
    h.core.set_unseal_delay(UNSEAL);
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = h.notifier.wait_for(1).await;
    let id = n[0].request_id.clone();
    let (c1, c2) = (h.core.clone(), h.core.clone());
    let (i1, i2) = (id.clone(), id.clone());
    let a = tokio::spawn(async move { c1.approve(&i1, pw(PASS), admin()).await });
    pause(100).await;
    let b = tokio::spawn(async move { c2.approve(&i2, pw(PASS), admin()).await });
    let mut outs = vec![a.await.unwrap(), b.await.unwrap()];
    outs.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(outs, vec![ApproveOutcome::Busy, ApproveOutcome::Released]);
    let g: GetResult = serde_json::from_value(c.recv().await.unwrap().result.unwrap()).unwrap();
    assert_eq!(g.value, "hunter2-secret-value");
    let released = h.audit_events().iter().filter(|e| *e == "released").count();
    assert_eq!(released, 1);
}

#[tokio::test]
async fn wrong_passphrase_during_race_still_allows_retry() {
    let h = Harness::start(Opts::default()).await;
    h.core.set_unseal_delay(Duration::from_millis(200));
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = h.notifier.wait_for(1).await;
    let id = &n[0].request_id;
    assert_eq!(
        h.core.approve(id, pw("nope"), admin()).await,
        ApproveOutcome::WrongPassphrase { remaining: 2 }
    );
    assert_eq!(
        h.core.approve(id, pw(PASS), admin()).await,
        ApproveOutcome::Released
    );
    let g: GetResult = serde_json::from_value(c.recv().await.unwrap().result.unwrap()).unwrap();
    assert_eq!(g.value, "hunter2-secret-value");
}
