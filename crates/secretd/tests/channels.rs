//! Multi-channel rules (spec 19.1): first resolution wins, the other channels
//! are told the request is closed, a request fails only if every announcing
//! channel fails, and every approval event carries its channel.
mod common;
use async_trait::async_trait;
use common::*;
use secret_proto::config::ChannelKind;
use secret_proto::GetResult;
use secretd::channel::{AdminChannel, Channel, Closed};
use secretd::core::{ApproveOutcome, DenyOutcome, Source};
use secretd::notify::{Notification, NotifyError};
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A scripted channel that records what the core tells it.
struct Fake {
    kind: ChannelKind,
    fail: bool,
    seen: Mutex<Vec<Notification>>,
    closed: Mutex<Vec<(String, Closed)>>,
}

impl Fake {
    fn new(kind: ChannelKind, fail: bool) -> Arc<Fake> {
        Arc::new(Fake {
            kind,
            fail,
            seen: Mutex::new(Vec::new()),
            closed: Mutex::new(Vec::new()),
        })
    }
    async fn wait_seen(&self, n: usize) -> Vec<Notification> {
        for _ in 0..500 {
            {
                let s = self.seen.lock().unwrap();
                if s.len() >= n {
                    return s.clone();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {n} announcement(s)");
    }
    async fn wait_closed(&self) -> Vec<(String, Closed)> {
        for _ in 0..500 {
            {
                let c = self.closed.lock().unwrap();
                if !c.is_empty() {
                    return c.clone();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("channel was never told the request is closed");
    }
}

#[async_trait]
impl Channel for Fake {
    fn kind(&self) -> ChannelKind {
        self.kind
    }
    async fn announce(&self, n: &Notification) -> Result<(), NotifyError> {
        if self.fail {
            return Err(NotifyError("simulated".into()));
        }
        self.seen.lock().unwrap().push(n.clone());
        Ok(())
    }
    async fn closed(&self, id: &str, why: Closed) {
        self.closed.lock().unwrap().push((id.to_string(), why));
    }
}

fn opts(channels: Vec<Arc<dyn Channel>>) -> Opts {
    Opts {
        channels: Some(channels),
        ..Opts::default()
    }
}

#[tokio::test]
async fn request_fails_only_if_every_announcing_channel_fails() {
    let a = Fake::new(ChannelKind::Web, true);
    let b = Fake::new(ChannelKind::HomeAssistant, true);
    let h = Harness::start(opts(vec![a, b, Arc::new(AdminChannel)])).await;
    let mut c = h.connect().await;
    let r = c.get("db-password").await;
    assert_eq!(err_kind(&r), "INTERNAL");
    assert_eq!(h.core.pending_count(), 0);
    let lines = h.audit_lines();
    let failed: Vec<_> = lines
        .iter()
        .filter(|l| l["event"] == "notify_failed")
        .map(|l| l["channel"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(failed.len(), 2, "{lines:?}");
    assert!(failed.contains(&"web".to_string()) && failed.contains(&"homeassistant".to_string()));
    assert!(!h.audit_events().contains(&"notified".to_string()));
}

#[tokio::test]
async fn one_failing_channel_is_audited_but_not_fatal() {
    let bad = Fake::new(ChannelKind::Web, true);
    let good = Fake::new(ChannelKind::HomeAssistant, false);
    let h = Harness::start(opts(vec![bad, good.clone()])).await;
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = good.wait_seen(1).await;
    // Approvable through the surviving channel.
    let id = n[0].request_id.clone();
    assert_eq!(
        h.core.approve(&id, pw(PASS), Source::HomeAssistant).await,
        ApproveOutcome::Released
    );
    let g: GetResult = serde_json::from_value(c.recv().await.unwrap().result.unwrap()).unwrap();
    assert_eq!(g.value, "hunter2-secret-value");
    let lines = h.audit_lines();
    let has = |ev: &str, ch: &str| lines.iter().any(|l| l["event"] == ev && l["channel"] == ch);
    assert!(has("notify_failed", "web"), "{lines:?}");
    assert!(has("notified", "homeassistant"), "{lines:?}");
    assert!(has("approved", "homeassistant"), "{lines:?}");
    assert!(has("released", "homeassistant"), "{lines:?}");
}

#[tokio::test]
async fn first_resolution_wins_and_others_are_told_it_is_closed() {
    let web = Fake::new(ChannelKind::Web, false);
    let ha = Fake::new(ChannelKind::HomeAssistant, false);
    let h = Harness::start(opts(vec![web.clone(), ha.clone(), Arc::new(AdminChannel)])).await;
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = ha.wait_seen(1).await;
    web.wait_seen(1).await;
    let id = n[0].request_id.clone();
    // Both channels got the same request and the same token.
    assert_eq!(
        web.seen.lock().unwrap()[0].approval_token,
        n[0].approval_token
    );

    assert_eq!(
        h.core.approve(&id, pw(PASS), Source::HomeAssistant).await,
        ApproveOutcome::Released
    );
    // The loser: the other channel's actions on the same request find it gone.
    assert_eq!(
        h.core.approve(&id, pw(PASS), Source::Admin).await,
        ApproveOutcome::Gone
    );
    assert_eq!(h.core.deny(&id, Source::Admin), DenyOutcome::Gone);
    assert_eq!(
        h.core.check_token(&id, &n[0].approval_token),
        secretd::core::TokenCheck::Unknown
    );
    // Every channel, including the winner, is told once.
    for ch in [&web, &ha] {
        let closed = ch.wait_closed().await;
        assert_eq!(closed, vec![(id.clone(), Closed::Released)]);
    }
    let g: GetResult = serde_json::from_value(c.recv().await.unwrap().result.unwrap()).unwrap();
    assert_eq!(g.value, "hunter2-secret-value");
}

#[tokio::test]
async fn deny_and_timeout_close_every_channel() {
    let web = Fake::new(ChannelKind::Web, false);
    let ha = Fake::new(ChannelKind::HomeAssistant, false);
    let h = Harness::start(opts(vec![web.clone(), ha.clone()])).await;
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = ha.wait_seen(1).await;
    assert_eq!(
        h.core.deny(&n[0].request_id, Source::HomeAssistant),
        DenyOutcome::Denied
    );
    assert_eq!(err_kind(&c.recv().await.unwrap()), "DENIED");
    for ch in [&web, &ha] {
        assert_eq!(ch.wait_closed().await[0].1, Closed::Denied);
    }
    let lines = h.audit_lines();
    assert!(lines
        .iter()
        .any(|l| l["event"] == "denied" && l["channel"] == "homeassistant"));

    // Timeout.
    let web = Fake::new(ChannelKind::Web, false);
    let h = Harness::start(opts(vec![web.clone()])).await;
    let mut c = h.connect().await;
    c.send(
        "secret.get",
        json!({"name": "db-password", "timeout_secs": 1}),
    )
    .await;
    assert_eq!(err_kind(&c.recv().await.unwrap()), "TIMEOUT");
    assert_eq!(web.wait_closed().await[0].1, Closed::Timeout);

    // Client disconnect.
    let web = Fake::new(ChannelKind::Web, false);
    let h = Harness::start(opts(vec![web.clone()])).await;
    let c = h.connect().await;
    let mut c = c;
    c.send("secret.get", json!({"name": "db-password"})).await;
    web.wait_seen(1).await;
    drop(c);
    assert_eq!(web.wait_closed().await[0].1, Closed::Cancelled);
}

#[tokio::test]
async fn admin_only_needs_no_announcement() {
    let h = Harness::start(opts(vec![Arc::new(AdminChannel)])).await;
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let mut id = None;
    for _ in 0..200 {
        if let Some(p) = h.core.pending_list().first() {
            id = Some(p.request_id.clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let id = id.expect("request pending");
    assert_eq!(
        h.core.approve(&id, pw(PASS), Source::Admin).await,
        ApproveOutcome::Released
    );
    let g: GetResult = serde_json::from_value(c.recv().await.unwrap().result.unwrap()).unwrap();
    assert_eq!(g.value, "hunter2-secret-value");
    let ev = h.audit_events();
    assert!(!ev.contains(&"notified".to_string()), "{ev:?}");
    assert!(!ev.contains(&"notify_failed".to_string()), "{ev:?}");
    assert!(h
        .audit_lines()
        .iter()
        .any(|l| l["event"] == "released" && l["channel"] == "admin"));
}

#[tokio::test]
async fn default_core_still_has_web_and_admin_channel_fields_in_audit() {
    // Existing behaviour: the classic pair, ntfy-style notifier.
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = h.notifier.wait_for(1).await;
    assert_eq!(
        h.core
            .approve(&n[0].request_id, pw("wrong"), Source::Admin)
            .await,
        ApproveOutcome::WrongPassphrase { remaining: 2 }
    );
    assert_eq!(
        h.core
            .approve(&n[0].request_id, pw(PASS), Source::Admin)
            .await,
        ApproveOutcome::Released
    );
    let _ = c.recv().await;
    let lines = h.audit_lines();
    assert!(lines
        .iter()
        .any(|l| l["event"] == "notified" && l["channel"] == "web"));
    assert!(lines
        .iter()
        .any(|l| l["event"] == "decrypt_failed" && l["channel"] == "admin"));
    assert!(!h.audit_raw().contains("hunter2"));
}

/// A channel whose announcement takes `delay` (forever when `stuck`) and that
/// records the order of `announce finished` and `closed`.
struct Slow {
    kind: ChannelKind,
    delay: Duration,
    stuck: bool,
    events: Mutex<Vec<&'static str>>,
}

impl Slow {
    fn new(kind: ChannelKind, delay: Duration, stuck: bool) -> Arc<Slow> {
        Arc::new(Slow {
            kind,
            delay,
            stuck,
            events: Mutex::new(Vec::new()),
        })
    }
    fn events(&self) -> Vec<&'static str> {
        self.events.lock().unwrap().clone()
    }
}

#[async_trait]
impl Channel for Slow {
    fn kind(&self) -> ChannelKind {
        self.kind
    }
    async fn announce(&self, _n: &Notification) -> Result<(), NotifyError> {
        if self.stuck {
            std::future::pending::<()>().await;
        }
        tokio::time::sleep(self.delay).await;
        self.events.lock().unwrap().push("announced");
        Ok(())
    }
    async fn closed(&self, _id: &str, _why: Closed) {
        self.events.lock().unwrap().push("closed");
    }
}

async fn wait_for(what: &str, f: impl Fn() -> bool) {
    for _ in 0..500 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn a_slow_announcement_finishes_is_audited_and_then_told_the_request_closed() {
    let fast = Fake::new(ChannelKind::Web, false);
    let slow = Slow::new(
        ChannelKind::HomeAssistant,
        Duration::from_millis(400),
        false,
    );
    let h = Harness::start(opts(vec![fast.clone(), slow.clone()])).await;
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = fast.wait_seen(1).await;
    // The owner denies while the slow channel is still announcing.
    assert_eq!(
        h.core.deny(&n[0].request_id, Source::Admin),
        DenyOutcome::Denied
    );
    assert_eq!(err_kind(&c.recv().await.unwrap()), "DENIED");
    assert!(slow.events().is_empty(), "still announcing");
    // It is not abandoned: it completes, is audited, and only then closed
    // (so a channel can clean up what it just sent).
    wait_for("the slow channel to be closed", || {
        slow.events().contains(&"closed")
    })
    .await;
    assert_eq!(slow.events(), vec!["announced", "closed"]);
    let notified: Vec<_> = h
        .audit_lines()
        .into_iter()
        .filter(|l| l["event"] == "notified")
        .map(|l| l["channel"].as_str().unwrap().to_string())
        .collect();
    assert!(notified.contains(&"web".to_string()), "{notified:?}");
    assert!(
        notified.contains(&"homeassistant".to_string()),
        "the late announcement was not audited: {notified:?}"
    );
    assert_eq!(fast.wait_closed().await.len(), 1);
}

#[tokio::test]
async fn an_announcement_that_never_finishes_is_given_up_and_audited() {
    let fast = Fake::new(ChannelKind::Web, false);
    let stuck = Slow::new(ChannelKind::HomeAssistant, Duration::ZERO, true);
    let h = Harness::start(opts(vec![fast.clone(), stuck.clone()])).await;
    h.core.set_announce_grace(Duration::from_millis(200));
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = fast.wait_seen(1).await;
    h.core.deny(&n[0].request_id, Source::Admin);
    assert_eq!(err_kind(&c.recv().await.unwrap()), "DENIED");
    wait_for("the stuck channel to be closed", || {
        stuck.events().contains(&"closed")
    })
    .await;
    assert!(h.audit_lines().iter().any(|l| {
        l["event"] == "notify_failed"
            && l["channel"] == "homeassistant"
            && l["outcome"] == "timeout"
    }));
}

#[tokio::test]
async fn acl_changed_denial_names_channel_and_source() {
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    c.send("secret.get", json!({"name": "db-password"})).await;
    let n = h.notifier.wait_for(1).await;
    // The ACL is tightened (a reload) while the request is pending.
    let mut cfg = h.cfg.clone();
    cfg.secrets
        .iter_mut()
        .find(|s| s.name == "db-password")
        .unwrap()
        .uids = vec![2000];
    h.core.set_config(cfg);
    let ip: std::net::IpAddr = "10.1.2.3".parse().unwrap();
    assert_eq!(
        h.core
            .approve(&n[0].request_id, pw(PASS), Source::Http(ip))
            .await,
        ApproveOutcome::Gone
    );
    assert_eq!(err_kind(&c.recv().await.unwrap()), "NOT_FOUND");
    let lines = h.audit_lines();
    let ev = lines
        .iter()
        .find(|l| l["event"] == "acl_denied" && l["outcome"] == "acl_changed")
        .expect("acl_changed event");
    assert_eq!(ev["channel"], "web");
    assert_eq!(ev["source_ip"], "10.1.2.3");
    assert_eq!(ev["request_id"], n[0].request_id.as_str());
}
