//! The Home Assistant channel against a mock HA WebSocket server (spec 19.6).
mod common;
use common::ha::*;
use common::web::*;
use common::*;
use secret_proto::config::HaCfg;
use secret_proto::GetResult;
use secretd::channel::{AdminChannel, Channel};
use secretd::homeassistant::HaChannel;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

fn ha_cfg(url: &str) -> HaCfg {
    HaCfg {
        url: url.into(),
        ws_url: format!("{}/api/websocket", url.replacen("http", "ws", 1)),
        token_file: "/unused".into(),
        notify_service: "notify.mobile_app_owner_phone".into(),
        passphrase_entity: ENTITY.into(),
        owner_user_ids: vec![OWNER.into()],
        allow_insecure_http: false,
        ca_file: None,
        require_user_id: true,
        backoff_min_ms: 50,
        backoff_max_ms: 400,
    }
}

struct Env {
    h: Harness,
    ha: MockHa,
    chan: Arc<HaChannel>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Env {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_env() -> Env {
    start_env_with(|_| {}, HA_TOKEN, 30).await
}

async fn start_env_with(edit: impl FnOnce(&mut HaCfg), token: &str, timeout_secs: u64) -> Env {
    let ha = MockHa::start().await;
    let mut cfg = ha_cfg(&ha.url());
    edit(&mut cfg);
    let chan = HaChannel::new(&cfg, pw(token)).unwrap();
    let channels: Vec<Arc<dyn Channel>> = vec![chan.clone(), Arc::new(AdminChannel)];
    let h = Harness::start(Opts {
        channels: Some(channels),
        timeout_secs,
        ..Opts::default()
    })
    .await;
    let task = tokio::spawn(chan.clone().run(h.core.clone()));
    Env { h, ha, chan, task }
}

impl Env {
    async fn ready(self) -> Env {
        self.ha.wait_connected().await;
        // The connect-time stale check has run.
        self.ha
            .wait_until("stale check", |m| m.get_states_count() >= 1)
            .await;
        self
    }

    /// Start a `secret.get`; returns the connection, the request id and the
    /// (approve, deny) action ids once the announcement arrived.
    async fn request(&self, name: &str, nth: usize) -> (Conn, String, (String, String)) {
        let mut c = self.h.connect().await;
        c.send("secret.get", json!({"name": name, "reason": "tests"}))
            .await;
        let n = self.ha.wait_notification(nth).await;
        (c, request_id_of(&n), actions_of(&n))
    }
}

async fn value_of(c: &mut Conn) -> String {
    let r = c.recv().await.expect("response");
    assert!(r.error.is_none(), "{r:?}");
    let g: GetResult = serde_json::from_value(r.result.unwrap()).unwrap();
    g.value
}

/// `needles` appear in `timeline` in this order (prefix match), after `from`.
fn in_order(timeline: &[String], needles: &[&str]) -> bool {
    let mut i = 0;
    for t in timeline {
        if i < needles.len() && t.starts_with(needles[i]) {
            i += 1;
        }
    }
    i == needles.len()
}

/// The token part of `SECRETD_APPROVE_<32 hex id>_<token>`.
fn token_of_action(a: &str) -> &str {
    &a["SECRETD_APPROVE_".len() + 33..]
}

fn audit_has(h: &Harness, event: &str, key: &str, val: &str) -> bool {
    h.audit_lines()
        .iter()
        .any(|l| l["event"] == event && l[key] == val)
}

#[tokio::test]
async fn auth_subscription_and_audit() {
    let env = start_env().await.ready().await;
    assert!(env.chan.is_connected());
    assert!(audit_has(
        &env.h,
        "ha_connected",
        "channel",
        "homeassistant"
    ));
    // Nothing but the stale check has happened yet.
    assert_eq!(env.ha.notifications().len(), 0);
}

#[tokio::test]
async fn wrong_token_means_unavailable_and_requests_fail() {
    let env = start_env_with(|_| {}, "not-the-token", 30).await;
    env.ha
        .wait_until("an auth failure", |m| m.auth_failures() >= 1)
        .await;
    assert!(!env.chan.is_connected());
    // HA is the only announcing channel: the request fails INTERNAL, audited.
    let mut c = env.h.connect().await;
    let r = c.get("db-password").await;
    assert_eq!(err_kind(&r), "INTERNAL");
    assert!(audit_has(
        &env.h,
        "notify_failed",
        "channel",
        "homeassistant"
    ));
    assert!(!env.h.audit_events().contains(&"ha_connected".to_string()));
    // The access token never reaches the audit log.
    assert!(!env.h.audit_raw().contains("not-the-token"));
    assert!(!env.h.audit_raw().contains(HA_TOKEN));
}

#[tokio::test]
async fn reconnects_with_exponential_backoff_and_resets() {
    let ha = MockHa::start().await;
    ha.reject_next(4);
    let mut cfg = ha_cfg(&ha.url());
    cfg.backoff_min_ms = 40;
    cfg.backoff_max_ms = 100;
    let chan = HaChannel::new(&cfg, pw(HA_TOKEN)).unwrap();
    let h = Harness::start(Opts {
        channels: Some(vec![chan.clone(), Arc::new(AdminChannel)]),
        ..Opts::default()
    })
    .await;
    // Every connect line is wanted here (the coalescer has its own test).
    h.core.set_coalesce_window(Duration::ZERO);
    let task = tokio::spawn(chan.clone().run(h.core.clone()));
    ha.wait_connected().await;
    let t = ha.connections();
    assert_eq!(t.len(), 5, "four rejected attempts, then one that works");
    let gaps: Vec<u128> = t.windows(2).map(|w| (w[1] - w[0]).as_millis()).collect();
    // 40, 80, then capped at 100 (scheduling can only make gaps longer).
    assert!(
        gaps[0] >= 35 && gaps[1] >= 70 && gaps[2] >= 90 && gaps[3] >= 90,
        "{gaps:?}"
    );
    assert!(gaps[1] > gaps[0] && gaps[3] < 800, "{gaps:?}");
    // While down, an announcement is a failure; after a drop it reconnects.
    ha.drop_connection();
    ha.wait_until("disconnect", |_| !chan.is_connected()).await;
    for _ in 0..300 {
        if chan.is_connected() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(chan.is_connected(), "reconnected after a drop");
    assert!(audit_has(&h, "ha_disconnected", "channel", "homeassistant"));
    assert_eq!(
        h.audit_events()
            .iter()
            .filter(|e| *e == "ha_connected")
            .count(),
        2
    );
    task.abort();
}

#[tokio::test]
async fn announcement_has_tag_actions_and_no_token_or_passphrase_in_text() {
    let env = start_env().await.ready().await;
    let (_c, id, (approve, deny)) = env.request("db-password", 0).await;
    let call = env.ha.notifications()[0].clone();
    assert_eq!(call["domain"], "notify");
    assert_eq!(call["service"], "mobile_app_owner_phone");
    assert_eq!(call["service_data"]["data"]["tag"], id.as_str());
    assert_eq!(call["service_data"]["title"], "Secret request: db-password");
    let token = approve
        .strip_prefix(&format!("SECRETD_APPROVE_{id}_"))
        .expect("approve action carries id and token");
    assert_eq!(deny, format!("SECRETD_DENY_{id}_{token}"));
    assert_eq!(token.len(), 43, "256-bit token, base64url");
    let text = call["service_data"]["message"].as_str().unwrap();
    for want in [
        "Secret: db-password (Primary DB password)",
        "uid 1000",
        "Executable: /opt/test/bin/psql",
        "Command line: psql -h db",
        "Reason (client-supplied, untrusted): tests",
        &id,
        ENTITY,
    ] {
        assert!(text.contains(want), "{want} missing from {text}");
    }
    assert!(!text.contains(token), "token must not be in the text");
    assert!(!text.contains("http"), "no approval link on this channel");
    // The same token the web link would carry (one per request).
    assert!(audit_has(&env.h, "notified", "channel", "homeassistant"));
    assert!(!env.h.audit_raw().contains(token));
}

#[tokio::test]
async fn approve_reads_then_clears_entity_and_releases() {
    let env = start_env().await.ready().await;
    let (mut c, id, (approve, _)) = env.request("db-password", 0).await;
    // Never read before an Approve: only the connect-time check so far.
    assert_eq!(env.ha.get_states_count(), 1);
    env.ha.set_state(ENTITY, PASS);
    env.ha.inject_action(&approve, Some(OWNER));
    assert_eq!(value_of(&mut c).await, "hunter2-secret-value");
    env.ha
        .wait_until("notification cleared", |m| {
            m.count("clear_notification:") >= 1
        })
        .await;
    let tl = env.ha.timeline();
    assert!(
        in_order(
            &tl,
            &["notify:", "get_states", "set_value:", "clear_notification:"]
        ),
        "{tl:?}"
    );
    assert_eq!(env.ha.state(ENTITY), "", "entity cleared");
    assert!(tl.iter().any(|t| t == &format!("clear_notification:{id}")));
    // Audit: channel on every approval event, nothing sensitive.
    for ev in ["approve_attempt", "approved", "released"] {
        assert!(audit_has(&env.h, ev, "channel", "homeassistant"), "{ev}");
    }
    let raw = env.h.audit_raw();
    for bad in [PASS, "hunter2", HA_TOKEN, approve.as_str()] {
        assert!(!raw.contains(bad), "audit leaks {bad}");
    }
    assert!(!raw.contains(token_of_action(&approve)), "token in audit");
}

#[tokio::test]
async fn approve_with_empty_entity_reprompts_and_costs_no_attempt() {
    let env = start_env().await.ready().await;
    let (mut c, id, (approve, _)) = env.request("db-password", 0).await;
    env.ha.inject_action(&approve, Some(OWNER));
    let n = env.ha.wait_notification(1).await;
    assert_eq!(n["service_data"]["data"]["tag"], id.as_str(), "same tag");
    assert!(n["service_data"]["message"]
        .as_str()
        .unwrap()
        .contains("first, then tap Approve"));
    // Still approvable (actions present again) and no attempt consumed.
    assert_eq!(actions_of(&n).0, approve);
    let (_, _, remaining) = env.h.core.pending_info(&id).unwrap();
    assert_eq!(remaining, 3);
    // Empty entity: nothing was cleared and no unseal was attempted.
    assert_eq!(env.ha.count("set_value:"), 0);
    assert!(!env
        .h
        .audit_events()
        .contains(&"approve_attempt".to_string()));
    // Now fill it in and approve.
    env.ha.set_state(ENTITY, PASS);
    env.ha.inject_action(&approve, Some(OWNER));
    assert_eq!(value_of(&mut c).await, "hunter2-secret-value");
}

#[tokio::test]
async fn deny_clears_notification_and_entity() {
    let env = start_env().await.ready().await;
    let (mut c, id, (_, deny)) = env.request("db-password", 0).await;
    // The owner had typed the passphrase but then denies: it must not linger.
    env.ha.set_state(ENTITY, "typed-but-denied");
    env.ha.inject_action(&deny, Some(OWNER));
    assert_eq!(err_kind(&c.recv().await.unwrap()), "DENIED");
    env.ha
        .wait_until("cleanup", |m| {
            m.count("clear_notification:") == 1 && m.state(ENTITY).is_empty()
        })
        .await;
    assert!(env
        .ha
        .timeline()
        .contains(&format!("clear_notification:{id}")));
    assert!(audit_has(&env.h, "denied", "channel", "homeassistant"));
    // Deny never reads the entity.
    assert_eq!(env.ha.get_states_count(), 1);
}

#[tokio::test]
async fn wrong_passphrase_then_right_one() {
    let env = start_env().await.ready().await;
    let (mut c, id, (approve, _)) = env.request("db-password", 0).await;
    env.ha.set_state(ENTITY, "wrong guess");
    env.ha.inject_action(&approve, Some(OWNER));
    let n = env.ha.wait_notification(1).await;
    assert_eq!(n["service_data"]["data"]["tag"], id.as_str());
    let msg = n["service_data"]["message"].as_str().unwrap();
    assert!(msg.contains("2 of 3 attempts left"), "{msg}");
    assert_eq!(actions_of(&n).0, approve, "Approve is offered again");
    assert_eq!(
        env.ha.state(ENTITY),
        "",
        "cleared even though the guess was wrong"
    );
    assert!(!msg.contains("wrong guess"));
    assert!(audit_has(
        &env.h,
        "decrypt_failed",
        "channel",
        "homeassistant"
    ));
    // Second try.
    env.ha.set_state(ENTITY, PASS);
    env.ha.inject_action(&approve, Some(OWNER));
    assert_eq!(value_of(&mut c).await, "hunter2-secret-value");
    assert_eq!(env.ha.state(ENTITY), "");
    // Two reads, two clears.
    assert_eq!(env.ha.count("set_value:"), 2);
    assert!(!env.h.audit_raw().contains("wrong guess"));
}

/// Wait until no approval is being processed on the channel.
async fn wait_idle(chan: &HaChannel) {
    for _ in 0..600 {
        if !chan.is_approving() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the approval gate never opened");
}

#[tokio::test]
async fn three_wrong_passphrases_deny_and_clear() {
    let env = start_env().await.ready().await;
    let (mut c, id, (approve, _)) = env.request("db-password", 0).await;
    for i in 0..3usize {
        env.ha.set_state(ENTITY, "nope");
        env.ha.inject_action(&approve, Some(OWNER));
        if i < 2 {
            // The attempt is over once the "wrong passphrase" follow-up is out
            // (it is the (i+1)th notification after the announcement) and the
            // approval gate is open again. Tapping Approve earlier would be
            // answered "busy" (which the channel does by design), so this
            // waits for the state, not for a log line that is written first:
            // polling the audit log for `decrypt_failed` raced with the
            // approval handler still sending its follow-up.
            let n = env.ha.wait_notification(i + 1).await;
            assert!(n["service_data"]["title"]
                .as_str()
                .unwrap()
                .contains("Wrong passphrase"));
            wait_idle(&env.chan).await;
        }
    }
    assert_eq!(err_kind(&c.recv().await.unwrap()), "DECRYPT_FAILED");
    env.ha
        .wait_until("clear", |m| m.count("clear_notification:") >= 1)
        .await;
    assert!(env
        .ha
        .timeline()
        .contains(&format!("clear_notification:{id}")));
    assert_eq!(env.ha.count("set_value:"), 3, "one clear per read");
    // The owner is told the request is over (a separate, action-less message).
    env.ha
        .wait_until("outcome notification", |m| {
            m.count(&format!("notify:secretd-result-{id}:")) == 1
        })
        .await;
}

#[tokio::test]
async fn a_follow_up_in_flight_does_not_block_the_next_approval() {
    // Regression for the flaky `three_wrong_passphrases_deny_and_clear`: the
    // approval gate used to stay closed while the "wrong passphrase"
    // follow-up was being sent, so an Approve tapped just after the attempt
    // was answered "busy" (and never read the entity).
    let env = start_env().await.ready().await;
    let (mut c, _id, (approve, _)) = env.request("db-password", 0).await;
    env.ha.hold_notify_replies(true);
    env.ha.set_state(ENTITY, "wrong guess");
    env.ha.inject_action(&approve, Some(OWNER));
    env.ha
        .wait_until("the follow-up to be sent", |m| {
            m.timeline().iter().any(|t| t.contains("Wrong passphrase"))
        })
        .await;
    // HA has not answered the follow-up yet, but the attempt is over.
    assert!(!env.chan.is_approving(), "gate held while notifying");
    let reads = env.ha.get_states_count();
    env.ha.set_state(ENTITY, PASS);
    env.ha.inject_action(&approve, Some(OWNER));
    assert_eq!(value_of(&mut c).await, "hunter2-secret-value");
    assert_eq!(env.ha.get_states_count(), reads + 1, "read, not busy");
    env.ha.release_replies();
}

#[tokio::test]
async fn timeout_clears_notification_and_entity() {
    let env = start_env_with(|_| {}, HA_TOKEN, 1).await.ready().await;
    let (mut c, id, _) = env.request("db-password", 0).await;
    env.ha.set_state(ENTITY, "typed-then-ignored");
    assert_eq!(err_kind(&c.recv().await.unwrap()), "TIMEOUT");
    env.ha
        .wait_until("cleanup", |m| {
            m.count("clear_notification:") == 1 && m.state(ENTITY).is_empty()
        })
        .await;
    assert!(env
        .ha
        .timeline()
        .contains(&format!("clear_notification:{id}")));
}

#[tokio::test]
async fn entity_is_cleared_after_every_read_even_when_the_store_is_broken() {
    let env = start_env().await.ready().await;
    let (mut c, _id, (approve, _)) = env.request("db-password", 0).await;
    std::fs::remove_file(&env.h.store).unwrap();
    env.ha.set_state(ENTITY, PASS);
    env.ha.inject_action(&approve, Some(OWNER));
    let r = c.recv().await.unwrap();
    assert!(r.error.is_some(), "{r:?}");
    assert_eq!(env.ha.state(ENTITY), "");
    assert_eq!(env.ha.count("set_value:"), 1);
    assert!(!env.h.audit_raw().contains(PASS));
}

#[tokio::test]
async fn clear_failure_is_retried_audited_and_not_fatal() {
    let env = start_env().await.ready().await;
    let (mut c, _id, (approve, _)) = env.request("db-password", 0).await;
    env.ha.fail_service("input_text.set_value");
    env.ha.set_state(ENTITY, PASS);
    env.ha.inject_action(&approve, Some(OWNER));
    // The clear was attempted (3 times) before the release went ahead.
    assert_eq!(value_of(&mut c).await, "hunter2-secret-value");
    assert!(env.ha.count("set_value:") >= 3);
    assert!(audit_has(
        &env.h,
        "ha_clear_failed",
        "channel",
        "homeassistant"
    ));
    // Closing the request retries (3 more attempts) because a clear is owed.
    env.ha
        .wait_until("the retry at close", |m| m.count("set_value:") >= 6)
        .await;
    assert_eq!(env.ha.state(ENTITY), PASS, "still there: HA refused");
}

#[tokio::test]
async fn stale_entity_is_cleared_at_startup() {
    let ha = MockHa::start().await;
    ha.set_state(ENTITY, "left-over-passphrase");
    let chan = HaChannel::new(&ha_cfg(&ha.url()), pw(HA_TOKEN)).unwrap();
    let h = Harness::start(Opts {
        channels: Some(vec![chan.clone(), Arc::new(AdminChannel)]),
        ..Opts::default()
    })
    .await;
    let task = tokio::spawn(chan.clone().run(h.core.clone()));
    ha.wait_until("stale value cleared", |m| m.state(ENTITY).is_empty())
        .await;
    for _ in 0..200 {
        if audit_has(&h, "ha_entity_cleared", "outcome", "stale") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(audit_has(&h, "ha_entity_cleared", "outcome", "stale"));
    assert!(!h.audit_raw().contains("left-over-passphrase"));
    task.abort();
    // An already-empty entity is left alone.
    let env = start_env().await.ready().await;
    assert_eq!(env.ha.count("set_value:"), 0);
}

#[tokio::test]
async fn untrusted_events_are_ignored_and_audited() {
    let env = start_env().await.ready().await;
    let (mut c, id, (approve, deny)) = env.request("db-password", 0).await;
    env.ha.set_state(ENTITY, PASS);
    let reads = env.ha.get_states_count();

    // A user that is not the owner, and an event without a user id.
    env.ha.inject_action(&approve, Some("mallory"));
    env.ha.inject_action(&deny, None);
    // Right user, wrong token.
    let forged = format!("SECRETD_APPROVE_{id}_{}", "A".repeat(43));
    env.ha.inject_action(&forged, Some(OWNER));
    // Right user, unknown (already resolved / never existed) request.
    let ghost = format!("SECRETD_APPROVE_{}_{}", "0".repeat(32), "B".repeat(43));
    env.ha.inject_action(&ghost, Some(OWNER));
    // Garbage and someone else's action are not even audited.
    env.ha.inject_action("SECRETD_APPROVE_garbage", Some(OWNER));
    env.ha.inject_action("OTHER_APP_ACTION", Some("mallory"));
    for _ in 0..300 {
        let n = env
            .h
            .audit_lines()
            .iter()
            .filter(|l| l["event"] == "ha_event_rejected")
            .count();
        if n >= 5 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let lines = env.h.audit_lines();
    let rejected: Vec<_> = lines
        .iter()
        .filter(|l| l["event"] == "ha_event_rejected")
        .collect();
    let outcomes: Vec<&str> = rejected
        .iter()
        .map(|l| l["outcome"].as_str().unwrap())
        .collect();
    for want in [
        "user_not_allowed",
        "user_missing",
        "bad_token",
        "unknown_request",
        "malformed_action",
    ] {
        assert!(outcomes.contains(&want), "{want} missing from {outcomes:?}");
    }
    let mallory = rejected
        .iter()
        .find(|l| l["outcome"] == "user_not_allowed")
        .unwrap();
    assert!(mallory["detail"].as_str().unwrap().contains("mallory"));
    assert!(rejected.iter().all(|l| l["channel"] == "homeassistant"));
    // Nothing was acted on: the request is pending, the entity untouched.
    assert_eq!(env.h.core.pending_count(), 1);
    assert_eq!(env.ha.get_states_count(), reads, "entity never read");
    assert_eq!(env.ha.state(ENTITY), PASS, "entity never cleared");
    // Action ids and tokens are never audited.
    let raw = env.h.audit_raw();
    assert!(!raw.contains("SECRETD_"), "action id in audit");
    assert!(!raw.contains(token_of_action(&approve)));
    assert!(!raw.contains(&"A".repeat(43)));
    // The real owner can still approve.
    env.ha.inject_action(&approve, Some(OWNER));
    assert_eq!(value_of(&mut c).await, "hunter2-secret-value");
}

#[tokio::test]
async fn already_resolved_request_is_rejected() {
    let env = start_env().await.ready().await;
    let (mut c, _id, (approve, deny)) = env.request("db-password", 0).await;
    env.ha.set_state(ENTITY, PASS);
    env.ha.inject_action(&approve, Some(OWNER));
    assert_eq!(value_of(&mut c).await, "hunter2-secret-value");
    let reads = env.ha.get_states_count();
    env.ha.inject_action(&deny, Some(OWNER));
    env.ha.inject_action(&approve, Some(OWNER));
    for _ in 0..300 {
        if audit_has(&env.h, "ha_event_rejected", "outcome", "unknown_request") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(audit_has(
        &env.h,
        "ha_event_rejected",
        "outcome",
        "unknown_request"
    ));
    assert_eq!(env.ha.get_states_count(), reads);
}

#[tokio::test]
async fn second_concurrent_approve_gets_busy() {
    let env = start_env().await.ready().await;
    env.h.core.set_unseal_delay(Duration::from_millis(700));
    let (mut c, id, (approve, _)) = env.request("db-password", 0).await;
    env.ha.set_state(ENTITY, PASS);
    env.ha.inject_action(&approve, Some(OWNER));
    tokio::time::sleep(Duration::from_millis(250)).await; // first is unsealing
    env.ha.inject_action(&approve, Some(OWNER));
    let busy = env.ha.wait_notification(1).await;
    assert!(
        busy["service_data"]["title"]
            .as_str()
            .unwrap()
            .contains("Busy"),
        "{busy}"
    );
    assert_eq!(busy["service_data"]["data"]["tag"], id.as_str());
    // The first approval is unaffected, and the busy tap read nothing.
    assert_eq!(value_of(&mut c).await, "hunter2-secret-value");
    assert_eq!(
        env.ha.get_states_count(),
        2,
        "connect check + the first approve"
    );
}

#[tokio::test]
async fn user_id_requirement_can_be_opted_out() {
    let env = start_env_with(|c| c.require_user_id = false, HA_TOKEN, 30)
        .await
        .ready()
        .await;
    let (mut c, _id, (approve, deny)) = env.request("db-password", 0).await;
    // A listed-user check still applies to events that do carry a user id.
    env.ha.inject_action(&deny, Some("mallory"));
    for _ in 0..300 {
        if audit_has(&env.h, "ha_event_rejected", "outcome", "user_not_allowed") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(env.h.core.pending_count(), 1);
    // No user id at all is accepted in this mode.
    env.ha.set_state(ENTITY, PASS);
    env.ha.inject_action(&approve, None);
    assert_eq!(value_of(&mut c).await, "hunter2-secret-value");
}

#[tokio::test]
async fn ha_approval_closes_the_web_page_with_410() {
    let ha = MockHa::start().await;
    let chan = HaChannel::new(&ha_cfg(&ha.url()), pw(HA_TOKEN)).unwrap();
    let w = Web::start(Opts {
        extra_channels: vec![chan.clone() as Arc<dyn Channel>],
        ..Opts::default()
    })
    .await;
    let task = tokio::spawn(chan.clone().run(w.h.core.clone()));
    ha.wait_connected().await;
    ha.wait_until("stale check", |m| m.get_states_count() >= 1)
        .await;

    let (mut conn, n) = w.start_get("db-password").await;
    let call = ha.wait_notification(0).await;
    assert_eq!(
        request_id_of(&call),
        n.request_id,
        "same request on both channels"
    );
    let (approve, _) = actions_of(&call);
    // The web page is open (signed in, form rendered).
    let path = path_of(&n.approval_url);
    let token = token_of(&n.approval_url);
    let sess = w.login(Some(&path)).await;
    let page = w.get(&path, Some(&sess)).await;
    assert_eq!(page.status, 200);
    let csrf = csrf_of(&page.body);
    // The owner approves from Home Assistant instead.
    ha.set_state(ENTITY, PASS);
    ha.inject_action(&approve, Some(OWNER));
    let g: GetResult = serde_json::from_value(conn.recv().await.unwrap().result.unwrap()).unwrap();
    assert_eq!(g.value, "hunter2-secret-value");
    // Web: the page and a late submit both say 410 Gone.
    assert_eq!(w.get(&path, Some(&sess)).await.status, 410);
    let r = w
        .post_form(
            &path,
            Some(&sess),
            &[
                ("t", &token),
                ("csrf", &csrf),
                ("action", "approve"),
                ("passphrase", PASS),
            ],
        )
        .await;
    assert_eq!(r.status, 410, "{}", r.body);
    // The approval carried the right channel; the web one is absent.
    assert!(audit_has(&w.h, "released", "channel", "homeassistant"));
    assert!(audit_has(&w.h, "notified", "channel", "web"));
    task.abort();
}

#[tokio::test]
async fn web_approval_clears_the_home_assistant_notification() {
    let ha = MockHa::start().await;
    let chan = HaChannel::new(&ha_cfg(&ha.url()), pw(HA_TOKEN)).unwrap();
    let w = Web::start(Opts {
        extra_channels: vec![chan.clone() as Arc<dyn Channel>],
        ..Opts::default()
    })
    .await;
    let task = tokio::spawn(chan.clone().run(w.h.core.clone()));
    ha.wait_connected().await;
    let (mut conn, n) = w.start_get("db-password").await;
    let call = ha.wait_notification(0).await;
    // The web side wins.
    let path = path_of(&n.approval_url);
    let token = token_of(&n.approval_url);
    let sess = w.login(Some(&path)).await;
    let page = w.get(&path, Some(&sess)).await;
    let csrf = csrf_of(&page.body);
    let r = w
        .post_form(
            &path,
            Some(&sess),
            &[
                ("t", &token),
                ("csrf", &csrf),
                ("action", "approve"),
                ("passphrase", PASS),
            ],
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let g: GetResult = serde_json::from_value(conn.recv().await.unwrap().result.unwrap()).unwrap();
    assert_eq!(g.value, "hunter2-secret-value");
    ha.wait_until("HA notification cleared", |m| {
        m.count("clear_notification:") == 1
    })
    .await;
    assert!(ha
        .timeline()
        .contains(&format!("clear_notification:{}", request_id_of(&call))));
    // A late Approve tap in HA is rejected (request gone).
    let (approve, _) = actions_of(&call);
    ha.inject_action(&approve, Some(OWNER));
    for _ in 0..300 {
        if audit_has(&w.h, "ha_event_rejected", "outcome", "unknown_request") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(audit_has(
        &w.h,
        "ha_event_rejected",
        "outcome",
        "unknown_request"
    ));
    task.abort();
}

// ------------------------------------------------ passphrase entity handling

/// Wait (bounded) for a condition on the daemon side.
async fn wait_for(what: &str, f: impl Fn() -> bool) {
    for _ in 0..600 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn closing_one_request_keeps_a_passphrase_typed_for_another() {
    let env = start_env().await.ready().await;
    let (ca, id_a, _) = env.request("db-password", 0).await;
    let (cb, id_b, _) = env.request("second", 1).await;
    // The owner is typing the passphrase for B ...
    env.ha.set_state(ENTITY, "typed-for-B");
    // ... when A goes away (the client disconnects).
    drop(ca);
    env.ha
        .wait_until("A's notification cleared", |m| {
            m.timeline().contains(&format!("clear_notification:{id_a}"))
        })
        .await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(env.ha.state(ENTITY), "typed-for-B", "B's passphrase wiped");
    assert_eq!(env.ha.count("set_value:"), 0);
    assert_eq!(env.h.core.pending_count(), 1);
    // B is the last request: when it closes, the entity is cleared.
    drop(cb);
    env.ha
        .wait_until("B's cleanup", |m| {
            m.timeline().contains(&format!("clear_notification:{id_b}"))
                && m.state(ENTITY).is_empty()
        })
        .await;
}

#[tokio::test]
async fn release_through_another_channel_clears_a_typed_passphrase() {
    let env = start_env().await.ready().await;
    let (mut c, id, _) = env.request("db-password", 0).await;
    // The owner typed the passphrase into HA but approves on the admin socket.
    env.ha.set_state(ENTITY, "typed-into-ha");
    assert_eq!(
        env.h
            .core
            .approve(&id, pw(PASS), secretd::core::Source::Admin)
            .await,
        secretd::core::ApproveOutcome::Released
    );
    assert_eq!(value_of(&mut c).await, "hunter2-secret-value");
    env.ha
        .wait_until("the typed passphrase to be cleared", |m| {
            m.state(ENTITY).is_empty()
        })
        .await;
    assert!(!env.h.audit_raw().contains("typed-into-ha"));
}

#[tokio::test]
async fn a_failed_clear_is_retried_when_the_request_closes() {
    let env = start_env().await.ready().await;
    let (mut c, _id, (approve, _)) = env.request("db-password", 0).await;
    env.ha.fail_service("input_text.set_value");
    env.ha.set_state(ENTITY, PASS);
    env.ha.inject_action(&approve, Some(OWNER));
    assert_eq!(value_of(&mut c).await, "hunter2-secret-value");
    assert_eq!(env.ha.state(ENTITY), PASS, "the clear failed");
    // HA recovers: the clear owed by the closed request goes through.
    env.ha
        .wait_until("first failures", |m| m.count("set_value:") >= 3)
        .await;
    env.ha.unfail_service("input_text.set_value");
    env.ha
        .wait_until("the owed clear", |m| m.state(ENTITY).is_empty())
        .await;
    assert!(audit_has(
        &env.h,
        "ha_clear_failed",
        "channel",
        "homeassistant"
    ));
}

#[tokio::test]
async fn an_owed_clear_is_settled_at_reconnect_even_with_requests_pending() {
    let env = start_env().await.ready().await;
    let (mut ca, _a, (approve_a, _)) = env.request("db-password", 0).await;
    let (_cb, _b, _) = env.request("second", 1).await;
    // A is approved but HA refuses every clear: PASS stays in the entity.
    env.ha.fail_service("input_text.set_value");
    env.ha.set_state(ENTITY, PASS);
    env.ha.inject_action(&approve_a, Some(OWNER));
    assert_eq!(value_of(&mut ca).await, "hunter2-secret-value");
    env.ha
        .wait_until("failed clears", |m| m.count("set_value:") >= 3)
        .await;
    assert_eq!(env.ha.state(ENTITY), PASS);
    // B is still pending, so the entity is left alone while connected ...
    // (the owner may be typing for B) ... but the link drops, HA recovers and
    // the connection comes back: the passphrase that was already used goes.
    env.ha.unfail_service("input_text.set_value");
    env.ha.drop_connection();
    wait_for("the link to come back", || {
        env.chan.is_connected() && env.ha.state(ENTITY).is_empty()
    })
    .await;
    assert!(env
        .h
        .audit_lines()
        .iter()
        .any(|l| { l["event"] == "ha_entity_cleared" && l["outcome"] == "owed" }));
}

#[tokio::test]
async fn a_failed_read_still_clears_the_entity() {
    let env = start_env().await.ready().await;
    let (mut c, _id, (approve, _)) = env.request("db-password", 0).await;
    // HA answers the state query with an error: the typed passphrase is
    // still in the entity and must not be left there.
    env.ha.set_state(ENTITY, PASS);
    env.ha.fail_get_states(true);
    env.ha.inject_action(&approve, Some(OWNER));
    let n = env.ha.wait_notification(1).await;
    assert!(n["service_data"]["title"]
        .as_str()
        .unwrap()
        .contains("Cannot read"));
    assert_eq!(env.ha.state(ENTITY), "", "cleared after the failed read");
    assert_eq!(env.ha.count("set_value:"), 1);
    assert!(n["service_data"]["message"]
        .as_str()
        .unwrap()
        .contains("cleared"));
    // The request is still pending; the owner types it again and it works.
    env.ha.fail_get_states(false);
    env.ha.set_state(ENTITY, PASS);
    env.ha.inject_action(&approve, Some(OWNER));
    assert_eq!(value_of(&mut c).await, "hunter2-secret-value");
}

#[tokio::test]
async fn a_read_that_loses_the_connection_still_ends_with_a_cleared_entity() {
    let env = start_env().await.ready().await;
    let (_c, _id, (approve, _)) = env.request("db-password", 0).await;
    env.ha.set_state(ENTITY, PASS);
    env.ha.drop_on_get_states(true);
    env.ha.inject_action(&approve, Some(OWNER));
    // The link dies mid-read: the clear is retried (and, if it cannot get
    // through, owed until the reconnect).
    wait_for("the disconnect", || !env.chan.is_connected()).await;
    env.ha.drop_on_get_states(false);
    wait_for("reconnect and the owed clear", || {
        env.chan.is_connected() && env.ha.state(ENTITY).is_empty()
    })
    .await;
}

#[tokio::test]
async fn outcomes_that_consume_the_passphrase_notify_the_owner() {
    // Aborted: the client goes away while the store is being unsealed.
    let env = start_env().await.ready().await;
    env.h.core.set_unseal_delay(Duration::from_millis(600));
    let (c, id, (approve, _)) = env.request("db-password", 0).await;
    env.ha.set_state(ENTITY, PASS);
    env.ha.inject_action(&approve, Some(OWNER));
    wait_for("the approval to start", || {
        env.h
            .audit_events()
            .contains(&"approve_attempt".to_string())
    })
    .await;
    drop(c);
    let tag = format!("notify:secretd-result-{id}:");
    env.ha
        .wait_until("the outcome notification", |m| m.count(&tag) == 1)
        .await;
    let n = env
        .ha
        .notifications()
        .into_iter()
        .find(|n| n["service_data"]["data"]["tag"] == format!("secretd-result-{id}").as_str())
        .unwrap();
    assert!(n["service_data"]["title"]
        .as_str()
        .unwrap()
        .contains("aborted"));
    assert!(n["service_data"]["data"]["actions"].is_null(), "no buttons");
    assert!(!env.h.audit_raw().contains(PASS));
    drop(env);

    // CallerChanged: the requesting process is not the one that connected.
    let env = start_env().await.ready().await;
    let (mut c, id, (approve, _)) = env.request("db-password", 0).await;
    env.h.procs.set(
        PID,
        secretd::procinfo::ProcInfo {
            exe: "/opt/test/bin/imposter".into(),
            ..psql_proc()
        },
    );
    env.ha.set_state(ENTITY, PASS);
    env.ha.inject_action(&approve, Some(OWNER));
    assert_eq!(err_kind(&c.recv().await.unwrap()), "CALLER_CHANGED");
    let tag = format!("notify:secretd-result-{id}:");
    env.ha
        .wait_until("the outcome notification", |m| m.count(&tag) == 1)
        .await;
    let n = env
        .ha
        .notifications()
        .into_iter()
        .find(|n| n["service_data"]["data"]["tag"] == format!("secretd-result-{id}").as_str())
        .unwrap();
    assert!(n["service_data"]["title"]
        .as_str()
        .unwrap()
        .contains("caller changed"));
    assert_eq!(env.ha.state(ENTITY), "");
}

#[tokio::test]
async fn auth_invalid_is_retried_slowly_and_audited_once() {
    let ha = MockHa::start().await;
    let chan = HaChannel::new(&ha_cfg(&ha.url()), pw("revoked-token")).unwrap();
    chan.set_auth_invalid_backoff(Duration::from_millis(500));
    let h = Harness::start(Opts {
        channels: Some(vec![chan.clone(), Arc::new(AdminChannel)]),
        ..Opts::default()
    })
    .await;
    let task = tokio::spawn(chan.clone().run(h.core.clone()));
    ha.wait_until("the first rejection", |m| m.auth_failures() >= 1)
        .await;
    // The normal backoff (50 ms here) would have retried several times by now.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(ha.auth_failures(), 1, "no fast retries after auth_invalid");
    // It does retry later (500 ms, then doubled), and audits only once.
    ha.wait_until("the second attempt", |m| m.auth_failures() >= 2)
        .await;
    let n = h
        .audit_events()
        .iter()
        .filter(|e| *e == "ha_auth_invalid")
        .count();
    assert_eq!(n, 1, "{:?}", h.audit_events());
    assert!(!h.audit_raw().contains("revoked-token"));
    task.abort();
}

#[tokio::test]
async fn a_notification_that_could_not_be_cleared_is_cleared_at_reconnect() {
    let env = start_env().await.ready().await;
    let (c, id, _) = env.request("db-password", 0).await;
    env.ha.set_state(ENTITY, "typed-while-down");
    // The link goes down and stays down.
    env.ha.reject_next(10_000);
    env.ha.drop_connection();
    wait_for("the disconnect", || !env.chan.is_connected()).await;
    // The request ends while HA cannot be reached.
    drop(c);
    wait_for("the request to close", || env.h.core.pending_count() == 0).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!env
        .ha
        .timeline()
        .contains(&format!("clear_notification:{id}")));
    // HA comes back: the stale notification and the passphrase are cleared.
    env.ha.reject_next(0);
    env.ha
        .wait_until("the deferred clean-up", |m| {
            m.timeline().contains(&format!("clear_notification:{id}")) && m.state(ENTITY).is_empty()
        })
        .await;
}

#[tokio::test]
async fn connect_and_disconnect_audit_lines_are_coalesced() {
    let env = start_env().await.ready().await;
    for _ in 0..3 {
        env.ha.drop_connection();
        wait_for("the disconnect", || !env.chan.is_connected()).await;
        wait_for("the reconnect", || env.chan.is_connected()).await;
    }
    let count = |e: &str| env.h.audit_events().iter().filter(|x| *x == e).count();
    assert_eq!(count("ha_connected"), 1, "{:?}", env.h.audit_events());
    assert_eq!(count("ha_disconnected"), 1);
    env.h.core.flush_audit_summaries(true);
    let summaries: Vec<String> = env
        .h
        .audit_lines()
        .iter()
        .filter(|l| {
            l["detail"]
                .as_str()
                .is_some_and(|d| d.starts_with("summary"))
        })
        .map(|l| format!("{} {}", l["event"], l["detail"]))
        .collect();
    assert!(
        summaries
            .iter()
            .any(|s| s.contains("ha_connected") && s.contains("3 further")),
        "{summaries:?}"
    );
    assert!(
        summaries
            .iter()
            .any(|s| s.contains("ha_disconnected") && s.contains("2 further")),
        "{summaries:?}"
    );
}

#[tokio::test]
async fn at_most_sixteen_action_events_are_handled_at_once() {
    let env = start_env().await.ready().await;
    let (_c, _id, (approve, _)) = env.request("db-password", 0).await;
    // Sixteen handlers get stuck waiting for HA: one on the state query, the
    // other fifteen on their "busy" answers.
    env.ha.hold_replies(true);
    for _ in 0..16 {
        env.ha.inject_action(&approve, Some(OWNER));
    }
    env.ha
        .wait_until("sixteen blocked handlers", |m| m.held_count() == 16)
        .await;
    // A seventeenth and further events are dropped, not handled: handling one
    // would audit a rejection (one per distinct user).
    for i in 0..10 {
        env.ha
            .inject_action(&approve, Some(&format!("mallory-{i}")));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !env.h
            .audit_events()
            .contains(&"ha_event_rejected".to_string()),
        "events beyond the cap were handled"
    );
    assert_eq!(env.ha.held_count(), 16);
    // Once the handlers finish, their permits are free again.
    env.ha.release_replies();
    wait_idle(&env.chan).await;
    env.ha.inject_action(&approve, Some("mallory-late"));
    wait_for("an event to be handled again", || {
        env.h.audit_lines().iter().any(|l| {
            l["event"] == "ha_event_rejected"
                && l["detail"]
                    .as_str()
                    .is_some_and(|d| d.contains("mallory-late"))
        })
    })
    .await;
}

#[tokio::test]
async fn revoking_a_user_id_by_reload_takes_effect() {
    let env = start_env().await.ready().await;
    let (mut c, _id, (approve, _)) = env.request("db-password", 0).await;
    env.ha.set_state(ENTITY, PASS);
    let reads = env.ha.get_states_count();
    // The owner's id is removed from the allowlist (what a SIGHUP applies).
    let mut cfg = ha_cfg(&env.ha.url());
    cfg.owner_user_ids = vec!["the-new-owner".into()];
    env.chan.apply_config(Some(&cfg));
    env.ha.inject_action(&approve, Some(OWNER));
    wait_for("the rejection", || {
        audit_has(&env.h, "ha_event_rejected", "outcome", "user_not_allowed")
    })
    .await;
    assert_eq!(env.h.core.pending_count(), 1, "request untouched");
    assert_eq!(env.ha.get_states_count(), reads, "entity never read");
    assert_eq!(env.ha.state(ENTITY), PASS);
    // Removing the section altogether rejects everybody.
    env.chan.apply_config(None);
    env.ha.inject_action(&approve, Some("the-new-owner"));
    env.ha.inject_action(&approve, Some("another-user"));
    wait_for("two more rejections", || {
        env.h
            .audit_lines()
            .iter()
            .filter(|l| l["event"] == "ha_event_rejected")
            .count()
            >= 3
    })
    .await;
    assert_eq!(env.h.core.pending_count(), 1);
    // The new list is live: the new owner can approve.
    env.chan.apply_config(Some(&cfg));
    env.ha.inject_action(&approve, Some("the-new-owner"));
    assert_eq!(value_of(&mut c).await, "hunter2-secret-value");
}
