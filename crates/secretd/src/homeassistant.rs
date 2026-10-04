//! Home Assistant channel (spec section 19).
//!
//! One WebSocket connection to `/api/websocket`, authenticated with a
//! long-lived token, carries everything: the `mobile_app_notification_action`
//! event subscription, the `notify` service call that announces a request
//! (with Approve/Deny actions whose ids carry the per-request token), reads and
//! clears of the passphrase `input_text` entity, and the call that clears the
//! notification afterwards.
//!
//! Security properties kept here (see `docs/DECISIONS.md` and the README):
//! * the passphrase entity is read only in response to a valid Approve action
//!   for a pending request (and once at connect, to clear a stale value), and
//!   is cleared immediately after being read, whatever happens next;
//! * action events are accepted only from `owner_user_ids` (`context.user_id`)
//!   and only with the constant-time-checked per-request token;
//! * the notification text contains neither the passphrase nor the token; the
//!   token appears only inside the action ids;
//! * the access token, the passphrase and action ids are never logged or
//!   audited.

use crate::audit::AuditEvent;
use crate::channel::{Channel, Closed};
use crate::core::{ApproveOutcome, Core, DenyOutcome, Source, TokenCheck, MAX_ATTEMPTS};
use crate::notify::{Notification, NotifyError};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use secret_proto::config::{ChannelKind, HaCfg};
use secret_proto::sanitize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};
use zeroize::Zeroizing;

/// Event fired by the Companion apps when a notification action is tapped.
pub const EVENT_TYPE: &str = "mobile_app_notification_action";
const APPROVE_PREFIX: &str = "SECRETD_APPROVE_";
const DENY_PREFIX: &str = "SECRETD_DENY_";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
const PING_EVERY: Duration = Duration::from_secs(30);
const DEAD_AFTER: Duration = Duration::from_secs(75);
/// Largest WebSocket message accepted (a `get_states` answer of a big install).
const MAX_MESSAGE: usize = 16 * 1024 * 1024;
/// Action events handled at the same time; the rest are dropped.
const MAX_HANDLERS: usize = 16;
const CLEAR_ATTEMPTS: u32 = 3;
const CLEAR_RETRY_DELAY: Duration = Duration::from_millis(200);

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;
type CallResult = Result<Value, String>;

struct Cmd {
    /// The command without its `id` (assigned by the connection task).
    body: Value,
    reply: oneshot::Sender<CallResult>,
}

pub struct HaChannel {
    cfg: HaCfg,
    token: Zeroizing<String>,
    tls: Option<Arc<rustls::ClientConfig>>,
    /// Command queue of the live, authenticated connection (`None` while down).
    link: Mutex<Option<mpsc::Sender<Cmd>>>,
    /// Requests announced here: id -> approval token (for re-prompts).
    tracked: Mutex<HashMap<String, Zeroizing<String>>>,
    /// One approval at a time: every request shares one passphrase entity.
    approving: AtomicBool,
    core: Mutex<Weak<Core>>,
    handlers: Arc<Semaphore>,
}

/// Holds the "an approval is being processed" flag.
struct ApprovalGate<'a>(&'a AtomicBool);

impl<'a> ApprovalGate<'a> {
    fn enter(flag: &'a AtomicBool) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| ApprovalGate(flag))
    }
}

impl Drop for ApprovalGate<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn read_pem_certs(path: &std::path::Path) -> io::Result<Vec<Vec<u8>>> {
    use base64::Engine;
    let text = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for line in text.lines() {
        let l = line.trim();
        if l == "-----BEGIN CERTIFICATE-----" {
            cur = Some(String::new());
        } else if l == "-----END CERTIFICATE-----" {
            if let Some(b64) = cur.take() {
                let der = base64::engine::general_purpose::STANDARD
                    .decode(b64.as_bytes())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                out.push(der);
            }
        } else if let Some(b) = cur.as_mut() {
            b.push_str(l);
        }
    }
    Ok(out)
}

/// TLS settings for `wss://`: the pinned `ca_file` if configured, else the
/// system roots. `None` for plain `ws://`.
fn build_tls(cfg: &HaCfg) -> io::Result<Option<Arc<rustls::ClientConfig>>> {
    if !cfg.ws_url.starts_with("wss://") {
        return Ok(None);
    }
    let mut roots = rustls::RootCertStore::empty();
    match &cfg.ca_file {
        Some(p) => {
            for der in read_pem_certs(p)? {
                roots
                    .add(rustls::pki_types::CertificateDer::from(der))
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            }
            if roots.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} contains no certificate", p.display()),
                ));
            }
        }
        None => {
            for c in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(c);
            }
            if roots.is_empty() {
                return Err(io::Error::other(
                    "no system root certificates found; set homeassistant.ca_file",
                ));
            }
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let conf = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Some(Arc::new(conf)))
}

async fn recv_json(ws: &mut Ws, dur: Duration) -> Result<Value, String> {
    loop {
        let m = tokio::time::timeout(dur, ws.next())
            .await
            .map_err(|_| "timed out".to_string())?;
        match m {
            None => return Err("connection closed".into()),
            Some(Err(e)) => return Err(e.to_string()),
            Some(Ok(Message::Text(t))) => {
                return serde_json::from_str(t.as_str()).map_err(|e| e.to_string())
            }
            Some(Ok(Message::Close(_))) => return Err("connection closed".into()),
            Some(Ok(_)) => continue,
        }
    }
}

/// Text of the announcement: the same details as the other channels, but no
/// approval link and no token.
pub fn message_text(n: &Notification, entity: &str) -> String {
    let mut b = String::new();
    b.push_str(&format!("Secret: {}", sanitize::clean(&n.secret_name, 256)));
    if let Some(d) = &n.description {
        b.push_str(&format!(" ({})", sanitize::clean(d, 120)));
    }
    if let Some(via) = &n.via {
        b.push_str(&format!("\nRequested {}", sanitize::clean(via, 600)));
    }
    let best_effort = if n.via.is_some() {
        " (best effort)"
    } else {
        ""
    };
    b.push_str(&format!("\nRequest ID: {}\n", n.request_id));
    if n.identified {
        b.push_str(&format!(
            "Caller{}: uid {} ({}), pid {}\nExecutable: {}\nCommand line: {}\n",
            best_effort,
            n.uid,
            sanitize::clean(&n.username, 64),
            n.pid,
            sanitize::clean(&n.exe, 512),
            sanitize::clean(&n.cmdline, 256),
        ));
    } else {
        b.push_str("Caller: unknown (no reader process could be identified)\n");
    }
    if let Some(r) = &n.reason {
        b.push_str(&format!(
            "Reason (client-supplied, untrusted): {}\n",
            sanitize::clean(r, 200)
        ));
    }
    b.push_str(&format!(
        "Expires: {}\nType the store passphrase into {entity}, then tap Approve.",
        n.expires_at
    ));
    b
}

impl HaChannel {
    /// `token` is the long-lived access token (read from `token_file` by the
    /// caller). Fails if the configured `ca_file` cannot be used.
    pub fn new(cfg: &HaCfg, token: Zeroizing<String>) -> io::Result<Arc<HaChannel>> {
        Ok(Arc::new(HaChannel {
            tls: build_tls(cfg)?,
            cfg: cfg.clone(),
            token,
            link: Mutex::new(None),
            tracked: Mutex::new(HashMap::new()),
            approving: AtomicBool::new(false),
            core: Mutex::new(Weak::new()),
            handlers: Arc::new(Semaphore::new(MAX_HANDLERS)),
        }))
    }

    /// True while the WebSocket is up and authenticated.
    pub fn is_connected(&self) -> bool {
        self.link
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    fn core(&self) -> Option<Arc<Core>> {
        self.core
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .upgrade()
    }

    // ------------------------------------------------------- connection

    /// Maintain the connection forever: connect, authenticate, subscribe,
    /// serve; on any failure wait (exponential backoff, `backoff_min_ms` up to
    /// `backoff_max_ms`) and start over. Abort the task to stop it.
    pub async fn run(self: Arc<Self>, core: Arc<Core>) {
        *self.core.lock().unwrap_or_else(|e| e.into_inner()) = Arc::downgrade(&core);
        let mut delay = self.cfg.backoff_min_ms;
        loop {
            let mut connected = false;
            let res = self.session(&core, &mut connected).await;
            *self.link.lock().unwrap_or_else(|e| e.into_inner()) = None;
            let why = match res {
                Ok(()) => "closed".to_string(),
                Err(e) => e,
            };
            if connected {
                delay = self.cfg.backoff_min_ms;
                let _ = core.audit(
                    &AuditEvent::new("ha_disconnected")
                        .channel(ChannelKind::HomeAssistant)
                        .detail(&sanitize::clean(&why, 200)),
                );
                tracing::warn!("home assistant disconnected: {why}");
            } else {
                tracing::warn!("home assistant connection failed: {why} (retry in {delay} ms)");
            }
            tokio::time::sleep(Duration::from_millis(delay)).await;
            delay = (delay.saturating_mul(2)).min(self.cfg.backoff_max_ms);
        }
    }

    async fn session(
        self: &Arc<Self>,
        core: &Arc<Core>,
        connected: &mut bool,
    ) -> Result<(), String> {
        let mut ws_cfg = WebSocketConfig::default();
        ws_cfg.max_message_size = Some(MAX_MESSAGE);
        ws_cfg.max_frame_size = Some(MAX_MESSAGE);
        let connector = self.tls.clone().map(Connector::Rustls);
        let (mut ws, _) = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio_tungstenite::connect_async_tls_with_config(
                self.cfg.ws_url.as_str(),
                Some(ws_cfg),
                false,
                connector,
            ),
        )
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| format!("connect: {e}"))?;

        // auth_required -> auth -> auth_ok
        let first = recv_json(&mut ws, AUTH_TIMEOUT).await?;
        if first["type"] != "auth_required" {
            return Err("unexpected greeting from the server".into());
        }
        let auth = Zeroizing::new(
            json!({"type": "auth", "access_token": self.token.as_str()}).to_string(),
        );
        ws.send(Message::text(auth.as_str()))
            .await
            .map_err(|e| e.to_string())?;
        drop(auth);
        let reply = recv_json(&mut ws, AUTH_TIMEOUT).await?;
        match reply["type"].as_str() {
            Some("auth_ok") => {}
            Some("auth_invalid") => return Err("authentication rejected (auth_invalid)".into()),
            _ => return Err("unexpected reply to authentication".into()),
        }

        // Subscribe to action events (command id 1).
        ws.send(Message::text(
            json!({"id": 1, "type": "subscribe_events", "event_type": EVENT_TYPE}).to_string(),
        ))
        .await
        .map_err(|e| e.to_string())?;
        loop {
            let m = recv_json(&mut ws, AUTH_TIMEOUT).await?;
            if m["type"] == "result" && m["id"] == 1 {
                if m["success"] != true {
                    return Err("event subscription refused".into());
                }
                break;
            }
        }

        let (tx, mut rx) = mpsc::channel::<Cmd>(32);
        *self.link.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        *connected = true;
        let _ = core.audit(&AuditEvent::new("ha_connected").channel(ChannelKind::HomeAssistant));
        tracing::info!("home assistant connected");
        // Do not leave a passphrase typed before we started lying around.
        tokio::spawn({
            let me = self.clone();
            let core = core.clone();
            async move { me.clear_stale(&core).await }
        });

        let mut next_id: u64 = 2;
        let mut calls: HashMap<u64, oneshot::Sender<CallResult>> = HashMap::new();
        let mut tick = tokio::time::interval_at(Instant::now() + PING_EVERY, PING_EVERY);
        let mut last_rx = Instant::now();
        loop {
            tokio::select! {
                m = ws.next() => {
                    let Some(m) = m else { return Err("connection closed".into()) };
                    last_rx = Instant::now();
                    match m.map_err(|e| e.to_string())? {
                        Message::Text(t) => {
                            let Ok(mut v) = serde_json::from_str::<Value>(t.as_str()) else {
                                continue;
                            };
                            self.on_message(&mut v, &mut calls, core);
                        }
                        Message::Close(_) => return Err("connection closed".into()),
                        _ => {}
                    }
                }
                Some(cmd) = rx.recv() => {
                    let id = next_id;
                    next_id += 1;
                    let mut body = cmd.body;
                    body["id"] = json!(id);
                    calls.insert(id, cmd.reply);
                    ws.send(Message::text(body.to_string()))
                        .await
                        .map_err(|e| e.to_string())?;
                }
                _ = tick.tick() => {
                    if last_rx.elapsed() > DEAD_AFTER {
                        return Err("no traffic from the server (dead connection)".into());
                    }
                    let id = next_id;
                    next_id += 1;
                    ws.send(Message::text(json!({"id": id, "type": "ping"}).to_string()))
                        .await
                        .map_err(|e| e.to_string())?;
                }
            }
        }
    }

    fn on_message(
        self: &Arc<Self>,
        v: &mut Value,
        calls: &mut HashMap<u64, oneshot::Sender<CallResult>>,
        core: &Arc<Core>,
    ) {
        match v["type"].as_str() {
            Some("result") => {
                let Some(id) = v["id"].as_u64() else { return };
                if let Some(reply) = calls.remove(&id) {
                    let r = if v["success"] == true {
                        Ok(v["result"].take())
                    } else {
                        Err(v["error"]["message"]
                            .as_str()
                            .map(|m| sanitize::clean(m, 200))
                            .unwrap_or_else(|| "call failed".into()))
                    };
                    let _ = reply.send(r);
                }
            }
            Some("event") if v["event"]["event_type"] == EVENT_TYPE => {
                let Some(action) = v["event"]["data"]["action"].as_str() else {
                    return;
                };
                if !action.starts_with(APPROVE_PREFIX) && !action.starts_with(DENY_PREFIX) {
                    return; // someone else's notification action
                }
                let user = v["event"]["context"]["user_id"]
                    .as_str()
                    .map(str::to_string);
                let Ok(permit) = self.handlers.clone().try_acquire_owned() else {
                    tracing::warn!("too many home assistant action events in flight; dropped one");
                    return;
                };
                let (me, core, action) = (self.clone(), core.clone(), action.to_string());
                tokio::spawn(async move {
                    me.handle_action(&core, &action, user.as_deref()).await;
                    drop(permit);
                });
            }
            _ => {}
        }
    }

    /// Send one command and wait for its result.
    async fn call(&self, body: Value) -> CallResult {
        let tx = self
            .link
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| "home assistant is not connected".to_string())?;
        let (reply, rx) = oneshot::channel();
        tx.send(Cmd { body, reply })
            .await
            .map_err(|_| "home assistant is not connected".to_string())?;
        match tokio::time::timeout(CALL_TIMEOUT, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err("connection lost".into()),
            Err(_) => Err("call timed out".into()),
        }
    }

    fn notify_call(&self, data: Value, message: &str, title: Option<&str>) -> Value {
        let (domain, service) = self
            .cfg
            .notify_service
            .split_once('.')
            .unwrap_or(("notify", &self.cfg.notify_service));
        let mut sd = json!({ "message": message, "data": data });
        if let Some(t) = title {
            sd["title"] = json!(t);
        }
        json!({"type": "call_service", "domain": domain, "service": service, "service_data": sd})
    }

    fn actions(id: &str, token: &str) -> Value {
        json!([
            {"action": format!("{APPROVE_PREFIX}{id}_{token}"), "title": "Approve"},
            {"action": format!("{DENY_PREFIX}{id}_{token}"), "title": "Deny"},
        ])
    }

    /// (Re)send the actionable notification for `id` under its tag.
    async fn prompt(&self, id: &str, title: &str, message: &str) -> Result<(), String> {
        let token = self
            .tracked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| "request not tracked".to_string())?;
        let data = json!({
            "tag": id,
            "actions": Self::actions(id, &token),
            "ttl": 0,
            "priority": "high",
        });
        self.call(self.notify_call(data, message, Some(title)))
            .await
            .map(|_| ())
    }

    async fn clear_notification(&self, id: &str) {
        let body = self.notify_call(json!({"tag": id}), "clear_notification", None);
        if let Err(e) = self.call(body).await {
            tracing::warn!("could not clear home assistant notification: {e}");
        }
    }

    // ------------------------------------------------- passphrase entity

    /// Current state of the passphrase entity. Unavailable/unknown count as empty.
    async fn read_entity(&self) -> Result<Zeroizing<String>, String> {
        let mut states = self.call(json!({"type": "get_states"})).await?;
        let list = states
            .as_array_mut()
            .ok_or_else(|| "unexpected get_states answer".to_string())?;
        for s in list.iter_mut() {
            if s["entity_id"] == self.cfg.passphrase_entity.as_str() {
                let st = match s["state"].take() {
                    Value::String(x) => Zeroizing::new(x),
                    _ => Zeroizing::new(String::new()),
                };
                return Ok(
                    if st.as_str() == "unknown" || st.as_str() == "unavailable" {
                        Zeroizing::new(String::new())
                    } else {
                        st
                    },
                );
            }
        }
        Err("passphrase entity not found in Home Assistant".into())
    }

    /// Set the passphrase entity to the empty string. Retries; audits
    /// `ha_clear_failed` if it still fails. Returns whether it worked.
    async fn clear_entity(&self, core: &Core) -> bool {
        let body = json!({
            "type": "call_service",
            "domain": "input_text",
            "service": "set_value",
            "target": {"entity_id": self.cfg.passphrase_entity},
            "service_data": {"value": ""},
        });
        let mut last = String::new();
        for attempt in 0..CLEAR_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(CLEAR_RETRY_DELAY).await;
            }
            match self.call(body.clone()).await {
                Ok(_) => return true,
                Err(e) => last = e,
            }
        }
        tracing::error!("could not clear the passphrase entity: {last}");
        let _ = core.audit(
            &AuditEvent::new("ha_clear_failed")
                .channel(ChannelKind::HomeAssistant)
                .detail(&sanitize::clean(&last, 200)),
        );
        false
    }

    /// At connect: a non-empty entity is a stale passphrase; clear it. Skipped
    /// while requests are pending here (the owner may be typing for one).
    async fn clear_stale(&self, core: &Core) {
        if !self
            .tracked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
        {
            return;
        }
        match self.read_entity().await {
            Ok(v) if v.is_empty() => {}
            Ok(v) => {
                drop(v);
                if self.clear_entity(core).await {
                    let _ = core.audit(
                        &AuditEvent::new("ha_entity_cleared")
                            .outcome("stale")
                            .channel(ChannelKind::HomeAssistant),
                    );
                }
            }
            Err(e) => tracing::warn!("could not check the passphrase entity at connect: {e}"),
        }
    }

    // ------------------------------------------------------- events

    fn reject(&self, core: &Core, outcome: &str, user: Option<&str>, request: Option<&str>) {
        let mut ev = AuditEvent::new("ha_event_rejected")
            .outcome(outcome)
            .channel(ChannelKind::HomeAssistant);
        if let Some(u) = user {
            ev = ev.detail(&format!("user_id={}", sanitize::clean(u, 64)));
        }
        if let Some(r) = request {
            ev = ev.request(r);
        }
        // Coalesced: anyone who can fire events on the HA bus can spam these.
        let _ = core.audit_coalesced(ev, &format!("{}|{outcome}", user.unwrap_or("-")));
    }

    fn user_allowed(&self, user: Option<&str>) -> Result<(), &'static str> {
        match user {
            Some(u) if self.cfg.owner_user_ids.iter().any(|o| o == u) => Ok(()),
            Some(_) if self.cfg.owner_user_ids.is_empty() && !self.cfg.require_user_id => Ok(()),
            Some(_) => Err("user_not_allowed"),
            None if !self.cfg.require_user_id => Ok(()),
            None => Err("user_missing"),
        }
    }

    async fn handle_action(self: &Arc<Self>, core: &Arc<Core>, action: &str, user: Option<&str>) {
        let (approve, rest) = if let Some(r) = action.strip_prefix(APPROVE_PREFIX) {
            (true, r)
        } else if let Some(r) = action.strip_prefix(DENY_PREFIX) {
            (false, r)
        } else {
            return;
        };
        // 1. Who fired the event. The action id is never audited.
        if let Err(why) = self.user_allowed(user) {
            self.reject(core, why, user, None);
            return;
        }
        // 2. `<32 hex request id>_<token>`.
        let parsed = rest.split_at_checked(32).and_then(|(id, t)| {
            let t = t.strip_prefix('_')?;
            let id_ok = id.bytes().all(|b| b.is_ascii_hexdigit());
            let t_ok = !t.is_empty()
                && t.len() <= 128
                && t.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            (id_ok && t_ok).then_some((id, t))
        });
        let Some((id, token)) = parsed else {
            self.reject(core, "malformed_action", user, None);
            return;
        };
        // 3. The request must still be pending and the token must match.
        match core.check_token(id, token) {
            TokenCheck::Ok => {}
            TokenCheck::Unknown => {
                self.reject(core, "unknown_request", user, Some(id));
                return;
            }
            TokenCheck::Mismatch => {
                self.reject(core, "bad_token", user, Some(id));
                return;
            }
        }
        if approve {
            self.do_approve(core, id).await;
        } else {
            match core.deny(id, Source::HomeAssistant) {
                DenyOutcome::Denied | DenyOutcome::DeniedUnaudited | DenyOutcome::Gone => {}
                DenyOutcome::Busy => {
                    let _ = self
                        .prompt(
                            id,
                            "Approval in progress",
                            "An approval of this request is being processed and can no longer be denied.",
                        )
                        .await;
                }
            }
        }
    }

    async fn do_approve(self: &Arc<Self>, core: &Arc<Core>, id: &str) {
        // Only one approval at a time: all requests share one entity.
        let Some(_gate) = ApprovalGate::enter(&self.approving) else {
            let _ = self
                .prompt(
                    id,
                    "Busy, try again",
                    "Another approval is being processed. Tap Approve again in a moment.",
                )
                .await;
            return;
        };
        // Read once ...
        let pass = match self.read_entity().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("cannot read the passphrase entity: {e}");
                let _ = self
                    .prompt(
                        id,
                        "Cannot read passphrase",
                        "Secretd could not read the passphrase entity. Try again.",
                    )
                    .await;
                return;
            }
        };
        if pass.is_empty() {
            // Nothing to unseal with; not an attempt.
            let _ = self
                .prompt(
                    id,
                    "Enter the passphrase first",
                    &format!(
                        "Enter the store passphrase into {} first, then tap Approve.",
                        self.cfg.passphrase_entity
                    ),
                )
                .await;
            return;
        }
        // ... and clear immediately, whether or not decryption will succeed.
        // The clear is attempted (with retries, audited on failure) before the
        // secret can be released.
        self.clear_entity(core).await;
        // Released, Failed, Gone, ...: the core closes the request, which
        // clears the notification (`closed`); only a retryable failure needs a
        // follow-up here.
        if let ApproveOutcome::WrongPassphrase { remaining } =
            core.approve(id, pass, Source::HomeAssistant).await
        {
            let _ = self
                .prompt(
                    id,
                    "Wrong passphrase",
                    &format!(
                        "Wrong passphrase. {remaining} of {MAX_ATTEMPTS} attempts left. \
                         Enter it again, then tap Approve."
                    ),
                )
                .await;
        }
    }
}

#[async_trait]
impl Channel for HaChannel {
    fn kind(&self) -> ChannelKind {
        ChannelKind::HomeAssistant
    }

    async fn announce(&self, n: &Notification) -> Result<(), NotifyError> {
        if !self.is_connected() {
            return Err(NotifyError("home assistant is not connected".into()));
        }
        self.tracked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                n.request_id.clone(),
                Zeroizing::new(n.approval_token.clone()),
            );
        let title = format!("Secret request: {}", sanitize::clean(&n.secret_name, 120));
        let text = message_text(n, &self.cfg.passphrase_entity);
        let r = self.prompt(&n.request_id, &title, &text).await;
        if let Err(e) = r {
            self.tracked
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&n.request_id);
            return Err(NotifyError(e));
        }
        Ok(())
    }

    async fn closed(&self, request_id: &str, why: Closed) {
        let was_ours = self
            .tracked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(request_id)
            .is_some();
        if !was_ours {
            return;
        }
        self.clear_notification(request_id).await;
        // A passphrase typed for a request that is now dead must not linger.
        if why != Closed::Released {
            if let Some(core) = self.core() {
                if self.is_connected() {
                    self.clear_entity(&core).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(ws_url: &str, ca: Option<std::path::PathBuf>) -> HaCfg {
        HaCfg {
            url: "https://ha".into(),
            ws_url: ws_url.into(),
            token_file: "/t".into(),
            notify_service: "notify.mobile_app_x".into(),
            passphrase_entity: "input_text.p".into(),
            owner_user_ids: vec!["u".into()],
            allow_insecure_http: false,
            ca_file: ca,
            require_user_id: true,
            backoff_min_ms: 1000,
            backoff_max_ms: 60_000,
        }
    }

    #[test]
    fn message_has_details_but_neither_token_nor_link() {
        let n = Notification {
            request_id: "0123456789abcdef0123456789abcdef".into(),
            secret_name: "db".into(),
            description: Some("Primary".into()),
            uid: 1000,
            username: "alice".into(),
            pid: 7,
            exe: "/usr/bin/psql".into(),
            cmdline: "psql".into(),
            reason: Some("because".into()),
            expires_at: "2026-01-01T00:00:00Z".into(),
            approval_url: "https://x/approve/abc?t=SECRETTOKEN".into(),
            approval_token: "SECRETTOKEN".into(),
            via: None,
            identified: true,
        };
        let t = message_text(&n, "input_text.p");
        assert!(t.contains("Secret: db (Primary)") && t.contains("uid 1000 (alice), pid 7"));
        assert!(t.contains("client-supplied, untrusted"));
        assert!(!t.contains("SECRETTOKEN") && !t.contains("https://"));
        assert!(!t.contains("best effort"));
        let f = Notification {
            via: Some("via FIFO /run/x".into()),
            ..n
        };
        let t = message_text(&f, "input_text.p");
        assert!(t.contains("via FIFO /run/x") && t.contains("Caller (best effort)"));
    }

    #[test]
    fn pinned_ca_must_contain_a_certificate() {
        let d = tempfile::tempdir().unwrap();
        let empty = d.path().join("empty.pem");
        std::fs::write(&empty, "not a certificate\n").unwrap();
        assert!(build_tls(&cfg("wss://ha/api/websocket", Some(empty))).is_err());
        assert!(build_tls(&cfg(
            "wss://ha/api/websocket",
            Some(d.path().join("missing"))
        ))
        .is_err());
        // Plain ws needs no TLS configuration at all.
        assert!(build_tls(&cfg("ws://ha/api/websocket", None))
            .unwrap()
            .is_none());
    }

    #[test]
    fn pem_bundle_is_split_into_certificates() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ca.pem");
        std::fs::write(
            &p,
            "junk\n-----BEGIN CERTIFICATE-----\nAAEC\nAwQ=\n-----END CERTIFICATE-----\n\
             -----BEGIN CERTIFICATE-----\nBQYH\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let v = read_pem_certs(&p).unwrap();
        assert_eq!(v, vec![vec![0, 1, 2, 3, 4], vec![5, 6, 7]]);
    }

    #[test]
    fn action_gate_admits_one() {
        let f = AtomicBool::new(false);
        let g = ApprovalGate::enter(&f).expect("first");
        assert!(ApprovalGate::enter(&f).is_none());
        drop(g);
        assert!(ApprovalGate::enter(&f).is_some());
    }
}
