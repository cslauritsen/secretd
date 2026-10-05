#![allow(dead_code)]
//! A mock Home Assistant: just enough of the WebSocket API (`auth`,
//! `subscribe_events`, `call_service`, `get_states`, `ping`) with a tiny
//! entity store, a log of every command the daemon sent, event injection and
//! fault injection (reject connections, drop the link, fail service calls).

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

pub const HA_TOKEN: &str = "ha-long-lived-token-xyz";
pub const ENTITY: &str = "input_text.secretd_passphrase";
pub const OWNER: &str = "owner-user-id";

enum ServerCmd {
    Frame(Value),
    Close,
}

#[derive(Default)]
struct Inner {
    token: Mutex<String>,
    log: Mutex<Vec<Value>>,
    timeline: Mutex<Vec<String>>,
    entities: Mutex<HashMap<String, String>>,
    conn_times: Mutex<Vec<Instant>>,
    reject_next: AtomicUsize,
    auth_failures: AtomicUsize,
    get_states: AtomicUsize,
    fail_services: Mutex<HashSet<String>>,
    /// `get_states` answers with an error.
    fail_get_states: AtomicBool,
    /// `get_states` cuts the connection instead of answering.
    drop_on_get_states: AtomicBool,
    /// While set, `call_service` and `get_states` are executed but their
    /// answers are held back until `release_replies`.
    hold: AtomicBool,
    /// Like `hold`, but only for `notify` service calls.
    hold_notify: AtomicBool,
    held: Mutex<Vec<Value>>,
    current: Mutex<Option<mpsc::UnboundedSender<ServerCmd>>>,
    sub_id: Mutex<Option<u64>>,
}

pub struct MockHa {
    pub addr: SocketAddr,
    inner: Arc<Inner>,
}

impl MockHa {
    pub async fn start() -> MockHa {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let inner = Arc::new(Inner::default());
        *inner.token.lock().unwrap() = HA_TOKEN.to_string();
        inner
            .entities
            .lock()
            .unwrap()
            .insert(ENTITY.to_string(), String::new());
        let i2 = inner.clone();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { return };
                i2.conn_times.lock().unwrap().push(Instant::now());
                let i3 = i2.clone();
                tokio::spawn(async move { serve(i3, s).await });
            }
        });
        MockHa { addr, inner }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    // ---- state and fault injection
    pub fn set_state(&self, entity: &str, v: &str) {
        self.inner
            .entities
            .lock()
            .unwrap()
            .insert(entity.to_string(), v.to_string());
    }
    pub fn state(&self, entity: &str) -> String {
        self.inner
            .entities
            .lock()
            .unwrap()
            .get(entity)
            .cloned()
            .unwrap_or_default()
    }
    /// Close the next `n` connections right after the TCP accept (no handshake).
    pub fn reject_next(&self, n: usize) {
        self.inner.reject_next.store(n, Ordering::SeqCst);
    }
    pub fn fail_service(&self, name: &str) {
        self.inner.fail_services.lock().unwrap().insert(name.into());
    }
    pub fn unfail_service(&self, name: &str) {
        self.inner.fail_services.lock().unwrap().remove(name);
    }
    pub fn fail_get_states(&self, on: bool) {
        self.inner.fail_get_states.store(on, Ordering::SeqCst);
    }
    pub fn drop_on_get_states(&self, on: bool) {
        self.inner.drop_on_get_states.store(on, Ordering::SeqCst);
    }
    /// Hold back the answers to `call_service` / `get_states` (the commands
    /// are still executed and logged).
    pub fn hold_replies(&self, on: bool) {
        self.inner.hold.store(on, Ordering::SeqCst);
    }
    /// Hold back only the answers to `notify` service calls.
    pub fn hold_notify_replies(&self, on: bool) {
        self.inner.hold_notify.store(on, Ordering::SeqCst);
    }
    /// Number of answers currently held back.
    pub fn held_count(&self) -> usize {
        self.inner.held.lock().unwrap().len()
    }
    /// Stop holding and send every held answer.
    pub fn release_replies(&self) {
        self.inner.hold.store(false, Ordering::SeqCst);
        self.inner.hold_notify.store(false, Ordering::SeqCst);
        let held: Vec<Value> = std::mem::take(&mut *self.inner.held.lock().unwrap());
        if let Some(tx) = self.inner.current.lock().unwrap().clone() {
            for f in held {
                let _ = tx.send(ServerCmd::Frame(f));
            }
        }
    }
    pub fn remove_entity(&self, entity: &str) {
        self.inner.entities.lock().unwrap().remove(entity);
    }
    pub fn drop_connection(&self) {
        if let Some(tx) = self.inner.current.lock().unwrap().take() {
            let _ = tx.send(ServerCmd::Close);
        }
    }
    pub fn connections(&self) -> Vec<Instant> {
        self.inner.conn_times.lock().unwrap().clone()
    }
    pub fn auth_failures(&self) -> usize {
        self.inner.auth_failures.load(Ordering::SeqCst)
    }
    pub fn get_states_count(&self) -> usize {
        self.inner.get_states.load(Ordering::SeqCst)
    }

    // ---- event injection
    /// Fire a `mobile_app_notification_action` event as `user`.
    pub fn inject_action(&self, action: &str, user: Option<&str>) {
        let id = self.inner.sub_id.lock().unwrap().expect("subscribed");
        let mut ctx = json!({"id": "ctx", "parent_id": null});
        if let Some(u) = user {
            ctx["user_id"] = json!(u);
        } else {
            ctx["user_id"] = Value::Null;
        }
        let frame = json!({
            "id": id,
            "type": "event",
            "event": {
                "event_type": "mobile_app_notification_action",
                "data": {"action": action},
                "origin": "REMOTE",
                "time_fired": "2026-01-01T00:00:00+00:00",
                "context": ctx,
            }
        });
        let tx = self
            .inner
            .current
            .lock()
            .unwrap()
            .clone()
            .expect("connected");
        let _ = tx.send(ServerCmd::Frame(frame));
    }

    // ---- observation
    pub fn calls(&self) -> Vec<Value> {
        self.inner.log.lock().unwrap().clone()
    }
    pub fn timeline(&self) -> Vec<String> {
        self.inner.timeline.lock().unwrap().clone()
    }
    /// `notify` service calls (announcements, re-prompts and clears), in order.
    pub fn notifications(&self) -> Vec<Value> {
        self.calls()
            .into_iter()
            .filter(|c| c["type"] == "call_service" && c["domain"] == "notify")
            .collect()
    }
    pub fn count(&self, prefix: &str) -> usize {
        self.timeline()
            .iter()
            .filter(|t| t.starts_with(prefix))
            .count()
    }

    pub async fn wait_until(&self, what: &str, f: impl Fn(&MockHa) -> bool) {
        for _ in 0..600 {
            if f(self) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "timed out waiting for {what}; timeline: {:?}",
            self.timeline()
        );
    }

    pub async fn wait_connected(&self) {
        self.wait_until("the daemon to subscribe", |m| {
            m.inner.sub_id.lock().unwrap().is_some() && m.inner.current.lock().unwrap().is_some()
        })
        .await;
    }

    /// The nth (0-based) actionable announcement, once it arrived.
    pub async fn wait_notification(&self, n: usize) -> Value {
        self.wait_until("a notification", |m| m.notifications().len() > n)
            .await;
        self.notifications()[n].clone()
    }
}

/// (approve action id, deny action id) of a notify call.
pub fn actions_of(call: &Value) -> (String, String) {
    let acts = call["service_data"]["data"]["actions"].as_array().unwrap();
    let find = |t: &str| {
        acts.iter()
            .find(|a| a["title"] == t)
            .map(|a| a["action"].as_str().unwrap().to_string())
            .unwrap()
    };
    (find("Approve"), find("Deny"))
}

pub fn request_id_of(call: &Value) -> String {
    call["service_data"]["data"]["tag"].as_str().unwrap().into()
}

fn result_ok(id: u64, result: Value) -> Value {
    json!({"id": id, "type": "result", "success": true, "result": result})
}

async fn serve(inner: Arc<Inner>, s: tokio::net::TcpStream) {
    let prev = inner.reject_next.load(Ordering::SeqCst);
    if prev > 0 {
        inner.reject_next.store(prev - 1, Ordering::SeqCst);
        drop(s);
        return;
    }
    let Ok(mut ws) = tokio_tungstenite::accept_async(s).await else {
        return;
    };
    let hello = json!({"type": "auth_required", "ha_version": "2026.1.0"});
    if ws.send(Message::text(hello.to_string())).await.is_err() {
        return;
    }
    let Some(Ok(Message::Text(t))) = ws.next().await else {
        return;
    };
    let auth: Value = serde_json::from_str(t.as_str()).unwrap();
    let want = inner.token.lock().unwrap().clone();
    if auth["type"] != "auth" || auth["access_token"] != want.as_str() {
        inner.auth_failures.fetch_add(1, Ordering::SeqCst);
        let _ = ws
            .send(Message::text(
                json!({"type": "auth_invalid", "message": "Invalid access token"}).to_string(),
            ))
            .await;
        return;
    }
    let _ = ws
        .send(Message::text(
            json!({"type": "auth_ok", "ha_version": "2026.1.0"}).to_string(),
        ))
        .await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    inner.held.lock().unwrap().clear();
    *inner.current.lock().unwrap() = Some(tx);
    loop {
        tokio::select! {
            m = ws.next() => {
                let Some(Ok(m)) = m else { return };
                let Message::Text(t) = m else { continue };
                let cmd: Value = serde_json::from_str(t.as_str()).unwrap();
                let reply = handle(&inner, &cmd);
                let held = (matches!(cmd["type"].as_str(), Some("call_service" | "get_states"))
                    && inner.hold.load(Ordering::SeqCst))
                    || (cmd["type"] == "call_service"
                        && cmd["domain"] == "notify"
                        && inner.hold_notify.load(Ordering::SeqCst));
                if let (true, Some(r)) = (held, reply.clone()) {
                    inner.held.lock().unwrap().push(r);
                    continue;
                }
                if let Some(r) = reply {
                    if ws.send(Message::text(r.to_string())).await.is_err() { return; }
                }
            }
            c = rx.recv() => match c {
                Some(ServerCmd::Frame(f)) => {
                    if ws.send(Message::text(f.to_string())).await.is_err() { return; }
                }
                Some(ServerCmd::Close) | None => {
                    let _ = ws.close(None).await;
                    return;
                }
            }
        }
    }
}

fn handle(inner: &Inner, cmd: &Value) -> Option<Value> {
    let id = cmd["id"].as_u64().unwrap_or(0);
    match cmd["type"].as_str() {
        Some("ping") => Some(json!({"id": id, "type": "pong"})),
        Some("subscribe_events") => {
            *inner.sub_id.lock().unwrap() = Some(id);
            Some(result_ok(id, Value::Null))
        }
        Some("get_states") => {
            inner.get_states.fetch_add(1, Ordering::SeqCst);
            inner.log.lock().unwrap().push(cmd.clone());
            inner.timeline.lock().unwrap().push("get_states".into());
            if inner.drop_on_get_states.load(Ordering::SeqCst) {
                if let Some(tx) = inner.current.lock().unwrap().take() {
                    let _ = tx.send(ServerCmd::Close);
                }
                return None;
            }
            if inner.fail_get_states.load(Ordering::SeqCst) {
                return Some(json!({
                    "id": id, "type": "result", "success": false,
                    "error": {"code": "home_assistant_error", "message": "simulated failure"}
                }));
            }
            let list: Vec<Value> = inner
                .entities
                .lock()
                .unwrap()
                .iter()
                .map(|(k, v)| json!({"entity_id": k, "state": v, "attributes": {}}))
                .chain([json!({"entity_id": "light.kitchen", "state": "on", "attributes": {}})])
                .collect();
            Some(result_ok(id, Value::Array(list)))
        }
        Some("call_service") => {
            inner.log.lock().unwrap().push(cmd.clone());
            let domain = cmd["domain"].as_str().unwrap_or("");
            let service = cmd["service"].as_str().unwrap_or("");
            let full = format!("{domain}.{service}");
            let label = if full == "input_text.set_value" {
                format!(
                    "set_value:{}",
                    cmd["service_data"]["value"].as_str().unwrap_or("?")
                )
            } else if domain == "notify" && cmd["service_data"]["message"] == "clear_notification" {
                format!(
                    "clear_notification:{}",
                    cmd["service_data"]["data"]["tag"].as_str().unwrap_or("")
                )
            } else if domain == "notify" {
                format!(
                    "notify:{}:{}",
                    cmd["service_data"]["data"]["tag"].as_str().unwrap_or(""),
                    cmd["service_data"]["title"].as_str().unwrap_or("")
                )
            } else {
                full.clone()
            };
            inner.timeline.lock().unwrap().push(label);
            if inner.fail_services.lock().unwrap().contains(&full) {
                return Some(json!({
                    "id": id, "type": "result", "success": false,
                    "error": {"code": "home_assistant_error", "message": "simulated failure"}
                }));
            }
            if full == "input_text.set_value" {
                let ent = cmd["target"]["entity_id"].as_str().unwrap().to_string();
                let v = cmd["service_data"]["value"].as_str().unwrap().to_string();
                inner.entities.lock().unwrap().insert(ent, v);
            }
            Some(result_ok(id, json!({"context": {"id": "c"}})))
        }
        _ => None,
    }
}
