//! The real `secretd` binary with Home Assistant as the only approval channel
//! (plus the admin socket): no [notify], [approval] or OIDC settings, and no
//! HTTP listener.

mod common;
use common::ha::*;
use common::*;
use secret_proto::store::{self, Entry};
use secret_proto::GetResult;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};

struct Daemon {
    child: Child,
    dir: tempfile::TempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn me() -> (u32, String) {
    let uid = unsafe { libc::geteuid() };
    let exe = std::env::current_exe()
        .unwrap()
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    (uid, exe)
}

fn write_config(dir: &Path, url: &str, owners: &str, entity: &str) {
    let d = dir.display();
    let (uid, exe) = me();
    let cfg = format!(
        r#"
[daemon]
user = "root"
socket = "{d}/s.sock"
admin_socket = "{d}/a.sock"
store = "{d}/store.age"
audit_log = "{d}/audit.jsonl"
request_timeout_secs = 30
[channels]
enabled = ["homeassistant", "admin"]
[homeassistant]
url = "{url}"
token_file = "{d}/ha.token"
notify_service = "notify.mobile_app_owner_phone"
passphrase_entity = "{entity}"
owner_user_ids = {owners}
backoff_min_ms = 50
[[secret]]
name = "mine"
allow_uids = [{uid}]
allow_exes = ["{exe}"]
"#
    );
    std::fs::write(dir.join("config.toml"), cfg).unwrap();
    std::fs::set_permissions(
        dir.join("config.toml"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
}

/// Start the real daemon against `ha`; returns it once the HA link is up.
async fn start_daemon(ha: &MockHa) -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("ha.token"), format!("{HA_TOKEN}\n")).unwrap();
    write_config(dir.path(), &ha.url(), &format!("[\"{OWNER}\"]"), ENTITY);
    let sp = dir.path().join("store.age");
    store::create(&sp, &pw(PASS), WF).unwrap();
    let mut s = store::load(&sp, &pw(PASS)).unwrap();
    s.insert("mine", Entry::from_bytes(b"binary-ha-secret"));
    store::save(&sp, &pw(PASS), &s, WF).unwrap();
    let log = std::fs::File::create(dir.path().join("daemon.log")).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_secretd"))
        .arg("--config")
        .arg(dir.path().join("config.toml"))
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap();
    let daemon = Daemon { child, dir };
    let sock = daemon.dir.path().join("s.sock");
    for _ in 0..300 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    ha.wait_connected().await;
    ha.wait_until("stale check", |m| m.get_states_count() >= 1)
        .await;
    daemon
}

impl Daemon {
    fn sock(&self) -> std::path::PathBuf {
        self.dir.path().join("s.sock")
    }
    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("daemon.log")).unwrap_or_default()
    }
    fn audit(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl")).unwrap_or_default()
    }
    async fn wait_log(&self, what: &str) {
        for _ in 0..500 {
            if self.log().contains(what) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for {what:?} in the log:\n{}", self.log());
    }
}

#[tokio::test]
async fn home_assistant_only_deployment() {
    let ha = MockHa::start().await;
    let daemon = start_daemon(&ha).await;
    let (_, exe) = me();
    let mut c = Conn::connect(&daemon.sock()).await;
    c.send("secret.get", json!({"name": "mine", "reason": "ha-only"}))
        .await;
    let n = ha.wait_notification(0).await;
    let text = n["service_data"]["message"].as_str().unwrap();
    assert!(
        text.contains(&format!("pid {}", std::process::id())),
        "{text}"
    );
    assert!(text.contains(&exe), "{text}");
    let (approve, _) = actions_of(&n);
    ha.set_state(ENTITY, PASS);
    ha.inject_action(&approve, Some(OWNER));
    let r = c.recv().await.unwrap();
    let g: GetResult = serde_json::from_value(r.result.unwrap()).unwrap();
    assert_eq!(g.value, "binary-ha-secret");
    assert_eq!(ha.state(ENTITY), "");
    // The audit log of the real daemon carries the channel and no secrets.
    let raw = daemon.audit();
    assert!(raw.contains("\"channel\":\"homeassistant\""));
    for bad in [PASS, "binary-ha-secret", HA_TOKEN] {
        assert!(!raw.contains(bad), "audit leaks {bad}");
    }
    let log = daemon.log();
    for bad in [PASS, "binary-ha-secret", HA_TOKEN] {
        assert!(!log.contains(bad), "daemon log leaks {bad}");
    }
}

#[tokio::test]
async fn sighup_applies_the_allowlist_and_names_what_needs_a_restart() {
    let ha = MockHa::start().await;
    let daemon = start_daemon(&ha).await;
    let mut c = Conn::connect(&daemon.sock()).await;
    c.send("secret.get", json!({"name": "mine", "reason": "reload"}))
        .await;
    let n = ha.wait_notification(0).await;
    let (approve, _) = actions_of(&n);
    // The owner's id is revoked and another id added; the entity is changed
    // too, which only a restart can apply.
    write_config(
        daemon.dir.path(),
        &ha.url(),
        "[\"the-new-owner\"]",
        "input_text.somewhere_else",
    );
    unsafe { libc::kill(daemon.child.id() as i32, libc::SIGHUP) };
    daemon.wait_log("configuration reloaded").await;
    daemon.wait_log("NOT applied").await;
    let log = daemon.log();
    assert!(log.contains("homeassistant"), "names the section: {log}");
    // The revoked id no longer approves ...
    ha.set_state(ENTITY, PASS);
    ha.inject_action(&approve, Some(OWNER));
    for _ in 0..500 {
        if daemon.audit().contains("user_not_allowed") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        daemon.audit().contains("user_not_allowed"),
        "{}",
        daemon.audit()
    );
    assert_eq!(ha.state(ENTITY), PASS, "nothing was read or cleared");
    // ... and the new one does (the entity is still the old one: restart).
    ha.inject_action(&approve, Some("the-new-owner"));
    let r = c.recv().await.unwrap();
    let g: GetResult = serde_json::from_value(r.result.unwrap()).unwrap();
    assert_eq!(g.value, "binary-ha-secret");
}
