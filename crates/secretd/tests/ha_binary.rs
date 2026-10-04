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

#[tokio::test]
async fn home_assistant_only_deployment() {
    let ha = MockHa::start().await;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().display();
    let uid = unsafe { libc::geteuid() };
    let exe = std::env::current_exe()
        .unwrap()
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    std::fs::write(dir.path().join("ha.token"), format!("{HA_TOKEN}\n")).unwrap();
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
passphrase_entity = "{ENTITY}"
owner_user_ids = ["{OWNER}"]
backoff_min_ms = 50
[[secret]]
name = "mine"
allow_uids = [{uid}]
allow_exes = ["{exe}"]
"#,
        url = ha.url()
    );
    std::fs::write(dir.path().join("config.toml"), cfg).unwrap();
    std::fs::set_permissions(
        dir.path().join("config.toml"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
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

    let mut c = Conn::connect(&sock).await;
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
    let raw = std::fs::read_to_string(daemon.dir.path().join("audit.jsonl")).unwrap();
    assert!(raw.contains("\"channel\":\"homeassistant\""));
    for bad in [PASS, "binary-ha-secret", HA_TOKEN] {
        assert!(!raw.contains(bad), "audit leaks {bad}");
    }
    let log = std::fs::read_to_string(daemon.dir.path().join("daemon.log")).unwrap();
    for bad in [PASS, "binary-ha-secret", HA_TOKEN] {
        assert!(!log.contains(bad), "daemon log leaks {bad}");
    }
}
