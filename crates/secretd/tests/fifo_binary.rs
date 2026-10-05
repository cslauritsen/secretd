//! The real `secretd` binary serving a named pipe: real process-table scan (`/proc` or libproc), real
//! reader process (`cat`), approval through the mock Home Assistant, clean-up
//! on SIGTERM.

mod common;
use common::ha::*;
use common::*;
use secret_proto::store::{self, Entry};
use secretd::procinfo::{ProcInfoReader, RealProcReader};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::process::{Command, Stdio};

#[tokio::test]
async fn real_daemon_serves_a_pipe_to_a_real_reader() {
    let ha = MockHa::start().await;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().display();
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    // The executable `cat` really is, as the kernel reports it.
    let mut probe = Command::new("cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let cat_exe = RealProcReader.read(probe.id()).unwrap().exe;
    let _ = probe.kill();
    let _ = probe.wait();
    let pipe = dir.path().join("pipes/mine");
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
[[fifo]]
path = "{pipe}"
secret = "mine"
group = {gid}
mode = "0640"
enforce_acl = true
cooldown_secs = 1
"#,
        url = ha.url(),
        exe = cat_exe,
        pipe = pipe.display()
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
    s.insert("mine", Entry::from_bytes(b"piped-secret\n\x00\x01"));
    store::save(&sp, &pw(PASS), &s, WF).unwrap();
    let log = std::fs::File::create(dir.path().join("daemon.log")).unwrap();
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_secretd"))
        .arg("--config")
        .arg(dir.path().join("config.toml"))
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap();
    for _ in 0..300 {
        if std::fs::symlink_metadata(&pipe).is_ok_and(|m| m.file_type().is_fifo()) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        std::fs::symlink_metadata(&pipe)
            .unwrap()
            .file_type()
            .is_fifo(),
        "{}",
        std::fs::read_to_string(dir.path().join("daemon.log")).unwrap_or_default()
    );
    ha.wait_connected().await;
    ha.wait_until("stale check", |m| m.get_states_count() >= 1)
        .await;

    // A legacy program reads the pipe.
    let reader = Command::new("cat")
        .arg(&pipe)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let rpid = reader.id();
    let n = ha.wait_notification(0).await;
    let text = n["service_data"]["message"].as_str().unwrap();
    assert!(text.contains("via FIFO"), "{text}");
    assert!(text.contains(&pipe.display().to_string()), "{text}");
    assert!(text.contains(&format!("pid {rpid}")), "{text}");
    assert!(text.contains(&cat_exe.to_string()), "{text}");
    assert!(text.contains("best effort"), "{text}");
    let (approve, _) = actions_of(&n);
    ha.set_state(ENTITY, PASS);
    ha.inject_action(&approve, Some(OWNER));
    let out = tokio::task::spawn_blocking(move || reader.wait_with_output().unwrap())
        .await
        .unwrap();
    assert_eq!(
        out.stdout, b"piped-secret\n\x00\x01",
        "raw bytes, nothing added"
    );
    assert_eq!(ha.state(ENTITY), "");

    // Audit: the pipe is named, the secret never appears.
    let raw = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    assert!(raw.contains(&format!("\"fifo\":\"{}\"", pipe.display())));
    assert!(raw.contains("\"event\":\"released\""));
    for bad in [PASS, "piped-secret", HA_TOKEN] {
        assert!(!raw.contains(bad), "audit leaks {bad}");
    }

    // SIGTERM: clean shutdown removes the pipe.
    unsafe {
        libc::kill(daemon.id() as i32, libc::SIGTERM);
    }
    for _ in 0..200 {
        if daemon.try_wait().unwrap().is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        daemon.try_wait().unwrap().is_some(),
        "daemon exited on SIGTERM"
    );
    assert!(!pipe.exists(), "pipe removed on clean shutdown");
    let _ = daemon.kill();
}
