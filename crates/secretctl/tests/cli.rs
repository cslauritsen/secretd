use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        std::fs::write(p.join("pass"), "pw-one\n").unwrap();
        std::fs::write(p.join("pass2"), "pw-two\n").unwrap();
        std::fs::write(p.join("oidc-secret"), "x\n").unwrap();
        std::fs::set_permissions(
            p.join("oidc-secret"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let cfg = format!(
            r#"
[daemon]
store = "{d}/store.age"
socket = "{d}/s.sock"
admin_socket = "{d}/a.sock"
audit_log = "{d}/audit.jsonl"
[notify]
kind = "ntfy"
url = "https://ntfy.example.com/t"
[approval]
external_url = "https://secretd.example.com"
[approval.oidc]
client_id = "abc"
client_secret_file = "{d}/oidc-secret"
owner_emails = ["o@example.com"]
[[secret]]
name = "db"
description = "database"
allow_uids = [1000]
allow_exes = ["/opt/test/bin/psql"]
"#,
            d = p.display()
        );
        std::fs::write(p.join("config.toml"), cfg).unwrap();
        std::fs::set_permissions(
            p.join("config.toml"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        Env { dir }
    }

    fn path(&self, n: &str) -> PathBuf {
        self.dir.path().join(n)
    }

    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_secretctl"));
        c.arg("--config")
            .arg(self.path("config.toml"))
            .args(["--work-factor", "8"])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        {
            let mut si = child.stdin.take().unwrap();
            if let Some(b) = stdin {
                let _ = si.write_all(b);
            }
        }
        child.wait_with_output().unwrap()
    }

    fn pf(&self) -> String {
        self.path("pass").display().to_string()
    }
}

fn ok(o: &Output) {
    assert!(
        o.status.success(),
        "failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

fn contains(path: &Path, needle: &[u8]) -> bool {
    std::fs::read(path)
        .unwrap()
        .windows(needle.len())
        .any(|w| w == needle)
}

#[test]
fn init_add_list_remove_flow() {
    let e = Env::new();
    let pf = e.pf();
    ok(&e.run(&["--passphrase-file", &pf, "init"], None));
    assert!(e.path("store.age").exists());
    // init refuses to overwrite
    assert!(!e
        .run(&["--passphrase-file", &pf, "init"], None)
        .status
        .success());

    ok(&e.run(
        &["--passphrase-file", &pf, "add", "db"],
        Some(b"s3cr3t-value\n"),
    ));
    assert!(!contains(&e.path("store.age"), b"s3cr3t-value"));

    // list: names + ACL from config, never values
    let o = e.run(&["list"], None);
    ok(&o);
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(out.contains("db"));
    assert!(out.contains("uids=[1000]"));
    assert!(out.contains("/opt/test/bin/psql"));
    assert!(!out.contains("s3cr3t-value"));

    // an unconfigured name warns
    let o = e.run(&["--passphrase-file", &pf, "add", "other"], Some(b"v"));
    ok(&o);
    assert!(String::from_utf8_lossy(&o.stderr).contains("unreachable"));

    let o = e.run(&["--passphrase-file", &pf, "list", "--check-store"], None);
    ok(&o);
    assert!(String::from_utf8_lossy(&o.stderr).contains("\"other\" is in the store but not"));

    ok(&e.run(&["--passphrase-file", &pf, "remove", "other"], None));
    assert!(!e
        .run(&["--passphrase-file", &pf, "remove", "other"], None)
        .status
        .success());
}

#[test]
fn add_wrong_passphrase_fails_and_does_not_modify() {
    let e = Env::new();
    let pf = e.pf();
    ok(&e.run(&["--passphrase-file", &pf, "init"], None));
    let before = std::fs::read(e.path("store.age")).unwrap();
    let pf2 = e.path("pass2").display().to_string();
    let o = e.run(&["--passphrase-file", &pf2, "add", "db"], Some(b"v"));
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("wrong passphrase"));
    assert_eq!(before, std::fs::read(e.path("store.age")).unwrap());
}

#[test]
fn add_from_file_binary_and_rejects_bad_name() {
    let e = Env::new();
    let pf = e.pf();
    ok(&e.run(&["--passphrase-file", &pf, "init"], None));
    std::fs::write(e.path("bin"), [0u8, 159, 146, 150]).unwrap();
    let bin = e.path("bin").display().to_string();
    ok(&e.run(
        &["--passphrase-file", &pf, "add", "db", "--file", &bin],
        None,
    ));
    assert!(!e
        .run(&["--passphrase-file", &pf, "add", "bad name"], Some(b"v"))
        .status
        .success());
    // verify through the library
    let s = secret_proto::store::load(
        &e.path("store.age"),
        &zeroize::Zeroizing::new("pw-one".to_string()),
    )
    .unwrap();
    let ent = s.get("db").unwrap();
    assert_eq!(ent.encoding, secret_proto::Encoding::Base64);
    assert_eq!(
        secret_proto::b64::decode(&ent.value).unwrap(),
        vec![0u8, 159, 146, 150]
    );
}

#[test]
fn rotate_passphrase() {
    let e = Env::new();
    let pf = e.pf();
    let pf2 = e.path("pass2").display().to_string();
    ok(&e.run(&["--passphrase-file", &pf, "init"], None));
    ok(&e.run(&["--passphrase-file", &pf, "add", "db"], Some(b"value-1")));
    ok(&e.run(
        &[
            "--passphrase-file",
            &pf,
            "--new-passphrase-file",
            &pf2,
            "rotate-passphrase",
        ],
        None,
    ));
    // old passphrase no longer works, new one does
    assert!(!e
        .run(&["--passphrase-file", &pf, "remove", "db"], None)
        .status
        .success());
    let s = secret_proto::store::load(
        &e.path("store.age"),
        &zeroize::Zeroizing::new("pw-two".to_string()),
    )
    .unwrap();
    assert_eq!(s.get("db").unwrap().value.as_str(), "value-1");
}

#[test]
fn secrets_are_not_accepted_as_arguments() {
    let e = Env::new();
    let pf = e.pf();
    ok(&e.run(&["--passphrase-file", &pf, "init"], None));
    // A second positional argument (value) is rejected by the parser.
    let o = e.run(&["--passphrase-file", &pf, "add", "db", "hunter2"], None);
    assert!(!o.status.success());
}

#[test]
fn check_config() {
    let e = Env::new();
    let o = e.run(&["check-config"], None);
    ok(&o);
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(out.contains("OK:"));
    assert!(out.contains("does not exist")); // store not initialised yet

    // group-writable config is refused
    std::fs::set_permissions(
        e.path("config.toml"),
        std::fs::Permissions::from_mode(0o664),
    )
    .unwrap();
    let o = e.run(&["check-config"], None);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("writable"));
}

#[test]
fn check_config_validates_channels() {
    let e = Env::new();
    let base = std::fs::read_to_string(e.path("config.toml")).unwrap();
    let with = |extra: &str| {
        std::fs::write(e.path("config.toml"), format!("{base}\n{extra}\n")).unwrap();
        e.run(&["check-config"], None)
    };
    // No approval channel at all: refused.
    let o = with("[channels]\nenabled = []");
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("at least one approval channel"));
    // Unknown channel: refused.
    assert!(!with("[channels]\nenabled = [\"sms\"]").status.success());
    // Subset: accepted, and the summary names the channels.
    let o = with("[channels]\nenabled = [\"web\", \"admin\"]");
    ok(&o);
    assert!(String::from_utf8_lossy(&o.stdout).contains("channels: web, admin"));
}

#[test]
fn check_config_home_assistant() {
    let e = Env::new();
    let base = std::fs::read_to_string(e.path("config.toml")).unwrap();
    let ha = |token_file: &str, extra: &str| {
        format!(
            "{base}\n[channels]\nenabled = [\"web\", \"homeassistant\"]\n[homeassistant]\n\
             url = \"https://ha.example.com\"\ntoken_file = \"{token_file}\"\n\
             notify_service = \"notify.mobile_app_phone\"\n\
             passphrase_entity = \"input_text.secretd_passphrase\"\n\
             owner_user_ids = [\"abc\"]\n{extra}\n"
        )
    };
    // Missing token file: an error.
    let missing = e.path("ha.token").display().to_string();
    std::fs::write(e.path("config.toml"), ha(&missing, "")).unwrap();
    let o = e.run(&["check-config"], None);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("homeassistant.token_file"));
    // With the token file: OK, plus the documented limits.
    std::fs::write(e.path("ha.token"), "tok\n").unwrap();
    std::fs::set_permissions(e.path("ha.token"), std::fs::Permissions::from_mode(0o400)).unwrap();
    let o = e.run(&["check-config"], None);
    ok(&o);
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(out.contains("channels: web, homeassistant"), "{out}");
    assert!(
        out.contains("255"),
        "passphrase length limit is documented: {out}"
    );
    assert!(out.contains("transits Home Assistant"), "{out}");
    // Plain http to a LAN host is refused by the validator.
    let cfg = ha(&e.path("ha.token").display().to_string(), "")
        .replace("https://ha.example.com", "http://homeassistant.local:8123");
    std::fs::write(e.path("config.toml"), cfg).unwrap();
    let o = e.run(&["check-config"], None);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("allow_insecure_http"));
    // Web off: no [notify]/[approval] needed at all.
    let only = format!(
        "[daemon]\nstore = \"{d}/store.age\"\nsocket = \"{d}/s.sock\"\n\
         admin_socket = \"{d}/a.sock\"\naudit_log = \"{d}/audit.jsonl\"\n\
         [channels]\nenabled = [\"homeassistant\"]\n[homeassistant]\n\
         url = \"https://ha.example.com\"\ntoken_file = \"{d}/ha.token\"\n\
         notify_service = \"notify.mobile_app_phone\"\n\
         passphrase_entity = \"input_text.secretd_passphrase\"\nowner_user_ids = [\"abc\"]\n",
        d = e.dir.path().display()
    );
    std::fs::write(e.path("config.toml"), only).unwrap();
    let o = e.run(&["check-config"], None);
    ok(&o);
    assert!(String::from_utf8_lossy(&o.stdout).contains("Home Assistant at https://ha.example.com"));
}

// ------------------------------------------------------------ admin socket

mod admin {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;

    /// A fake admin server that serves one connection and records requests.
    fn fake_server(
        dir: &Path,
        replies: Vec<serde_json::Value>,
    ) -> std::thread::JoinHandle<Vec<serde_json::Value>> {
        let l = UnixListener::bind(dir.join("a.sock")).unwrap();
        std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut rd = BufReader::new(s.try_clone().unwrap());
            let mut wr = s;
            let mut seen = Vec::new();
            for reply in replies {
                let mut line = String::new();
                if rd.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                let req: serde_json::Value = serde_json::from_str(&line).unwrap();
                let mut resp = reply;
                resp["jsonrpc"] = "2.0".into();
                resp["id"] = req["id"].clone();
                seen.push(req);
                wr.write_all(format!("{resp}\n").as_bytes()).unwrap();
            }
            seen
        })
    }

    #[test]
    fn pending_lists_requests() {
        let e = Env::new();
        let srv = fake_server(
            e.dir.path(),
            vec![serde_json::json!({"result": {"pending": [{
                "request_id": "abc123", "secret_name": "db", "uid": 1000, "username": "alice",
                "pid": 77, "exe": "/usr/bin/psql", "cmdline": "psql -h x",
                "reason": "backup", "expires_at": "2030-01-01T00:00:00Z"}]}})],
        );
        let sock = e.path("a.sock").display().to_string();
        let o = e.run(&["--admin-socket", &sock, "pending"], None);
        ok(&o);
        let out = String::from_utf8_lossy(&o.stdout).to_string();
        assert!(out.contains("abc123") && out.contains("db") && out.contains("alice"));
        assert!(out.contains("reason (client-supplied, untrusted): backup"));
        let seen = srv.join().unwrap();
        assert_eq!(seen[0]["method"], "admin.pending");
    }

    #[test]
    fn approve_sends_passphrase_and_reports_errors() {
        let e = Env::new();
        let srv = fake_server(
            e.dir.path(),
            vec![serde_json::json!({"result": {"ok": true}})],
        );
        let sock = e.path("a.sock").display().to_string();
        let pf = e.pf();
        ok(&e.run(
            &[
                "--admin-socket",
                &sock,
                "--passphrase-file",
                &pf,
                "approve",
                "abc123",
            ],
            None,
        ));
        let seen = srv.join().unwrap();
        assert_eq!(seen[0]["method"], "admin.approve");
        assert_eq!(seen[0]["params"]["request_id"], "abc123");
        assert_eq!(seen[0]["params"]["passphrase"], "pw-one");

        std::fs::remove_file(e.path("a.sock")).unwrap();
        let srv = fake_server(
            e.dir.path(),
            vec![
                serde_json::json!({"error": {"code": -32006, "message": "wrong passphrase",
                "data": {"kind": "DECRYPT_FAILED", "remaining_attempts": 2}}}),
            ],
        );
        let o = e.run(
            &[
                "--admin-socket",
                &sock,
                "--passphrase-file",
                &pf,
                "approve",
                "abc123",
            ],
            None,
        );
        assert!(!o.status.success());
        assert!(String::from_utf8_lossy(&o.stderr).contains("wrong passphrase"));
        srv.join().unwrap();
    }

    #[test]
    fn deny_sends_request_id() {
        let e = Env::new();
        let srv = fake_server(
            e.dir.path(),
            vec![serde_json::json!({"result": {"ok": true}})],
        );
        let sock = e.path("a.sock").display().to_string();
        ok(&e.run(&["--admin-socket", &sock, "deny", "abc123"], None));
        let seen = srv.join().unwrap();
        assert_eq!(seen[0]["method"], "admin.deny");
        assert_eq!(seen[0]["params"]["request_id"], "abc123");
    }

    #[test]
    fn missing_socket_is_a_clear_error() {
        let e = Env::new();
        let sock = e.path("nope.sock").display().to_string();
        let o = e.run(&["--admin-socket", &sock, "pending"], None);
        assert!(!o.status.success());
        assert!(String::from_utf8_lossy(&o.stderr).contains("admin socket"));
    }
}

#[test]
fn root_run_hands_the_store_to_the_daemon_user() {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("not root; skipping");
        return;
    }
    // Any existing unprivileged account will do as the "daemon user".
    let nobody = std::process::Command::new("id")
        .args(["-u", "nobody"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok());
    let Some(nobody) = nobody else {
        eprintln!("no 'nobody' user; skipping");
        return;
    };
    let e = Env::new();
    let cfg = std::fs::read_to_string(e.path("config.toml"))
        .unwrap()
        .replace("[daemon]\n", "[daemon]\nuser = \"nobody\"\n");
    std::fs::write(e.path("config.toml"), cfg).unwrap();
    let pf = e.pf();
    let owner = |e: &Env| std::fs::metadata(e.path("store.age")).unwrap().uid();

    let o = e.run(&["--passphrase-file", &pf, "init"], None);
    ok(&o);
    assert_eq!(owner(&e), nobody, "init");
    assert!(String::from_utf8_lossy(&o.stderr).contains("running as root"));
    ok(&e.run(&["--passphrase-file", &pf, "add", "db"], Some(b"v1\n")));
    assert_eq!(owner(&e), nobody, "add");
    let p2 = e.path("pass2").display().to_string();
    ok(&e.run(
        &[
            "--passphrase-file",
            &pf,
            "--new-passphrase-file",
            &p2,
            "rotate-passphrase",
        ],
        None,
    ));
    assert_eq!(owner(&e), nobody, "rotate-passphrase");
    ok(&e.run(&["--passphrase-file", &p2, "remove", "db"], None));
    assert_eq!(owner(&e), nobody, "remove");
    assert_eq!(
        std::fs::metadata(e.path("store.age")).unwrap().mode() & 0o777,
        0o600
    );
}

#[test]
fn check_config_flags_credentials_readable_by_the_socket_group() {
    use std::os::unix::fs::MetadataExt;
    let e = Env::new();
    let gid = std::fs::metadata(e.path("oidc-secret")).unwrap().gid();
    // Resolve the file's group name via the system database.
    let name = std::process::Command::new("getent")
        .args(["group", &gid.to_string()])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.split(':').next().map(str::to_string))
        .filter(|s| !s.is_empty());
    let Some(group) = name else {
        eprintln!("cannot resolve group name; skipping");
        return;
    };
    let cfg = std::fs::read_to_string(e.path("config.toml"))
        .unwrap()
        .replace(
            "[daemon]\n",
            &format!("[daemon]\nsocket_group = \"{group}\"\n"),
        );
    std::fs::write(e.path("config.toml"), cfg).unwrap();
    // Owner-only: fine. Group-readable by the socket group: flagged.
    let o = e.run(&["check-config"], None);
    ok(&o);
    assert!(!String::from_utf8_lossy(&o.stdout).contains("client socket group"));
    std::fs::set_permissions(
        e.path("oidc-secret"),
        std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    let o = e.run(&["check-config"], None);
    ok(&o);
    assert!(String::from_utf8_lossy(&o.stdout).contains("client socket group"));
}
