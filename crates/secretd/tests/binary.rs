//! End-to-end test of the real `secretd` binary: real sockets, real
//! SO_PEERCRED and /proc, mock ntfy and mock OIDC, plain-HTTP approval.

mod common;
use common::mock::*;
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
    http_port: u16,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
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

fn write_config(dir: &Path, port: u16, ntfy: &str, issuer: &str, uid: u32, exe: &str) {
    let d = dir.display();
    let text = format!(
        r#"
[daemon]
user = "root"
socket = "{d}/s.sock"
admin_socket = "{d}/a.sock"
store = "{d}/store.age"
audit_log = "{d}/audit.jsonl"
request_timeout_secs = 30
[notify]
kind = "ntfy"
url = "{ntfy}"
backoff_ms = 10
[approval]
listen = "127.0.0.1:{port}"
external_url = "https://secretd.test"
[approval.oidc]
issuer = "{issuer}"
client_id = "client-abc"
client_secret_file = "{d}/oidc-secret"
owner_emails = ["owner@example.com"]
[[secret]]
name = "mine"
allow_uids = [{uid}]
allow_exes = ["{exe}"]
"#
    );
    std::fs::write(dir.join("config.toml"), text).unwrap();
    std::fs::set_permissions(
        dir.join("config.toml"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
}

async fn start(ntfy: &str, issuer: &str) -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("oidc-secret"), "client-secret-value\n").unwrap();
    let sp = dir.path().join("store.age");
    store::create(&sp, &pw(PASS), WF).unwrap();
    let mut s = store::load(&sp, &pw(PASS)).unwrap();
    s.insert("mine", Entry::from_bytes(b"binary-secret-value"));
    store::save(&sp, &pw(PASS), &s, WF).unwrap();
    let port = free_port();
    let (uid, exe) = me();
    write_config(dir.path(), port, ntfy, issuer, uid, &exe);
    let log = std::fs::File::create(dir.path().join("daemon.log")).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_secretd"))
        .arg("--config")
        .arg(dir.path().join("config.toml"))
        .env("RUST_LOG", "debug")
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap();
    let d = Daemon {
        child,
        dir,
        http_port: port,
    };
    for _ in 0..300 {
        if d.dir.path().join("s.sock").exists()
            && std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
        {
            return d;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!(
        "daemon did not start: {}",
        std::fs::read_to_string(d.dir.path().join("daemon.log")).unwrap_or_default()
    );
}

struct Http {
    c: reqwest::Client,
    port: u16,
}

impl Http {
    fn new(port: u16) -> Http {
        Http {
            c: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .unwrap(),
            port,
        }
    }
    async fn get(&self, path: &str, cookie: Option<&str>) -> reqwest::Response {
        let mut r = self
            .c
            .get(format!("http://127.0.0.1:{}{path}", self.port))
            .header("Host", "secretd.test");
        if let Some(c) = cookie {
            r = r.header("Cookie", c);
        }
        r.send().await.unwrap()
    }
}

fn cookie_of(r: &reqwest::Response, name: &str) -> Option<String> {
    r.headers().get_all("set-cookie").iter().find_map(|v| {
        let f = v.to_str().ok()?.split(';').next()?.to_string();
        f.starts_with(&format!("{name}=")).then_some(f)
    })
}

#[tokio::test]
async fn full_system_flow_reload_and_shutdown() {
    let ntfy = MockNtfy::start(0).await;
    let oidc = MockOidc::start().await;
    let mut d = start(&ntfy.url, &oidc.issuer).await;
    let sock = d.dir.path().join("s.sock");

    // Socket permissions follow the config default (0660).
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o660);

    let mut c = Conn::connect(&sock).await;
    let p = c.call("server.ping", json!({})).await;
    assert_eq!(p.result.unwrap()["sealed"], true);
    let l = c.call("secret.list", json!({})).await;
    assert_eq!(l.result.unwrap()["names"], json!(["mine"]));

    // secret.get: real SO_PEERCRED + /proc identify this test process.
    c.send("secret.get", json!({"name": "mine", "reason": "e2e"}))
        .await;
    for _ in 0..300 {
        if !ntfy.received().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let m = ntfy.received().remove(0);
    let body = m.text();
    let (uid, exe) = me();
    assert!(body.contains(&format!("uid {uid}")), "{body}");
    assert!(
        body.contains(&format!("pid {}", std::process::id())),
        "{body}"
    );
    assert!(body.contains(&exe), "{body}");
    let click = url::Url::parse(m.header("click").unwrap()).unwrap();
    assert_eq!(click.host_str(), Some("secretd.test"));
    let path = format!("{}?{}", click.path(), click.query().unwrap());
    let token = click
        .query_pairs()
        .find(|(k, _)| k == "t")
        .unwrap()
        .1
        .into_owned();
    let id = click.path().trim_start_matches("/approve/").to_string();

    // Approve over plain HTTP after a (mock) Google sign-in.
    let http = Http::new(d.http_port);
    let r = http.get(&path, None).await;
    assert_eq!(r.status().as_u16(), 303);
    let r = http
        .get(
            &format!(
                "/auth/login?next={}",
                url::form_urlencoded::byte_serialize(path.as_bytes()).collect::<String>()
            ),
            None,
        )
        .await;
    assert_eq!(r.status().as_u16(), 303);
    let loc = url::Url::parse(r.headers()["location"].to_str().unwrap()).unwrap();
    let q: std::collections::HashMap<String, String> = loc.query_pairs().into_owned().collect();
    let login_cookie = cookie_of(&r, "__Host-sd_login").unwrap();
    oidc.plan("the-code", oidc.claims(&q["nonce"]), false);
    let cb = http
        .get(
            &format!("/auth/callback?code=the-code&state={}", q["state"]),
            Some(&login_cookie),
        )
        .await;
    assert_eq!(cb.status().as_u16(), 303);
    let sess = cookie_of(&cb, "__Host-sd_session").unwrap();
    let page = http.get(&path, Some(&sess)).await.text().await.unwrap();
    assert!(page.contains("e2e"));
    let csrf = common::web::csrf_of(&page);
    let form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("t", token.as_str()),
            ("csrf", &csrf),
            ("action", "approve"),
            ("passphrase", PASS),
        ])
        .finish();
    let r = http
        .c
        .post(format!("http://127.0.0.1:{}/approve/{id}", d.http_port))
        .header("Host", "secretd.test")
        .header("Cookie", &sess)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let g: GetResult = serde_json::from_value(c.recv().await.unwrap().result.unwrap()).unwrap();
    assert_eq!(g.value, "binary-secret-value");

    // SIGHUP reloads ACLs: remove our uid and the secret disappears.
    let (uid, exe) = me();
    write_config(
        d.dir.path(),
        d.http_port,
        &ntfy.url,
        &oidc.issuer,
        uid + 1,
        &exe,
    );
    unsafe {
        libc::kill(d.child.id() as i32, libc::SIGHUP);
    }
    let mut gone = false;
    for _ in 0..100 {
        let l = c.call("secret.list", json!({})).await;
        if l.result.unwrap()["names"] == json!([]) {
            gone = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }
    assert!(gone, "ACL reload did not take effect");

    // SIGTERM shuts down cleanly.
    unsafe {
        libc::kill(d.child.id() as i32, libc::SIGTERM);
    }
    let status = d.child.wait().unwrap();
    assert!(status.success());

    // Neither the logs nor the audit log contain secrets, passphrases or tokens.
    let log = std::fs::read_to_string(d.dir.path().join("daemon.log")).unwrap();
    let audit = std::fs::read_to_string(d.dir.path().join("audit.jsonl")).unwrap();
    for bad in ["binary-secret-value", PASS, &token, "client-secret-value"] {
        assert!(!log.contains(bad), "log leaked {bad}");
        assert!(!audit.contains(bad), "audit leaked {bad}");
    }
    assert!(audit.contains("\"released\""));
}

#[tokio::test]
async fn refuses_unsafe_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let (uid, exe) = me();
    std::fs::write(dir.path().join("oidc-secret"), "x").unwrap();
    write_config(
        dir.path(),
        18443,
        "http://127.0.0.1:1/x",
        "http://127.0.0.1:1",
        uid,
        &exe,
    );
    let cfg = dir.path().join("config.toml");
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_secretd"))
            .arg("--config")
            .arg(&cfg)
            .args(args)
            .output()
            .unwrap()
    };
    // --check validates and exits.
    let o = run(&["--check"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));

    // Group/world-writable config is refused.
    std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o666)).unwrap();
    let o = run(&["--check"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("writable"));
    std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o644)).unwrap();

    // Non-loopback listen address needs allow_non_loopback.
    let text = std::fs::read_to_string(&cfg)
        .unwrap()
        .replace("127.0.0.1:18443", "0.0.0.0:18443");
    std::fs::write(&cfg, &text).unwrap();
    let o = run(&["--check"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("allow_non_loopback"));
    let text = text.replace("[approval]\n", "[approval]\nallow_non_loopback = true\n");
    std::fs::write(&cfg, &text).unwrap();
    assert!(run(&["--check"]).status.success());

    // Missing allow_exes without allow_any_exe refuses to start.
    let bad = text.replace(&format!("allow_exes = [\"{exe}\"]"), "");
    std::fs::write(&cfg, bad).unwrap();
    let o = run(&["--check"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("allow_any_exe"));
}
