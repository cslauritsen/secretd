#![allow(dead_code)]
//! Shared integration-test harness: an in-process daemon core on a temp
//! socket with injectable peer credentials, `/proc` reader and notifier.

pub mod mock;
pub mod web;

use async_trait::async_trait;
use secret_proto::config::{Config, NameResolver};
use secret_proto::store::{self, Entry};
use secret_proto::{Request, Response};
use secretd::audit::Audit;
use secretd::channel::Channel;
use secretd::core::Core;
use secretd::notify::{Notification, Notifier, NotifyError};
use secretd::peer::{PeerCred, PeerCredProvider, StaticPeerCred};
use secretd::procinfo::{ProcInfo, ProcReader, StaticProcReader};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

pub const PASS: &str = "correct horse battery";
pub const WF: Option<u8> = Some(8);
pub const PSQL: &str = "/opt/test/bin/psql";
pub const PID: u32 = 4242;

pub fn pw(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_string())
}

struct NoNames;
impl NameResolver for NoNames {
    fn uid(&self, _: &str) -> Option<u32> {
        None
    }
    fn gid(&self, _: &str) -> Option<u32> {
        None
    }
}

/// Records notifications and lets tests wait for them.
#[derive(Default)]
pub struct RecordingNotifier {
    pub seen: Mutex<Vec<Notification>>,
    pub notify: tokio::sync::Notify,
    pub fail: Mutex<bool>,
}

impl RecordingNotifier {
    pub async fn wait_for(&self, n: usize) -> Vec<Notification> {
        for _ in 0..500 {
            {
                let s = self.seen.lock().unwrap();
                if s.len() >= n {
                    return s.clone();
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {n} notification(s)");
    }
    pub fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

#[async_trait]
impl Notifier for RecordingNotifier {
    async fn notify(&self, n: &Notification) -> Result<(), NotifyError> {
        if *self.fail.lock().unwrap() {
            return Err(NotifyError("simulated".into()));
        }
        self.seen.lock().unwrap().push(n.clone());
        self.notify.notify_waiters();
        Ok(())
    }
}

pub struct Opts {
    /// Extra TOML appended to the config (extra `[[secret]]`, `[limits]` ...
    /// — note `[limits]`/`[daemon]` keys must be passed via the dedicated fields).
    pub extra: String,
    pub limits: String,
    pub timeout_secs: u64,
    pub notifier: Option<Arc<dyn Notifier>>,
    /// Explicit channel set (replaces the default web+admin pair).
    pub channels: Option<Vec<Arc<dyn Channel>>>,
    #[allow(clippy::type_complexity)]
    pub notifier_from_cfg: Option<Box<dyn FnOnce(&Config) -> Arc<dyn Notifier>>>,
    pub audit_writer: Option<Box<dyn std::io::Write + Send>>,
    pub peer: Option<Arc<dyn PeerCredProvider>>,
    pub procs: Option<Arc<dyn ProcReader>>,
    pub notify_url: String,
    pub oidc_issuer: String,
    pub listen: String,
    pub external_url: String,
    pub notify_kind: String,
    pub notify_extra: String,
    pub trusted_proxies: String,
    pub session_ttl_secs: u64,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            extra: String::new(),
            limits: String::new(),
            timeout_secs: 30,
            notifier: None,
            channels: None,
            notifier_from_cfg: None,
            audit_writer: None,
            peer: None,
            procs: None,
            notify_url: "https://ntfy.example.com/t".into(),
            oidc_issuer: "https://accounts.google.com".into(),
            listen: "127.0.0.1:8443".into(),
            external_url: "https://secretd.test".into(),
            notify_kind: "ntfy".into(),
            notify_extra: String::new(),
            trusted_proxies: "[\"127.0.0.1/32\", \"::1/128\"]".into(),
            session_ttl_secs: 3600,
        }
    }
}

pub struct Harness {
    pub dir: tempfile::TempDir,
    pub core: Arc<Core>,
    pub sock: PathBuf,
    pub store: PathBuf,
    pub audit_path: PathBuf,
    pub peer: Arc<StaticPeerCred>,
    pub procs: Arc<StaticProcReader>,
    pub notifier: Arc<RecordingNotifier>,
    pub config_text: String,
    pub cfg: Config,
}

pub fn config_text(dir: &std::path::Path, o: &Opts) -> String {
    format!(
        r#"
[daemon]
store = "{d}/store.age"
socket = "{d}/s.sock"
admin_socket = "{d}/a.sock"
audit_log = "{d}/audit.jsonl"
request_timeout_secs = {t}
[limits]
{limits}
[notify]
kind = "{nkind}"
url = "{nurl}"
attempts = 3
backoff_ms = 10
{files}
{nextra}
[approval]
listen = "{listen}"
external_url = "{ext}"
trusted_proxies = {proxies}
[approval.oidc]
issuer = "{iss}"
client_id = "client-abc"
client_secret_file = "{d}/oidc-secret"
owner_emails = ["owner@example.com"]
session_ttl_secs = {ttl}

[[secret]]
name = "db-password"
description = "Primary DB password"
allow_uids = [1000]
allow_exes = ["{psql}"]

[[secret]]
name = "blob"
allow_uids = [1000]
allow_exes = ["{psql}"]

[[secret]]
name = "other-user-only"
allow_uids = [2000]
allow_exes = ["{psql}"]

[[secret]]
name = "wrong-exe"
allow_uids = [1000]
allow_exes = ["/opt/test/bin/other"]

[[secret]]
name = "second"
allow_uids = [1000]
allow_exes = ["{psql}"]

[[secret]]
name = "third"
allow_uids = [1000]
allow_exes = ["{psql}"]

[[secret]]
name = "fourth"
allow_uids = [1000]
allow_exes = ["{psql}"]
{extra}
"#,
        d = dir.display(),
        t = o.timeout_secs,
        limits = o.limits,
        files = if o.notify_kind == "webhook" {
            format!("hmac_secret_file = \"{}/hmac.key\"", dir.display())
        } else {
            format!("auth_token_file = \"{}/ntfy.token\"", dir.display())
        },
        nkind = o.notify_kind,
        nextra = o.notify_extra,
        proxies = o.trusted_proxies,
        ttl = o.session_ttl_secs,
        nurl = o.notify_url,
        listen = o.listen,
        ext = o.external_url,
        iss = o.oidc_issuer,
        psql = PSQL,
        extra = o.extra
    )
}

impl Harness {
    pub async fn start(o: Opts) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let text = config_text(dir.path(), &o);
        std::fs::write(dir.path().join("oidc-secret"), "client-secret-value\n").unwrap();
        std::fs::write(dir.path().join("ntfy.token"), "ntfy-token-value\n").unwrap();
        std::fs::write(dir.path().join("hmac.key"), "hmac-key-value\n").unwrap();
        let cfg = Config::parse(&text, &NoNames).unwrap();

        let store_path = dir.path().join("store.age");
        store::create(&store_path, &pw(PASS), WF).unwrap();
        let mut s = store::load(&store_path, &pw(PASS)).unwrap();
        s.insert("db-password", Entry::from_bytes(b"hunter2-secret-value"));
        s.insert("blob", Entry::from_bytes(&[0xde, 0xad, 0xbe, 0xef, 0x00]));
        s.insert("other-user-only", Entry::from_bytes(b"not-yours"));
        s.insert("wrong-exe", Entry::from_bytes(b"wrong-exe-value"));
        s.insert("second", Entry::from_bytes(b"second-value"));
        s.insert("third", Entry::from_bytes(b"third-value"));
        s.insert("fourth", Entry::from_bytes(b"fourth-value"));
        store::save(&store_path, &pw(PASS), &s, WF).unwrap();

        let audit_path = dir.path().join("audit.jsonl");
        let audit = match o.audit_writer {
            Some(w) => Audit::from_writer(w),
            None => Audit::open(&audit_path).unwrap(),
        };
        let notifier = Arc::new(RecordingNotifier::default());
        let procs = Arc::new(StaticProcReader::new());
        procs.set(PID, psql_proc());
        let peer = Arc::new(StaticPeerCred::new(PeerCred {
            uid: 1000,
            gid: 100,
            pid: PID,
        }));
        let n: Arc<dyn Notifier> = match (o.notifier, o.notifier_from_cfg) {
            (Some(n), _) => n,
            (None, Some(f)) => f(&cfg),
            (None, None) => notifier.clone(),
        };
        let p: Arc<dyn ProcReader> = o.procs.unwrap_or_else(|| procs.clone());
        let core = match o.channels {
            Some(ch) => Core::with_channels(cfg.clone(), audit, ch, p),
            None => Core::new(cfg.clone(), audit, n, p),
        };

        let sock = dir.path().join("s.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let provider: Arc<dyn PeerCredProvider> = o.peer.unwrap_or_else(|| peer.clone());
        tokio::spawn(secretd::server::serve_clients(
            core.clone(),
            listener,
            provider,
        ));
        Harness {
            dir,
            core,
            sock,
            store: store_path,
            audit_path,
            peer,
            procs,
            notifier,
            config_text: text,
            cfg,
        }
    }

    pub async fn connect(&self) -> Conn {
        Conn::connect(&self.sock).await
    }

    pub fn audit_lines(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.audit_path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    pub fn audit_events(&self) -> Vec<String> {
        self.audit_lines()
            .iter()
            .map(|v| v["event"].as_str().unwrap().to_string())
            .collect()
    }

    pub fn audit_raw(&self) -> String {
        std::fs::read_to_string(&self.audit_path).unwrap_or_default()
    }
}

pub fn psql_proc() -> ProcInfo {
    ProcInfo {
        exe: PSQL.to_string(),
        cmdline: "psql -h db".to_string(),
        start_time: 1111,
    }
}

pub struct Conn {
    rd: BufReader<OwnedReadHalf>,
    wr: OwnedWriteHalf,
    next_id: u64,
}

impl Conn {
    pub async fn connect(path: &std::path::Path) -> Conn {
        let s = UnixStream::connect(path).await.unwrap();
        let (rd, wr) = s.into_split();
        Conn {
            rd: BufReader::new(rd),
            wr,
            next_id: 1,
        }
    }

    pub async fn send_raw(&mut self, bytes: &[u8]) {
        self.wr.write_all(bytes).await.unwrap();
    }

    pub async fn send(&mut self, method: &str, params: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let mut line = serde_json::to_vec(&Request::new(method, params, id)).unwrap();
        line.push(b'\n');
        self.send_raw(&line).await;
        id
    }

    /// Read one response line; `None` on EOF.
    pub async fn recv(&mut self) -> Option<Response> {
        let mut line = String::new();
        let n = self.rd.read_line(&mut line).await.ok()?;
        if n == 0 {
            return None;
        }
        Some(serde_json::from_str(&line).unwrap())
    }

    /// Like `recv` but gives up after `ms` milliseconds.
    pub async fn recv_timeout(&mut self, ms: u64) -> Option<Response> {
        tokio::time::timeout(std::time::Duration::from_millis(ms), self.recv())
            .await
            .ok()
            .flatten()
    }

    pub async fn call(&mut self, method: &str, params: Value) -> Response {
        self.send(method, params).await;
        self.recv().await.expect("connection closed")
    }

    pub async fn get(&mut self, name: &str) -> Response {
        self.call("secret.get", json!({"name": name, "reason": "tests"}))
            .await
    }
}

pub fn err_kind(r: &Response) -> String {
    r.error
        .as_ref()
        .and_then(|e| e.kind_str().map(str::to_string))
        .unwrap_or_else(|| panic!("expected error, got {r:?}"))
}
