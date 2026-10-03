//! Runs the real `secret` binary against an in-process secretd core. The
//! daemon identifies the CLI via real SO_PEERCRED and /proc, and the ACL pins
//! the CLI's own executable path and uid.

use async_trait::async_trait;
use secret_proto::config::{Config, NameResolver};
use secret_proto::store::{self, Entry};
use secretd::audit::Audit;
use secretd::core::{ApproveOutcome, Core, Source};
use secretd::notify::{Notification, Notifier, NotifyError};
use secretd::peer::RealPeerCred;
use secretd::procinfo::RealProcReader;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UnixListener;
use zeroize::Zeroizing;

const PASS: &str = "pw-for-tests";
const BIN: &str = env!("CARGO_BIN_EXE_secret");

#[derive(Default)]
struct Rec(Mutex<Vec<Notification>>);

#[async_trait]
impl Notifier for Rec {
    async fn notify(&self, n: &Notification) -> Result<(), NotifyError> {
        self.0.lock().unwrap().push(n.clone());
        Ok(())
    }
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

struct Env {
    dir: tempfile::TempDir,
    core: Arc<Core>,
    rec: Arc<Rec>,
    sock: PathBuf,
}

fn pw() -> Zeroizing<String> {
    Zeroizing::new(PASS.to_string())
}

impl Env {
    async fn start(limits: &str) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().display();
        let uid = unsafe { libc::geteuid() };
        let exe = std::fs::canonicalize(BIN).unwrap();
        let exe = exe.display();
        let mut secrets = String::new();
        for n in ["db", "api", "blob", "other"] {
            secrets += &format!(
                "[[secret]]\nname = \"{n}\"\nallow_uids = [{uid}]\nallow_exes = [\"{exe}\"]\n"
            );
        }
        let text = format!(
            r#"
[daemon]
store = "{d}/store.age"
socket = "{d}/s.sock"
admin_socket = "{d}/a.sock"
audit_log = "{d}/audit.jsonl"
[limits]
{limits}
[notify]
kind = "ntfy"
url = "https://ntfy.example.com/t"
[approval]
external_url = "https://secretd.test"
[approval.oidc]
client_id = "x"
client_secret_file = "{d}/oidc"
owner_emails = ["o@example.com"]
{secrets}
"#
        );
        let cfg = Config::parse(&text, &NoNames).unwrap();
        let sp = dir.path().join("store.age");
        store::create(&sp, &pw(), Some(8)).unwrap();
        let mut s = store::load(&sp, &pw()).unwrap();
        s.insert("db", Entry::from_bytes(b"db-secret"));
        s.insert("api", Entry::from_bytes(b"api-secret"));
        s.insert("blob", Entry::from_bytes(&[0xde, 0xad, 0x00, 0xbe]));
        s.insert("other", Entry::from_bytes(b"other-secret"));
        store::save(&sp, &pw(), &s, Some(8)).unwrap();
        let rec = Arc::new(Rec::default());
        let core = Core::new(
            cfg,
            Audit::open(&dir.path().join("audit.jsonl")).unwrap(),
            rec.clone(),
            Arc::new(RealProcReader),
        );
        let sock = dir.path().join("s.sock");
        let l = UnixListener::bind(&sock).unwrap();
        tokio::spawn(secretd::server::serve_clients(
            core.clone(),
            l,
            Arc::new(RealPeerCred),
        ));
        Env {
            dir,
            core,
            rec,
            sock,
        }
    }

    fn spawn(&self, args: &[&str], stdin: Option<Vec<u8>>) -> std::thread::JoinHandle<Output> {
        let mut c = Command::new(BIN);
        c.args(args)
            .arg("--socket")
            .arg(&self.sock)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        std::thread::spawn(move || {
            let mut child = c.spawn().unwrap();
            {
                use std::io::Write;
                let mut si = child.stdin.take().unwrap();
                if let Some(b) = stdin {
                    let _ = si.write_all(&b);
                }
            }
            child.wait_with_output().unwrap()
        })
    }

    async fn nth(&self, n: usize) -> Notification {
        for _ in 0..500 {
            if let Some(x) = self.rec.0.lock().unwrap().get(n) {
                return x.clone();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("notification {n} never arrived");
    }

    async fn approve(&self, n: usize) {
        let x = self.nth(n).await;
        let r = self.core.approve(&x.request_id, pw(), Source::Admin).await;
        assert_eq!(r, ApproveOutcome::Released);
    }

    async fn deny(&self, n: usize) {
        let x = self.nth(n).await;
        self.core.deny(&x.request_id, Source::Admin);
    }

    fn notifications(&self) -> Vec<Notification> {
        self.rec.0.lock().unwrap().clone()
    }
}

async fn join(h: std::thread::JoinHandle<Output>) -> Output {
    tokio::task::spawn_blocking(move || h.join().unwrap())
        .await
        .unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_prints_value_without_newline() {
    let e = Env::start("").await;
    let h = e.spawn(&["get", "db", "--reason", "cli test"], None);
    let n = e.nth(0).await;
    assert_eq!(n.secret_name, "db");
    assert_eq!(n.reason.as_deref(), Some("cli test"));
    assert_eq!(n.exe, std::fs::canonicalize(BIN).unwrap().to_string_lossy());
    e.approve(0).await;
    let o = join(h).await;
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(o.stdout, b"db-secret", "no trailing newline when not a TTY");
    assert!(err(&o).contains("waiting for owner approval"));
    assert!(!err(&o).contains("db-secret"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_binary_secret_is_decoded() {
    let e = Env::start("").await;
    let h = e.spawn(&["get", "blob"], None);
    e.approve(0).await;
    let o = join(h).await;
    assert_eq!(o.stdout, vec![0xde, 0xad, 0x00, 0xbe]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exit_codes() {
    let e = Env::start("max_pending_per_uid = 1").await;
    // 2: not found / ACL (indistinguishable)
    let o = join(e.spawn(&["get", "nope"], None)).await;
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("no such secret, or access denied"));
    assert!(e.notifications().is_empty());
    // 3: denied
    let h = e.spawn(&["get", "db"], None);
    e.deny(0).await;
    assert_eq!(join(h).await.status.code(), Some(3));
    // 4: timeout
    let o = join(e.spawn(&["get", "db", "--timeout", "1"], None)).await;
    assert_eq!(o.status.code(), Some(4));
    // 5: rate limited (second pending from same uid with cap 1)
    let h1 = e.spawn(&["get", "db"], None);
    e.nth(2).await;
    let o = join(e.spawn(&["get", "api"], None)).await;
    assert_eq!(o.status.code(), Some(5));
    e.deny(2).await;
    let _ = join(h1).await;
    // 1: generic (cannot connect)
    let o = Command::new(BIN)
        .args(["get", "db", "--socket", "/nonexistent/sock"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("cannot connect"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_shows_permitted_names() {
    let e = Env::start("").await;
    let o = join(e.spawn(&["list"], None)).await;
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(out(&o), "db\napi\nblob\nother\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inject_stdin_to_stdout_with_each_name_requested_once() {
    let e = Env::start("").await;
    let tpl = b"user=app\npass={{ secret:db }}\nkey={{secret:api}}\nagain={{ secret:db }}\nlit=\\{{ secret:db }}\n".to_vec();
    let h = e.spawn(&["inject", "--reason", "deploy"], Some(tpl));
    e.approve(0).await;
    e.approve(1).await;
    let o = join(h).await;
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(
        out(&o),
        "user=app\npass=db-secret\nkey=api-secret\nagain=db-secret\nlit={{ secret:db }}\n"
    );
    let n = e.notifications();
    assert_eq!(n.len(), 2, "db requested once even though used twice");
    assert_eq!(n[0].secret_name, "db");
    assert_eq!(n[1].secret_name, "api");
    assert_eq!(n[0].reason.as_deref(), Some("deploy"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inject_is_binary_safe_and_decodes_base64() {
    let e = Env::start("").await;
    let mut tpl = vec![0xff, 0x00, 0xfe];
    tpl.extend_from_slice(b"{{ secret:blob }}");
    tpl.push(0x80);
    let h = e.spawn(&["inject"], Some(tpl));
    e.approve(0).await;
    let o = join(h).await;
    assert_eq!(
        o.stdout,
        vec![0xff, 0x00, 0xfe, 0xde, 0xad, 0x00, 0xbe, 0x80]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inject_without_tokens_needs_no_daemon() {
    let o = Command::new(BIN)
        .args(["inject", "--socket", "/nonexistent/sock"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin
                .take()
                .unwrap()
                .write_all(b"plain \\{{ secret:x }}")?;
            c.wait_with_output()
        })
        .unwrap();
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(o.stdout, b"plain {{ secret:x }}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inject_writes_nothing_when_any_lookup_fails() {
    let e = Env::start("").await;
    let outfile = e.dir.path().join("out.conf");
    let tpl = b"a={{ secret:db }}\nb={{ secret:api }}\n".to_vec();

    // Second secret denied: non-zero exit, nothing on stdout, no output file.
    let h = e.spawn(&["inject"], Some(tpl.clone()));
    e.approve(0).await;
    e.deny(1).await;
    let o = join(h).await;
    assert_eq!(o.status.code(), Some(3));
    assert!(o.stdout.is_empty(), "stdout must stay empty: {}", out(&o));
    assert!(!out(&o).contains("db-secret"));

    let h = e.spawn(
        &["inject", "-o", outfile.to_str().unwrap()],
        Some(tpl.clone()),
    );
    e.approve(2).await;
    e.deny(3).await;
    let o = join(h).await;
    assert_eq!(o.status.code(), Some(3));
    assert!(!outfile.exists(), "no output file on failure");

    // Unknown secret in the template (first lookup fails): exit 2, nothing written.
    let h = e.spawn(
        &["inject", "-o", outfile.to_str().unwrap()],
        Some(b"x={{ secret:nope }}".to_vec()),
    );
    let o = join(h).await;
    assert_eq!(o.status.code(), Some(2));
    assert!(!outfile.exists());

    // Timeout on the second secret.
    let h = e.spawn(&["inject", "--timeout", "1"], Some(tpl));
    e.approve(4).await;
    let o = join(h).await;
    assert_eq!(o.status.code(), Some(4));
    assert!(o.stdout.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inject_output_file_mode_and_overwrite_protection() {
    use std::os::unix::fs::PermissionsExt;
    let e = Env::start("").await;
    let infile = e.dir.path().join("in.tpl");
    let outfile = e.dir.path().join("out.conf");
    std::fs::write(&infile, "token={{ secret:db }}\n").unwrap();
    let args = [
        "inject",
        "-i",
        infile.to_str().unwrap(),
        "-o",
        outfile.to_str().unwrap(),
    ];

    let h = e.spawn(&args, None);
    e.approve(0).await;
    assert_eq!(join(h).await.status.code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(&outfile).unwrap(),
        "token=db-secret\n"
    );
    let mode = std::fs::metadata(&outfile).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    // Refuses to overwrite, and does so before asking the owner for anything.
    let o = join(e.spawn(&args, None)).await;
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("--force"));
    assert_eq!(e.notifications().len(), 1);
    assert_eq!(
        std::fs::read_to_string(&outfile).unwrap(),
        "token=db-secret\n"
    );

    // --force replaces it atomically, still 0600.
    std::fs::write(&infile, "token={{ secret:api }}\n").unwrap();
    let mut forced = args.to_vec();
    forced.push("--force");
    let h = e.spawn(&forced, None);
    e.approve(1).await;
    assert_eq!(join(h).await.status.code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(&outfile).unwrap(),
        "token=api-secret\n"
    );
    let mode = std::fs::metadata(&outfile).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let leftovers: Vec<_> = std::fs::read_dir(e.dir.path())
        .unwrap()
        .filter_map(|x| x.ok())
        .filter(|x| x.file_name().to_string_lossy().contains(".tmp"))
        .collect();
    assert!(leftovers.is_empty());
}
