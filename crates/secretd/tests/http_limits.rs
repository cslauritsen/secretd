//! Resource limits of the approval listener, the login limiter and Host handling.
mod common;
use common::web::*;
use common::*;
use secretd::approval::{self, ServeOpts};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A second approval listener on the harness's core with custom limits.
async fn custom_server(
    w: &Web,
    opts: ServeOpts,
    edit: impl FnOnce(&mut secret_proto::config::ApprovalCfg),
) -> SocketAddr {
    let mut cfg = w.h.cfg.approval.clone().unwrap();
    edit(&mut cfg);
    let app = approval::router(w.h.core.clone(), cfg, w.oidc_client.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = approval::serve_with(l, app, opts).await;
    });
    addr
}

fn opts(max: usize, header_ms: u64) -> ServeOpts {
    ServeOpts {
        max_connections: max,
        header_read_timeout: Duration::from_millis(header_ms),
        max_lifetime: Duration::from_secs(30),
    }
}

const HEALTHZ: &[u8] = b"GET /healthz HTTP/1.1\r\nHost: secretd.test\r\nConnection: close\r\n\r\n";

async fn healthz_ok(addr: SocketAddr) -> bool {
    let Ok(mut s) = TcpStream::connect(addr).await else {
        return false;
    };
    if s.write_all(HEALTHZ).await.is_err() {
        return false;
    }
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).contains("200 OK")
}

/// True if the server closed the connection (EOF/reset) within `ms`.
async fn closed_within(s: &mut TcpStream, ms: u64) -> bool {
    let mut b = [0u8; 256];
    match tokio::time::timeout(Duration::from_millis(ms), s.read(&mut b)).await {
        Ok(Ok(0)) | Ok(Err(_)) => true,
        Ok(Ok(_)) => true, // e.g. a 408 body followed by close
        Err(_) => false,
    }
}

#[tokio::test]
async fn connection_cap_closes_extra_connections_and_recovers() {
    let w = Web::start(Opts::default()).await;
    let addr = custom_server(&w, opts(2, 30_000), |_| {}).await;
    // Two idle connections hold both slots.
    let a = TcpStream::connect(addr).await.unwrap();
    let b = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    // A third is closed immediately without being served.
    let mut c = TcpStream::connect(addr).await.unwrap();
    let _ = c.write_all(HEALTHZ).await;
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), c.read_to_end(&mut got)).await;
    assert!(
        !String::from_utf8_lossy(&got).contains("200 OK"),
        "over-cap connection must not be served"
    );
    // Freeing a slot lets service resume.
    drop(a);
    let mut ok = false;
    for _ in 0..50 {
        if healthz_ok(addr).await {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ok, "service resumes after a slot is freed");
    drop(b);
}

#[tokio::test]
async fn slow_headers_are_cut_off() {
    let w = Web::start(Opts::default()).await;
    let addr = custom_server(&w, opts(8, 500), |_| {}).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    // Headers never complete (no final CRLF): slowloris.
    s.write_all(b"GET /healthz HTTP/1.1\r\nHost: secretd.test\r\n")
        .await
        .unwrap();
    assert!(!closed_within(&mut s, 100).await, "not closed instantly");
    let t0 = Instant::now();
    assert!(
        closed_within(&mut s, 3_000).await,
        "header timeout closes it"
    );
    assert!(t0.elapsed() < Duration::from_secs(3));
    // An idle connection that never sends anything is dropped too.
    let mut idle = TcpStream::connect(addr).await.unwrap();
    assert!(closed_within(&mut idle, 3_000).await);
}

#[tokio::test]
async fn stalled_request_body_times_out_with_408() {
    let w = Web::start(Opts::default()).await;
    let addr = custom_server(&w, opts(8, 5_000), |c| c.request_timeout_secs = 1).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let id = "0123456789abcdef0123456789abcdef";
    // Complete headers announcing 50 body bytes, of which only 5 arrive.
    s.write_all(
        format!(
            "POST /approve/{id} HTTP/1.1\r\nHost: secretd.test\r\n\
             Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 50\r\n\r\nt=abc"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    let r = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if String::from_utf8_lossy(&out).contains("\r\n\r\n") {
                        break;
                    }
                }
            }
        }
    })
    .await;
    assert!(r.is_ok(), "server never answered the stalled request");
    assert!(
        String::from_utf8_lossy(&out).starts_with("HTTP/1.1 408"),
        "{}",
        String::from_utf8_lossy(&out)
    );
}

#[tokio::test]
async fn login_starts_are_rate_limited_per_ip() {
    let w = Web::start(Opts::default()).await;
    let addr = custom_server(&w, ServeOpts::default(), |c| c.max_login_starts_per_min = 3).await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();
    let start = |xff: &'static str| {
        let client = client.clone();
        async move {
            client
                .get(format!("http://{addr}/auth/login"))
                .header("Host", "secretd.test")
                .header("X-Forwarded-For", xff)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    // Every start counts, completed or not.
    for _ in 0..3 {
        assert_eq!(start("203.0.113.7").await, 303);
    }
    assert_eq!(start("203.0.113.7").await, 429);
    assert_eq!(start("203.0.113.7").await, 429);
    // Other addresses have their own budget.
    assert_eq!(start("203.0.113.8").await, 303);
    let raw = w.h.audit_raw();
    assert!(raw.contains("http_login_rate"));
}

#[tokio::test]
async fn token_mismatch_on_post_is_audited_like_on_get() {
    let w = Web::start(Opts::default()).await;
    let (_conn, n) = w.start_get("db-password").await;
    let id_path = format!("/approve/{}", n.request_id);
    let r = w
        .post_form(
            &id_path,
            None,
            &[
                ("t", "wrong-token-value"),
                ("action", "deny"),
                ("csrf", "x"),
            ],
        )
        .await;
    assert_eq!(r.status, 403);
    let n_bad =
        w.h.audit_lines()
            .iter()
            .filter(|l| l["event"] == "admin_action" && l["outcome"] == "bad_approval_token")
            .count();
    assert_eq!(n_bad, 1, "POST mismatch must be audited");
    // GET still is.
    let r = w.get(&format!("{id_path}?t=wrong-token-value"), None).await;
    assert_eq!(r.status, 403);
    let n_bad =
        w.h.audit_lines()
            .iter()
            .filter(|l| l["outcome"] == "bad_approval_token")
            .count();
    assert_eq!(n_bad, 2);
}

#[tokio::test]
async fn ipv6_external_url_host_matching() {
    let w = Web::start(Opts {
        external_url: "https://[::1]:8443".into(),
        ..Opts::default()
    })
    .await;
    let id = "0123456789abcdef0123456789abcdef";
    let path = format!("/approve/{id}?t=abcdef");
    // Any spelling of the configured address is accepted: unknown request -> 410,
    // not 400 "bad host".
    for host in ["[::1]:8443", "[0:0:0:0:0:0:0:1]:8443", "[0000::1]:8443"] {
        let r = w.req("GET", &path, None, &[("Host", host)], None).await;
        assert_eq!(r.status, 410, "Host {host}");
    }
    for host in ["[::1]:9999", "[::2]:8443", "::1:8443", "evil.example"] {
        let r = w.req("GET", &path, None, &[("Host", host)], None).await;
        assert_eq!(r.status, 400, "Host {host}");
    }
}
