mod common;
use common::web::*;
use common::*;
use hmac::Mac;
use secret_proto::GetResult;
use serde_json::json;

async fn approve_form(
    w: &Web,
    path: &str,
    sess: &str,
    token: &str,
    id_for_csrf_page: &str,
    action: &str,
    pass: &str,
) -> Resp {
    let page = w.get(id_for_csrf_page, Some(sess)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    let csrf = csrf_of(&page.body);
    w.post_form(
        path,
        Some(sess),
        &[
            ("t", token),
            ("csrf", &csrf),
            ("action", action),
            ("passphrase", pass),
        ],
    )
    .await
}

fn id_path(n: &secretd::notify::Notification) -> String {
    format!("/approve/{}", n.request_id)
}

#[tokio::test]
async fn approve_flow_end_to_end() {
    let w = Web::start(Opts::default()).await;
    let (mut conn, n) = w.start_get("db-password").await;

    // The push notification: headers and plain-text body, no secret or key.
    let got = w.ntfy.received();
    assert_eq!(got.len(), 1);
    let m = &got[0];
    assert_eq!(m.header("title"), Some("Secret request: db-password"));
    assert_eq!(m.header("priority"), Some("high"));
    assert_eq!(m.header("click"), Some(n.approval_url.as_str()));
    assert_eq!(m.header("authorization"), Some("Bearer ntfy-token-value"));
    let body = m.text();
    assert!(body.contains("Secret: db-password (Primary DB password)"));
    assert!(body.contains("uid 1000"));
    assert!(body.contains("Executable: /opt/test/bin/psql"));
    assert!(body.contains("Command line: psql -h db"));
    assert!(body.contains("Reason (client-supplied, untrusted): tests"));
    assert!(body.contains(&n.approval_url));
    assert!(!body.contains("hunter2"));
    assert!(!body.contains(PASS));

    let path = path_of(&n.approval_url);
    let token = token_of(&n.approval_url);
    // No session: redirected into the OIDC login flow.
    let r = w.get(&path, None).await;
    assert_eq!(r.status, 303);
    assert!(r
        .header("location")
        .unwrap()
        .starts_with("/auth/login?next="));

    // Sign in via the mock provider; we land back on the approval page.
    let (cb, sess) = w.login_with(Some(&path), |_| {}, false).await;
    assert_eq!(cb.status, 303);
    assert_eq!(cb.header("location").unwrap(), path);
    let sess = sess.unwrap();
    let c = cb.set_cookies().join("\n");
    assert!(c.contains("HttpOnly") && c.contains("Secure") && c.contains("SameSite=Lax"));

    let page = w.get(&path, Some(&sess)).await;
    assert_eq!(page.status, 200);
    for want in [
        "db-password",
        "/opt/test/bin/psql",
        "psql -h db",
        "client-supplied, untrusted",
        "Primary DB password",
        "type=\"password\"",
    ] {
        assert!(page.body.contains(want), "missing {want}");
    }
    assert_eq!(page.header("cache-control").as_deref(), Some("no-store"));
    assert_eq!(
        page.header("referrer-policy").as_deref(),
        Some("no-referrer")
    );
    assert_eq!(page.header("x-frame-options").as_deref(), Some("DENY"));
    let csp = page.header("content-security-policy").unwrap();
    assert!(csp.contains("default-src 'none'") && csp.contains("frame-ancestors 'none'"));
    assert!(!csp.contains("unsafe-inline"));

    let csrf = csrf_of(&page.body);
    let post = w
        .post_form(
            &id_path(&n),
            Some(&sess),
            &[
                ("t", &token),
                ("csrf", &csrf),
                ("action", "approve"),
                ("passphrase", PASS),
            ],
        )
        .await;
    assert_eq!(post.status, 200, "{}", post.body);
    assert!(post.body.contains("released"));

    let resp = conn.recv().await.unwrap();
    let g: GetResult = serde_json::from_value(resp.result.unwrap()).unwrap();
    assert_eq!(g.value, "hunter2-secret-value");

    // Single use: the same URL is now gone, and a replayed POST is rejected.
    assert_eq!(w.get(&path, Some(&sess)).await.status, 410);
    let replay = w
        .post_form(
            &id_path(&n),
            Some(&sess),
            &[
                ("t", &token),
                ("csrf", &csrf),
                ("action", "approve"),
                ("passphrase", PASS),
            ],
        )
        .await;
    assert_eq!(replay.status, 410);

    // Audit trail has the expected events and no secrets/tokens/passphrases.
    let ev = w.h.audit_events();
    for want in [
        "request_received",
        "notified",
        "approved",
        "released",
        "admin_action",
    ] {
        assert!(
            ev.contains(&want.to_string()),
            "missing audit event {want}: {ev:?}"
        );
    }
    let raw = w.h.audit_raw();
    for bad in [
        "hunter2",
        PASS,
        &token,
        "ntfy-token-value",
        "client-secret-value",
        "tests",
    ] {
        assert!(!raw.contains(bad), "audit log leaked {bad:?}");
    }
    let released =
        w.h.audit_lines()
            .into_iter()
            .find(|v| v["event"] == "released")
            .unwrap();
    assert_eq!(released["secret_name"], "db-password");
    assert_eq!(released["uid"], 1000);
    assert_eq!(released["exe"], PSQL);
    assert_eq!(released["source_ip"], "127.0.0.1");
}

#[tokio::test]
async fn deny_returns_denied() {
    let w = Web::start(Opts::default()).await;
    let (mut conn, n) = w.start_get("db-password").await;
    let sess = w.login(None).await;
    let r = approve_form(
        &w,
        &id_path(&n),
        &sess,
        &token_of(&n.approval_url),
        &path_of(&n.approval_url),
        "deny",
        "",
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(err_kind(&conn.recv().await.unwrap()), "DENIED");
    assert!(w.h.audit_events().contains(&"denied".to_string()));
    assert_eq!(
        w.get(&path_of(&n.approval_url), Some(&sess)).await.status,
        410
    );
}

#[tokio::test]
async fn timeout_returns_timeout_and_expires_url() {
    let w = Web::start(Opts::default()).await;
    let mut conn = w.h.connect().await;
    conn.send(
        "secret.get",
        json!({"name": "db-password", "timeout_secs": 1}),
    )
    .await;
    let n = w.h.notifier.count(); // recording notifier unused here; use ntfy
    let _ = n;
    for _ in 0..200 {
        if !w.ntfy.received().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let click = w.ntfy.received()[0].header("click").unwrap().to_string();
    let sess = w.login(None).await;
    assert_eq!(err_kind(&conn.recv().await.unwrap()), "TIMEOUT");
    assert_eq!(w.get(&path_of(&click), Some(&sess)).await.status, 410);
    assert!(w.h.audit_events().contains(&"timeout".to_string()));
    assert_eq!(w.h.core.pending_count(), 0);
}

#[tokio::test]
async fn wrong_passphrase_retry_limit() {
    let w = Web::start(Opts::default()).await;
    let (mut conn, n) = w.start_get("db-password").await;
    let sess = w.login(None).await;
    let (path, token) = (path_of(&n.approval_url), token_of(&n.approval_url));
    let r1 = approve_form(&w, &id_path(&n), &sess, &token, &path, "approve", "nope-1").await;
    assert_eq!(r1.status, 200);
    assert!(r1
        .body
        .contains("Wrong passphrase. 2 of 3 attempts remaining."));
    // The client is still waiting; DECRYPT_FAILED is only sent on final failure.
    let r2 = approve_form(&w, &id_path(&n), &sess, &token, &path, "approve", "nope-2").await;
    assert!(r2.body.contains("1 of 3 attempts remaining"));
    assert_eq!(w.h.core.pending_count(), 1);
    let r3 = approve_form(&w, &id_path(&n), &sess, &token, &path, "approve", "nope-3").await;
    assert_eq!(r3.status, 403);
    assert_eq!(err_kind(&conn.recv().await.unwrap()), "DECRYPT_FAILED");
    assert_eq!(w.get(&path, Some(&sess)).await.status, 410);
    let ev = w.h.audit_lines();
    let fails: Vec<_> = ev
        .iter()
        .filter(|v| v["event"] == "decrypt_failed")
        .collect();
    assert_eq!(fails.len(), 3);
    assert_eq!(fails[2]["outcome"], "final");
    let raw = w.h.audit_raw();
    for bad in ["nope-1", "nope-2", "nope-3"] {
        assert!(!raw.contains(bad));
    }
}

#[tokio::test]
async fn retry_then_correct_passphrase_releases() {
    let w = Web::start(Opts::default()).await;
    let (mut conn, n) = w.start_get("db-password").await;
    let sess = w.login(None).await;
    let (path, token) = (path_of(&n.approval_url), token_of(&n.approval_url));
    let r1 = approve_form(&w, &id_path(&n), &sess, &token, &path, "approve", "bad").await;
    assert!(r1.body.contains("attempts remaining"));
    let r2 = approve_form(&w, &id_path(&n), &sess, &token, &path, "approve", PASS).await;
    assert_eq!(r2.status, 200);
    let g: GetResult = serde_json::from_value(conn.recv().await.unwrap().result.unwrap()).unwrap();
    assert_eq!(g.value, "hunter2-secret-value");
}

#[tokio::test]
async fn client_disconnect_cancels_and_invalidates_url() {
    let w = Web::start(Opts::default()).await;
    let (conn, n) = w.start_get("db-password").await;
    let sess = w.login(None).await;
    let path = path_of(&n.approval_url);
    assert_eq!(w.get(&path, Some(&sess)).await.status, 200);
    drop(conn);
    let mut status = 0;
    for _ in 0..200 {
        status = w.get(&path, Some(&sess)).await.status;
        if status == 410 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(status, 410);
    assert_eq!(w.h.core.pending_count(), 0);
    assert!(w
        .h
        .audit_events()
        .contains(&"client_disconnected".to_string()));
}

#[tokio::test]
async fn wrong_or_missing_token_is_rejected() {
    let w = Web::start(Opts::default()).await;
    let (mut conn, n) = w.start_get("db-password").await;
    let sess = w.login(None).await;
    let r = w
        .get(
            &format!(
                "{}?t=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                id_path(&n)
            ),
            Some(&sess),
        )
        .await;
    assert_eq!(r.status, 403);
    let r = w.get(&id_path(&n), Some(&sess)).await; // no token at all
    assert_eq!(r.status, 410);
    let r = w
        .get(
            "/approve/00000000000000000000000000000000?t=abc",
            Some(&sess),
        )
        .await;
    assert_eq!(r.status, 410);
    // The real token still works (nothing was consumed by the failures).
    assert_eq!(
        w.get(&path_of(&n.approval_url), Some(&sess)).await.status,
        200
    );
    w.h.core.deny(&n.request_id, secretd::core::Source::Admin);
    assert_eq!(err_kind(&conn.recv().await.unwrap()), "DENIED");
}

#[tokio::test]
async fn host_header_must_match_external_url() {
    let w = Web::start(Opts::default()).await;
    let r = w
        .req("GET", "/approve/x", None, &[("Host", "evil.example")], None)
        .await;
    assert_eq!(r.status, 400);
    let r = w
        .req(
            "GET",
            "/auth/login",
            None,
            &[("Host", "secretd.test:1234")],
            None,
        )
        .await;
    assert_eq!(r.status, 400);
    // /healthz is unauthenticated and returns just "ok".
    let r = w
        .req("GET", "/healthz", None, &[("Host", "127.0.0.1")], None)
        .await;
    assert_eq!((r.status, r.body.as_str()), (200, "ok"));
    let r = w.get("/healthz", None).await;
    assert_eq!(r.body, "ok");
    assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));
    // Unknown routes are 404.
    assert_eq!(w.get("/anything", None).await.status, 404);
}

#[tokio::test]
async fn csrf_is_required_and_bound_to_request_and_session() {
    let w = Web::start(Opts::default()).await;
    let (mut c1, n1) = w.start_get("db-password").await;
    let (mut c2, n2) = w.start_get("second").await;
    let sess = w.login(None).await;
    let (t1, t2) = (token_of(&n1.approval_url), token_of(&n2.approval_url));
    let page1 = w.get(&path_of(&n1.approval_url), Some(&sess)).await;
    let csrf1 = csrf_of(&page1.body);
    // Missing and bogus csrf.
    let r = w
        .post_form(
            &id_path(&n1),
            Some(&sess),
            &[("t", &t1), ("action", "approve"), ("passphrase", PASS)],
        )
        .await;
    assert_eq!(r.status, 403);
    let r = w
        .post_form(
            &id_path(&n1),
            Some(&sess),
            &[
                ("t", &t1),
                ("csrf", "00"),
                ("action", "approve"),
                ("passphrase", PASS),
            ],
        )
        .await;
    assert_eq!(r.status, 403);
    // csrf issued for request 1 is not valid for request 2.
    let r = w
        .post_form(
            &id_path(&n2),
            Some(&sess),
            &[
                ("t", &t2),
                ("csrf", &csrf1),
                ("action", "approve"),
                ("passphrase", PASS),
            ],
        )
        .await;
    assert_eq!(r.status, 403);
    // ... nor in a different session.
    let sess2 = w.login(None).await;
    let r = w
        .post_form(
            &id_path(&n1),
            Some(&sess2),
            &[
                ("t", &t1),
                ("csrf", &csrf1),
                ("action", "approve"),
                ("passphrase", PASS),
            ],
        )
        .await;
    assert_eq!(r.status, 403);
    // Nothing was released.
    assert_eq!(w.h.core.pending_count(), 2);
    // No session at all: bounced to the approval page (and from there to login).
    let r = w
        .post_form(
            &id_path(&n1),
            None,
            &[
                ("t", &t1),
                ("csrf", &csrf1),
                ("action", "approve"),
                ("passphrase", PASS),
            ],
        )
        .await;
    assert_eq!(r.status, 303);
    w.h.core.deny(&n1.request_id, secretd::core::Source::Admin);
    w.h.core.deny(&n2.request_id, secretd::core::Source::Admin);
    let _ = (c1.recv().await, c2.recv().await);
}

#[tokio::test]
async fn failed_attempts_are_rate_limited_per_source_ip() {
    let w = Web::start(Opts::default()).await;
    let bad = "/approve/00000000000000000000000000000000?t=abc";
    for _ in 0..5 {
        assert_eq!(w.get(bad, None).await.status, 410);
    }
    let r = w.get(bad, None).await;
    assert_eq!(r.status, 429);
    assert_eq!(r.header("retry-after").as_deref(), Some("60"));
    // The peer (127.0.0.1) is a trusted proxy, so X-Forwarded-For selects the
    // source: a different client address has its own budget.
    let r = w
        .req(
            "GET",
            bad,
            None,
            &[("X-Forwarded-For", "203.0.113.7")],
            None,
        )
        .await;
    assert_eq!(r.status, 410);
    // Spoofed leading hops do not help: the rightmost untrusted hop is used.
    let r = w
        .req(
            "GET",
            bad,
            None,
            &[("X-Forwarded-For", "198.51.100.1, 127.0.0.1")],
            None,
        )
        .await;
    assert_eq!(r.status, 410);
    assert!(w.h.audit_events().contains(&"rate_limited".to_string()));
    let rl =
        w.h.audit_lines()
            .into_iter()
            .find(|v| v["event"] == "rate_limited")
            .unwrap();
    assert_eq!(rl["source_ip"], "127.0.0.1");
}

#[tokio::test]
async fn forwarded_for_ignored_unless_peer_is_trusted() {
    let w = Web::start(Opts {
        trusted_proxies: "[]".into(),
        ..Opts::default()
    })
    .await;
    let bad = "/approve/00000000000000000000000000000000?t=abc";
    for i in 0..5 {
        let xff = format!("203.0.113.{i}");
        assert_eq!(
            w.req("GET", bad, None, &[("X-Forwarded-For", &xff)], None)
                .await
                .status,
            410
        );
    }
    // All attempts were counted against the TCP peer, so a "new" XFF does not reset it.
    let r = w
        .req(
            "GET",
            bad,
            None,
            &[("X-Forwarded-For", "203.0.113.99")],
            None,
        )
        .await;
    assert_eq!(r.status, 429);
}

#[tokio::test]
async fn audit_source_ip_uses_forwarded_for_from_trusted_proxy() {
    let w = Web::start(Opts::default()).await;
    let (_conn, n) = w.start_get("db-password").await;
    let sess = w.login(None).await;
    let page = w.get(&path_of(&n.approval_url), Some(&sess)).await;
    let csrf = csrf_of(&page.body);
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("t", token_of(&n.approval_url).as_str()),
            ("csrf", csrf.as_str()),
            ("action", "deny"),
        ])
        .finish();
    let r = w
        .req(
            "POST",
            &id_path(&n),
            Some(&sess),
            &[("X-Forwarded-For", "203.0.113.50")],
            Some(body),
        )
        .await;
    assert_eq!(r.status, 200);
    let d =
        w.h.audit_lines()
            .into_iter()
            .find(|v| v["event"] == "denied")
            .unwrap();
    assert_eq!(d["source_ip"], "203.0.113.50");
}

#[tokio::test]
async fn notification_failure_fails_request_with_internal() {
    let mut o = Opts::default();
    let w = Web::start_with(&mut o, u32::MAX).await;
    let mut conn = w.h.connect().await;
    let r = conn.get("db-password").await;
    assert_eq!(err_kind(&r), "INTERNAL");
    assert_eq!(w.ntfy.received().len(), 3, "3 attempts with backoff");
    assert_eq!(w.h.core.pending_count(), 0);
    let ev = w.h.audit_events();
    assert!(ev.contains(&"notify_failed".to_string()));
    assert!(!ev.contains(&"notified".to_string()));
    // The error leaks no details.
    assert!(r.error.unwrap().message == "internal error");
}

#[tokio::test]
async fn notification_retries_then_succeeds() {
    let mut o = Opts::default();
    let w = Web::start_with(&mut o, 2).await;
    let (mut conn, n) = w.start_get("db-password").await;
    for _ in 0..300 {
        if w.ntfy.received().len() >= 3 && w.h.audit_events().contains(&"notified".to_string()) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(w.ntfy.received().len(), 3);
    w.h.core.deny(&n.request_id, secretd::core::Source::Admin);
    assert_eq!(err_kind(&conn.recv().await.unwrap()), "DENIED");
}

#[tokio::test]
async fn webhook_mode_posts_signed_json() {
    let mut o = Opts {
        notify_kind: "webhook".into(),
        ..Opts::default()
    };
    let w = Web::start_with(&mut o, 0).await;
    let (mut conn, n) = w.start_get("db-password").await;
    let m = &w.ntfy.received()[0];
    assert_eq!(m.header("content-type"), Some("application/json"));
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"hmac-key-value").unwrap();
    mac.update(&m.body);
    let want = format!(
        "sha256={}",
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    assert_eq!(m.header("x-secretd-signature"), Some(want.as_str()));
    let v: serde_json::Value = serde_json::from_slice(&m.body).unwrap();
    assert_eq!(v["secret_name"], "db-password");
    assert_eq!(v["caller"]["uid"], 1000);
    assert_eq!(v["caller"]["exe"], PSQL);
    assert_eq!(v["reason"], "tests");
    assert_eq!(v["reason_source"], "client-supplied, untrusted");
    assert_eq!(v["approval_url"], n.approval_url);
    assert!(!m.text().contains("hunter2"));
    w.h.core.deny(&n.request_id, secretd::core::Source::Admin);
    let _ = conn.recv().await;
}

#[tokio::test]
async fn hostile_reason_and_cmdline_are_sanitised() {
    let w = Web::start(Opts::default()).await;
    let mut p = psql_proc();
    p.cmdline = secret_proto::sanitize::clean("psql \u{202E}evil\x1b[2J", 256);
    w.h.procs.set(PID, p);
    let mut conn = w.h.connect().await;
    conn.send(
        "secret.get",
        json!({"name": "db-password", "reason": "<script>alert(1)</script>\n\u{202E}Approve me\u{0}"}),
    )
    .await;
    for _ in 0..200 {
        if !w.ntfy.received().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let m = &w.ntfy.received()[0];
    let body = m.text();
    assert!(!body.contains('\u{202E}') && !body.contains('\x1b') && !body.contains('\0'));
    let click = m.header("click").unwrap().to_string();
    let sess = w.login(None).await;
    let page = w.get(&path_of(&click), Some(&sess)).await;
    assert!(!page.body.contains("<script>"));
    assert!(page.body.contains("&lt;script&gt;"));
    assert!(!page.body.contains('\u{202E}'));
    let n = notification_from_click(&click);
    w.h.core.deny(&n.request_id, secretd::core::Source::Admin);
    let _ = conn.recv().await;
}
