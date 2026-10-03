mod common;
use common::mock::*;
use common::web::*;
use common::*;
use secret_proto::config::OidcCfg;
use secretd::oidc::{OidcClient, OidcError};
use serde_json::{json, Value};

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

struct Direct {
    mock: MockOidc,
    client: OidcClient,
    n: std::sync::atomic::AtomicU32,
}

impl Direct {
    async fn new() -> Direct {
        let mock = MockOidc::start().await;
        let cfg = OidcCfg {
            issuer: mock.issuer.clone(),
            client_id: CLIENT_ID.into(),
            client_secret_file: "/nonexistent".into(),
            redirect_url: "https://secretd.test/auth/callback".into(),
            owner_emails: vec!["owner@example.com".into()],
            session_ttl_secs: 3600,
        };
        let client = OidcClient::new(cfg, pw("s")).unwrap();
        Direct {
            mock,
            client,
            n: Default::default(),
        }
    }

    /// Run start() + complete() with an ID token produced by `edit`.
    async fn attempt(
        &self,
        edit: impl FnOnce(&mut Value),
        bad_signature: bool,
    ) -> Result<secretd::oidc::Identity, OidcError> {
        let req = self.client.start().await.unwrap();
        let code = format!(
            "c{}",
            self.n.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        );
        let mut claims = self.mock.claims(&req.nonce);
        edit(&mut claims);
        self.mock.plan(&code, claims, bad_signature);
        self.client
            .complete(&code, &req.pkce_verifier, &req.nonce)
            .await
    }
}

#[tokio::test]
async fn accepts_valid_token_and_records_amr() {
    let d = Direct::new().await;
    let id = d
        .attempt(|c| c["email"] = json!("Owner@Example.COM"), false)
        .await
        .unwrap();
    assert_eq!(id.email, "owner@example.com");
    assert_eq!(id.amr.as_deref(), Some("pwd,hwk"));
    // Works without an amr claim as well.
    let id = d
        .attempt(
            |c| {
                c.as_object_mut().unwrap().remove("amr");
            },
            false,
        )
        .await
        .unwrap();
    assert_eq!(id.amr, None);
}

#[tokio::test]
async fn authorization_request_shape() {
    let d = Direct::new().await;
    let r = d.client.start().await.unwrap();
    let u = url::Url::parse(&r.url).unwrap();
    let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["state"], r.state);
    assert_eq!(q["nonce"], r.nonce);
    assert_eq!(q["code_challenge_method"], "S256");
    assert!(q.contains_key("code_challenge"));
    assert!(!q.contains_key("prompt") && !q.contains_key("max_age"));
    assert!(!q.contains_key("access_type"), "no offline access");
    assert_eq!(q["scope"], "openid email");
}

#[tokio::test]
async fn rejects_bad_signature() {
    let d = Direct::new().await;
    assert_eq!(
        d.attempt(|_| {}, true).await.unwrap_err(),
        OidcError::Verification
    );
}

#[tokio::test]
async fn rejects_wrong_audience_and_issuer() {
    let d = Direct::new().await;
    assert_eq!(
        d.attempt(|c| c["aud"] = json!("someone-else"), false)
            .await
            .unwrap_err(),
        OidcError::Verification
    );
    assert_eq!(
        d.attempt(|c| c["aud"] = json!(["someone-else", "another"]), false)
            .await
            .unwrap_err(),
        OidcError::Verification
    );
    assert_eq!(
        d.attempt(|c| c["iss"] = json!("https://evil.example"), false)
            .await
            .unwrap_err(),
        OidcError::Verification
    );
}

#[tokio::test]
async fn rejects_expired_token() {
    let d = Direct::new().await;
    assert_eq!(
        d.attempt(|c| c["exp"] = json!(now() - 3600), false)
            .await
            .unwrap_err(),
        OidcError::Verification
    );
}

#[tokio::test]
async fn rejects_wrong_or_missing_nonce() {
    let d = Direct::new().await;
    assert_eq!(
        d.attempt(|c| c["nonce"] = json!("not-the-nonce"), false)
            .await
            .unwrap_err(),
        OidcError::Verification
    );
    assert_eq!(
        d.attempt(
            |c| {
                c.as_object_mut().unwrap().remove("nonce");
            },
            false
        )
        .await
        .unwrap_err(),
        OidcError::Verification
    );
}

#[tokio::test]
async fn rejects_unverified_missing_and_unlisted_email() {
    let d = Direct::new().await;
    assert_eq!(
        d.attempt(|c| c["email_verified"] = json!(false), false)
            .await
            .unwrap_err(),
        OidcError::EmailUnverified
    );
    assert_eq!(
        d.attempt(
            |c| {
                c.as_object_mut().unwrap().remove("email_verified");
            },
            false
        )
        .await
        .unwrap_err(),
        OidcError::EmailUnverified
    );
    assert_eq!(
        d.attempt(|c| c["email"] = json!("mallory@example.com"), false)
            .await
            .unwrap_err(),
        OidcError::NotAllowed
    );
    assert_eq!(
        d.attempt(
            |c| {
                c.as_object_mut().unwrap().remove("email");
            },
            false
        )
        .await
        .unwrap_err(),
        OidcError::NoEmail
    );
    // Exact match only: no suffix/prefix tricks, and `hd` alone is never enough.
    assert_eq!(
        d.attempt(|c| c["email"] = json!("owner@example.com.evil.test"), false)
            .await
            .unwrap_err(),
        OidcError::NotAllowed
    );
    assert_eq!(
        d.attempt(
            |c| {
                c["email"] = json!("mallory@example.com");
                c["hd"] = json!("example.com");
            },
            false
        )
        .await
        .unwrap_err(),
        OidcError::NotAllowed
    );
}

#[tokio::test]
async fn unknown_code_fails_exchange() {
    let d = Direct::new().await;
    let r = d.client.start().await.unwrap();
    assert_eq!(
        d.client
            .complete("nope", &r.pkce_verifier, &r.nonce)
            .await
            .unwrap_err(),
        OidcError::Exchange
    );
}

#[tokio::test]
async fn provider_down_is_reported() {
    let cfg = OidcCfg {
        issuer: "http://127.0.0.1:1".into(),
        client_id: "x".into(),
        client_secret_file: "/x".into(),
        redirect_url: "https://secretd.test/auth/callback".into(),
        owner_emails: vec!["a@b.c".into()],
        session_ttl_secs: 10,
    };
    let c = OidcClient::new(cfg, pw("s")).unwrap();
    assert!(matches!(c.start().await, Err(OidcError::Provider)));
}

// ---------------------------------------------------- HTTP-level behaviour

#[tokio::test]
async fn non_allowlisted_email_gets_generic_403_and_audit_event() {
    let w = Web::start(Opts::default()).await;
    let (r, sess) = w
        .login_with(None, |c| c["email"] = json!("mallory@example.com"), false)
        .await;
    assert_eq!(r.status, 403);
    assert!(sess.is_none(), "no session cookie on rejection");
    assert!(!r.body.contains("mallory") && !r.body.contains("allow"));
    let ev = w.h.audit_lines();
    let e = ev
        .iter()
        .find(|v| v["event"] == "admin_action" && v["outcome"] == "oidc_rejected")
        .expect("audit event");
    assert_eq!(e["detail"], "email_not_allowed");
}

#[tokio::test]
async fn bad_tokens_never_create_a_session() {
    let w = Web::start(Opts::default()).await;
    let (r, s) = w.login_with(None, |_| {}, true).await;
    assert_eq!((r.status, s), (403, None));
    let (r, s) = w
        .login_with(None, |c| c["email_verified"] = json!(false), false)
        .await;
    assert_eq!((r.status, s), (403, None));
    let (r, s) = w.login_with(None, |c| c["aud"] = json!("x"), false).await;
    assert_eq!((r.status, s), (403, None));
}

#[tokio::test]
async fn missing_forged_and_expired_sessions_are_not_accepted() {
    let w = Web::start(Opts {
        session_ttl_secs: 1,
        ..Opts::default()
    })
    .await;
    let (_conn, n) = w.start_get("db-password").await;
    let path = path_of(&n.approval_url);

    // missing
    assert_eq!(w.get(&path, None).await.status, 303);
    // forged
    assert_eq!(
        w.get(&path, Some("__Host-sd_session=forged")).await.status,
        303
    );
    // valid, then expired (absolute expiry)
    let sess = w.login(None).await;
    assert_eq!(w.get(&path, Some(&sess)).await.status, 200);
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let r = w.get(&path, Some(&sess)).await;
    assert_eq!(r.status, 303, "expired session must redirect to login");
    assert!(r.header("location").unwrap().starts_with("/auth/login"));
    // POST with an expired session does not act either.
    let r = w
        .post_form(
            &format!("/approve/{}", n.request_id),
            Some(&sess),
            &[
                ("t", &token_of(&n.approval_url)),
                ("csrf", "x"),
                ("action", "deny"),
            ],
        )
        .await;
    assert_eq!(r.status, 303);
    assert_eq!(w.h.core.pending_count(), 1);
}

#[tokio::test]
async fn session_is_reused_across_requests_without_relogin() {
    let w = Web::start(Opts::default()).await;
    let sess = w.login(None).await;
    for name in ["db-password", "second"] {
        let (mut conn, n) = w.start_get(name).await;
        let path = path_of(&n.approval_url);
        // Same session, no new OIDC round trip (the mock saw exactly one token request).
        assert_eq!(w.get(&path, Some(&sess)).await.status, 200);
        w.h.core.deny(&n.request_id, secretd::core::Source::Admin);
        let _ = conn.recv().await;
    }
    assert_eq!(w.oidc.state.token_requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn session_cookie_attributes() {
    let w = Web::start(Opts::default()).await;
    let (r, _) = w.login_with(None, |_| {}, false).await;
    let c = r
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("__Host-sd_session="))
        .unwrap();
    for a in [
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=3600",
    ] {
        assert!(c.contains(a), "{c} lacks {a}");
    }
    assert!(!c.contains("Domain"));
}

#[tokio::test]
async fn state_must_match_browser_and_is_single_use() {
    let w = Web::start(Opts::default()).await;
    // Start a login to get a valid state + cookie.
    let r = w.get("/auth/login", None).await;
    let loc = url::Url::parse(&r.header("location").unwrap()).unwrap();
    let q: std::collections::HashMap<String, String> = loc.query_pairs().into_owned().collect();
    let cookie = r.cookie("__Host-sd_login").unwrap();
    w.oidc.plan("c1", w.oidc.claims(&q["nonce"]), false);
    // Callback without the login cookie (different browser) is refused...
    let cb = format!("/auth/callback?code=c1&state={}", q["state"]);
    assert_eq!(w.get(&cb, None).await.status, 403);
    // ...and burns the state: even with the right cookie it cannot be replayed.
    assert_eq!(w.get(&cb, Some(&cookie)).await.status, 403);
    // Unknown state / missing params.
    assert_eq!(
        w.get(
            "/auth/callback?code=c1&state=bogus",
            Some("__Host-sd_login=bogus")
        )
        .await
        .status,
        403
    );
    assert_eq!(w.get("/auth/callback", None).await.status, 403);
    assert_eq!(
        w.get("/auth/callback?error=access_denied&state=x", None)
            .await
            .status,
        403
    );
}

#[tokio::test]
async fn login_next_must_be_an_approval_path() {
    let w = Web::start(Opts::default()).await;
    for bad in [
        "https://evil.example/",
        "//evil.example",
        "/approve/zz?t=a",
        "/other",
    ] {
        let r = w
            .get(
                &format!(
                    "/auth/login?next={}",
                    url::form_urlencoded::byte_serialize(bad.as_bytes()).collect::<String>()
                ),
                None,
            )
            .await;
        assert_eq!(r.status, 400, "{bad}");
    }
}

#[tokio::test]
async fn login_when_provider_down_is_502() {
    let w = Web::start(Opts {
        oidc_issuer: "http://127.0.0.1:1".into(),
        ..Opts::default()
    })
    .await;
    // Web::start overrides the issuer with the mock; build a dead client instead.
    let dead = std::sync::Arc::new(
        OidcClient::new(
            secret_proto::config::OidcCfg {
                issuer: "http://127.0.0.1:1".into(),
                ..w.h.cfg.approval.oidc.clone()
            },
            pw("s"),
        )
        .unwrap(),
    );
    let app = secretd::approval::router(w.h.core.clone(), w.h.cfg.approval.clone(), dead);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = secretd::approval::serve(l, app).await;
    });
    let c = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();
    let r = c
        .get(format!("http://{addr}/auth/login"))
        .header("Host", "secretd.test")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 502);
}
