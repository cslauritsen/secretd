#![allow(dead_code)]
//! Harness for the HTTP approval endpoint: daemon core + approval server on
//! an ephemeral loopback port + mock ntfy + mock OIDC provider.

use super::mock::{MockNtfy, MockOidc};
use super::*;
use secretd::approval;
use secretd::notify_http::HttpNotifier;
use secretd::oidc::OidcClient;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};

pub struct Web {
    pub h: Harness,
    pub addr: SocketAddr,
    pub ntfy: MockNtfy,
    pub oidc: MockOidc,
    pub oidc_client: Arc<OidcClient>,
    http: reqwest::Client,
    codes: AtomicU32,
}

#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    pub body: String,
}

impl Resp {
    pub fn header(&self, n: &str) -> Option<String> {
        self.headers.get(n).map(|v| v.to_str().unwrap().to_string())
    }
    pub fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }
    /// Value of a named cookie set by this response ("name=value" form).
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.set_cookies().into_iter().find_map(|c| {
            let first = c.split(';').next()?.to_string();
            first.starts_with(&format!("{name}=")).then_some(first)
        })
    }
}

impl Web {
    pub async fn start(mut o: Opts) -> Web {
        Self::start_with(&mut o, 0).await
    }

    pub async fn start_with(o: &mut Opts, ntfy_fail_first: u32) -> Web {
        let ntfy = MockNtfy::start(ntfy_fail_first).await;
        let oidc = MockOidc::start().await;
        o.notify_url = ntfy.url.clone();
        o.oidc_issuer = oidc.issuer.clone();
        let opts = Opts {
            extra: std::mem::take(&mut o.extra),
            limits: std::mem::take(&mut o.limits),
            timeout_secs: o.timeout_secs,
            notifier: o.notifier.take(),
            channels: o.channels.take(),
            notifier_from_cfg: Some(Box::new(|cfg: &Config| {
                Arc::new(HttpNotifier::new(cfg.notify.as_ref().unwrap()).unwrap())
                    as Arc<dyn Notifier>
            })),
            audit_writer: o.audit_writer.take(),
            peer: o.peer.take(),
            procs: o.procs.take(),
            notify_url: o.notify_url.clone(),
            oidc_issuer: o.oidc_issuer.clone(),
            listen: o.listen.clone(),
            external_url: o.external_url.clone(),
            notify_kind: o.notify_kind.clone(),
            notify_extra: std::mem::take(&mut o.notify_extra),
            trusted_proxies: o.trusted_proxies.clone(),
            session_ttl_secs: o.session_ttl_secs,
        };
        let h = Harness::start(opts).await;
        let oidc_client = Arc::new(
            OidcClient::new(
                h.cfg.approval.as_ref().unwrap().oidc.clone(),
                pw("client-secret-value"),
            )
            .unwrap(),
        );
        let app = approval::router(
            h.core.clone(),
            h.cfg.approval.clone().unwrap(),
            oidc_client.clone(),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = approval::serve(l, app).await;
        });
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap();
        Web {
            h,
            addr,
            ntfy,
            oidc,
            oidc_client,
            http,
            codes: AtomicU32::new(1),
        }
    }

    pub async fn req(
        &self,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        extra_headers: &[(&str, &str)],
        body: Option<String>,
    ) -> Resp {
        let url = format!("http://{}{}", self.addr, path);
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let mut r = self.http.request(m, url);
        if !extra_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("host"))
        {
            r = r.header("Host", "secretd.test");
        }
        if let Some(c) = cookie {
            r = r.header("Cookie", c);
        }
        for (k, v) in extra_headers {
            r = r.header(*k, *v);
        }
        if let Some(b) = body {
            r = r
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(b);
        }
        let resp = r.send().await.unwrap();
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = resp.text().await.unwrap();
        Resp {
            status,
            headers,
            body,
        }
    }

    pub async fn get(&self, path: &str, cookie: Option<&str>) -> Resp {
        self.req("GET", path, cookie, &[], None).await
    }

    pub async fn post_form(&self, path: &str, cookie: Option<&str>, form: &[(&str, &str)]) -> Resp {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form.iter().copied())
            .finish();
        self.req("POST", path, cookie, &[], Some(body)).await
    }

    /// Run the whole Google-style login against the mock provider and return
    /// the session cookie ("name=value"). `claims_edit` can alter the ID token.
    pub async fn login_with(
        &self,
        next: Option<&str>,
        claims_edit: impl FnOnce(&mut serde_json::Value),
        bad_signature: bool,
    ) -> (Resp, Option<String>) {
        let path = match next {
            Some(n) => format!(
                "/auth/login?next={}",
                url::form_urlencoded::byte_serialize(n.as_bytes()).collect::<String>()
            ),
            None => "/auth/login".to_string(),
        };
        let r = self.get(&path, None).await;
        assert_eq!(r.status, 303, "login start: {}", r.body);
        let loc = url::Url::parse(&r.header("location").unwrap()).unwrap();
        assert_eq!(loc.path(), "/authorize");
        let q: HashMap<String, String> = loc.query_pairs().into_owned().collect();
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["client_id"], mock::CLIENT_ID);
        assert_eq!(q["code_challenge_method"], "S256");
        assert!(q["scope"].split(' ').any(|s| s == "openid"));
        assert!(q["scope"].split(' ').any(|s| s == "email"));
        assert!(!q.contains_key("prompt"));
        assert!(!q.contains_key("max_age"));
        assert_eq!(q["redirect_uri"], "https://secretd.test/auth/callback");
        let login_cookie = r.cookie("__Host-sd_login").expect("login cookie");
        let n = self.codes.fetch_add(1, Ordering::SeqCst);
        let code = format!("code-{n}");
        let mut claims = self.oidc.claims(&q["nonce"]);
        claims_edit(&mut claims);
        self.oidc.plan(&code, claims, bad_signature);
        let cb = self
            .get(
                &format!(
                    "/auth/callback?code={code}&state={}",
                    url::form_urlencoded::byte_serialize(q["state"].as_bytes()).collect::<String>()
                ),
                Some(&login_cookie),
            )
            .await;
        if cb.status == 303 || cb.status == 200 {
            // PKCE: the verifier the daemon sent must hash to the challenge it offered.
            use base64::Engine;
            use sha2::Digest;
            let tr = self.oidc.last_token_request();
            let verifier = &tr["code_verifier"];
            let want = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(verifier.as_bytes()));
            assert_eq!(want, q["code_challenge"]);
            assert_eq!(tr["grant_type"], "authorization_code");
        }
        let sess = cb.cookie("__Host-sd_session");
        (cb, sess)
    }

    pub async fn login(&self, next: Option<&str>) -> String {
        let (r, s) = self.login_with(next, |_| {}, false).await;
        assert!(r.status == 303 || r.status == 200, "login failed: {r:?}");
        s.expect("session cookie")
    }

    /// Start a `secret.get` on a fresh connection; returns the connection and
    /// the notification once delivered.
    pub async fn start_get(&self, name: &str) -> (Conn, secretd::notify::Notification) {
        let mut c = self.h.connect().await;
        c.send("secret.get", json!({"name": name, "reason": "tests"}))
            .await;
        let before = self.pending_notifications();
        let n = self.wait_new_notification(before).await;
        (c, n)
    }

    fn pending_notifications(&self) -> usize {
        self.ntfy.received().len()
    }

    async fn wait_new_notification(&self, before: usize) -> secretd::notify::Notification {
        // Notifications go to the mock ntfy; reconstruct the id/url from the Click header.
        for _ in 0..500 {
            let r = self.ntfy.received();
            if r.len() > before {
                let last = r.last().unwrap();
                let click = match last.header("click") {
                    Some(c) => c.to_string(),
                    None => {
                        let v: serde_json::Value = serde_json::from_slice(&last.body).unwrap();
                        v["approval_url"].as_str().unwrap().to_string()
                    }
                };
                return notification_from_click(&click);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("no notification reached the mock ntfy");
    }
}

pub fn notification_from_click(click: &str) -> secretd::notify::Notification {
    let u = url::Url::parse(click).unwrap();
    let id = u.path().trim_start_matches("/approve/").to_string();
    secretd::notify::Notification {
        request_id: id,
        secret_name: String::new(),
        description: None,
        uid: 0,
        username: String::new(),
        pid: 0,
        exe: String::new(),
        cmdline: String::new(),
        reason: None,
        expires_at: String::new(),
        approval_url: click.to_string(),
        approval_token: String::new(),
    }
}

/// `/approve/ID?t=TOKEN` (path and query) from a full approval URL.
pub fn path_of(approval_url: &str) -> String {
    let u = url::Url::parse(approval_url).unwrap();
    format!("{}?{}", u.path(), u.query().unwrap())
}

pub fn token_of(approval_url: &str) -> String {
    let u = url::Url::parse(approval_url).unwrap();
    u.query_pairs()
        .find(|(k, _)| k == "t")
        .unwrap()
        .1
        .into_owned()
}

pub fn csrf_of(html: &str) -> String {
    let marker = "name=\"csrf\" value=\"";
    let i = html.find(marker).expect("csrf field") + marker.len();
    html[i..i + html[i..].find('"').unwrap()].to_string()
}
