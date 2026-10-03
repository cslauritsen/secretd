//! The owner-facing approval endpoint: plain HTTP (TLS is the reverse
//! proxy's job), Google OIDC session gate, CSRF-protected approve/deny forms.

use crate::audit::AuditEvent;
use crate::core::{ApproveOutcome, Core, DenyOutcome, Source, TokenCheck, MAX_ATTEMPTS};
use crate::oidc::{OidcClient, OidcError};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use hmac::{Hmac, Mac};
use secret_proto::config::ApprovalCfg;
use secret_proto::rpc::PendingInfo;
use secret_proto::sanitize;
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;
use zeroize::Zeroizing;

pub const SESSION_COOKIE: &str = "__Host-sd_session";
pub const LOGIN_COOKIE: &str = "__Host-sd_login";
const LOGIN_TTL: Duration = Duration::from_secs(600);
const MAX_STATES: usize = 1000;

struct Session {
    expires: Instant,
}

struct LoginState {
    pkce_verifier: Zeroizing<String>,
    nonce: String,
    /// Validated `/approve/<id>?t=<token>` to return to.
    next: Option<String>,
    created: Instant,
}

pub struct AppState {
    core: Arc<Core>,
    cfg: ApprovalCfg,
    oidc: Arc<OidcClient>,
    sessions: Mutex<HashMap<String, Session>>,
    logins: Mutex<HashMap<String, LoginState>>,
    failures: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
    csrf_key: [u8; 32],
}

pub fn router(core: Arc<Core>, cfg: ApprovalCfg, oidc: Arc<OidcClient>) -> Router {
    let mut csrf_key = [0u8; 32];
    getrandom::getrandom(&mut csrf_key).expect("OS randomness available");
    let state = Arc::new(AppState {
        core,
        cfg,
        oidc,
        sessions: Mutex::new(HashMap::new()),
        logins: Mutex::new(HashMap::new()),
        failures: Mutex::new(HashMap::new()),
        csrf_key,
    });
    Router::new()
        .route("/healthz", get(healthz))
        .route("/approve/{id}", get(get_approve).post(post_approve))
        .route("/auth/login", get(auth_login))
        .route("/auth/callback", get(auth_callback))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// Serve the router on `listener` until the task is dropped.
pub async fn serve(listener: tokio::net::TcpListener, app: Router) -> std::io::Result<()> {
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

// ------------------------------------------------------------ middleware

const BASE_CSP: &str =
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

async fn guard(State(st): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if path != "/healthz" {
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(str::to_ascii_lowercase);
        if host.as_deref() != Some(&st.cfg.external_host.to_ascii_lowercase()) {
            return with_headers((StatusCode::BAD_REQUEST, "bad host").into_response());
        }
    }
    with_headers(next.run(req).await)
}

fn with_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if !h.contains_key(header::CONTENT_SECURITY_POLICY) {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(BASE_CSP),
        );
    }
    resp
}

// ------------------------------------------------------------- helpers

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn random_b64(n: usize) -> String {
    use base64::Engine;
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("OS randomness available");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// An HTML page with a per-response CSP nonce for its (only) inline style.
fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let nonce = random_b64(16);
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{t}</title><style nonce=\"{n}\">\
body{{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}}\
th{{text-align:left;padding-right:1rem;vertical-align:top}}code{{word-break:break-all}}\
.warn{{background:#fee;border:1px solid #c00;padding:.5rem}}\
.note{{color:#555;font-size:.9rem}}button{{margin:.5rem .5rem 0 0;padding:.4rem 1rem}}\
</style></head><body>{b}</body></html>",
        t = esc(title),
        n = nonce,
        b = body
    );
    let csp = format!(
        "default-src 'none'; style-src 'nonce-{nonce}'; frame-ancestors 'none'; \
base-uri 'none'; form-action 'self'"
    );
    let mut r = (status, html).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    if let Ok(v) = HeaderValue::from_str(&csp) {
        r.headers_mut().insert(header::CONTENT_SECURITY_POLICY, v);
    }
    r
}

fn simple_page(status: StatusCode, title: &str, msg: &str) -> Response {
    page(
        status,
        title,
        &format!("<h1>{}</h1><p>{}</p>", esc(title), esc(msg)),
    )
}

fn redirect(to: &str) -> Response {
    let mut r = StatusCode::SEE_OTHER.into_response();
    if let Ok(v) = HeaderValue::from_str(to) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    r
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for h in headers.get_all(header::COOKIE) {
        let Ok(s) = h.to_str() else { continue };
        for part in s.split(';') {
            if let Some((k, v)) = part.trim().split_once('=') {
                if k == name {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

fn set_cookie(resp: &mut Response, name: &str, value: &str, max_age: u64) {
    let c = format!("{name}={value}; Max-Age={max_age}; Path=/; HttpOnly; Secure; SameSite=Lax");
    if let Ok(v) = HeaderValue::from_str(&c) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_token(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 128
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Parse `/approve/<id>?t=<token>` strictly; returns (id, token).
fn parse_next(next: &str) -> Option<(String, String)> {
    let rest = next.strip_prefix("/approve/")?;
    let (id, q) = rest.split_once("?t=")?;
    (valid_id(id) && valid_token(q)).then(|| (id.to_string(), q.to_string()))
}

fn encode_component(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

impl AppState {
    fn client_ip(&self, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
        let peer_ip = peer.ip();
        let trusted = |ip: IpAddr| self.cfg.trusted_proxies.iter().any(|c| c.contains(ip));
        if !trusted(peer_ip) {
            return peer_ip;
        }
        // Walk X-Forwarded-For from the right, skipping trusted proxies; the
        // first untrusted hop is the client.
        let mut hops: Vec<IpAddr> = Vec::new();
        for h in headers.get_all("x-forwarded-for") {
            if let Ok(s) = h.to_str() {
                hops.extend(s.split(',').filter_map(|p| p.trim().parse::<IpAddr>().ok()));
            }
        }
        for ip in hops.iter().rev() {
            if !trusted(*ip) {
                return *ip;
            }
        }
        hops.first().copied().unwrap_or(peer_ip)
    }

    fn limited(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut f = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let q = f.entry(ip).or_default();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            q.pop_front();
        }
        let limited = q.len() >= self.cfg.max_failed_attempts_per_min as usize;
        if q.is_empty() {
            f.remove(&ip);
        }
        limited
    }

    fn fail(&self, ip: IpAddr) {
        let mut f = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        if f.len() > 10_000 {
            f.clear();
        }
        f.entry(ip).or_default().push_back(Instant::now());
    }

    fn audit(&self, ev: AuditEvent) {
        let _ = self.core.audit(&ev);
    }

    fn rate_limited_response(&self, ip: IpAddr) -> Response {
        self.audit(
            AuditEvent::new("rate_limited")
                .outcome("http_failed_attempts")
                .source(Some(ip)),
        );
        let mut r = simple_page(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts",
            "Too many failed attempts from your address. Try again in a minute.",
        );
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        r
    }

    fn session_id(&self, headers: &HeaderMap) -> Option<String> {
        let sid = cookie_value(headers, SESSION_COOKIE)?;
        let mut s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        match s.get(&sid) {
            Some(sess) if sess.expires > Instant::now() => Some(sid),
            Some(_) => {
                s.remove(&sid);
                None
            }
            None => None,
        }
    }

    fn csrf(&self, sid: &str, request_id: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.csrf_key).expect("any key length");
        mac.update(b"csrf|");
        mac.update(sid.as_bytes());
        mac.update(b"|");
        mac.update(request_id.as_bytes());
        hex(&mac.finalize().into_bytes())
    }

    fn csrf_ok(&self, sid: &str, request_id: &str, given: &str) -> bool {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.csrf_key).expect("any key length");
        mac.update(b"csrf|");
        mac.update(sid.as_bytes());
        mac.update(b"|");
        mac.update(request_id.as_bytes());
        let Some(bytes) = unhex(given) else {
            return false;
        };
        mac.verify_slice(&bytes).is_ok()
    }

    fn login_url(&self, id: &str, token: &str) -> String {
        format!(
            "/auth/login?next={}",
            encode_component(&format!("/approve/{id}?t={token}"))
        )
    }
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
        .collect()
}

// ------------------------------------------------------------- handlers

async fn healthz() -> &'static str {
    "ok"
}

async fn not_found() -> Response {
    simple_page(StatusCode::NOT_FOUND, "Not found", "Nothing here.")
}

fn gone() -> Response {
    simple_page(
        StatusCode::GONE,
        "Request gone",
        "This request has expired, was cancelled, or has already been resolved.",
    )
}

fn approve_page(
    st: &AppState,
    sid: &str,
    info: &PendingInfo,
    description: Option<&str>,
    token: &str,
    error: Option<&str>,
) -> Response {
    let mut b = String::new();
    b.push_str("<h1>Secret release request</h1>");
    if let Some(e) = error {
        b.push_str(&format!("<p class=\"warn\">{}</p>", esc(e)));
    }
    b.push_str("<table>");
    let row = |k: &str, v: &str| format!("<tr><th>{}</th><td>{}</td></tr>", k, v);
    b.push_str(&row(
        "Secret",
        &format!("<code>{}</code>", esc(&info.secret_name)),
    ));
    if let Some(d) = description {
        b.push_str(&row("Description", &esc(&sanitize::clean(d, 200))));
    }
    b.push_str(&row(
        "Caller",
        &format!(
            "uid {} ({}), pid {}",
            info.uid,
            esc(&info.username),
            info.pid
        ),
    ));
    b.push_str(&row(
        "Executable",
        &format!("<code>{}</code>", esc(&info.exe)),
    ));
    b.push_str(&row(
        "Command line",
        &format!("<code>{}</code>", esc(&info.cmdline)),
    ));
    if let Some(r) = &info.reason {
        b.push_str(&row(
            "Reason <span class=\"note\">(client-supplied, untrusted)</span>",
            &esc(r),
        ));
    }
    b.push_str(&row("Expires", &esc(&info.expires_at)));
    b.push_str(&row(
        "Request ID",
        &format!("<code>{}</code>", esc(&info.request_id)),
    ));
    b.push_str("</table>");
    b.push_str(&format!(
        "<form method=\"post\" action=\"/approve/{id}\" autocomplete=\"off\">\
<input type=\"hidden\" name=\"t\" value=\"{t}\">\
<input type=\"hidden\" name=\"csrf\" value=\"{c}\">\
<p><label>Store passphrase <input type=\"password\" name=\"passphrase\" autocomplete=\"off\"></label></p>\
<button type=\"submit\" name=\"action\" value=\"approve\">Approve</button>\
<button type=\"submit\" name=\"action\" value=\"deny\">Deny</button></form>\
<p class=\"note\">Approving releases this one secret once, to the process above. \
The passphrase is required every time.</p>",
        id = esc(&info.request_id),
        t = esc(token),
        c = st.csrf(sid, &info.request_id),
    ));
    page(StatusCode::OK, "Secret release request", &b)
}

async fn get_approve(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let ip = st.client_ip(peer, &headers);
    if st.limited(ip) {
        return st.rate_limited_response(ip);
    }
    let token = q.get("t").cloned().unwrap_or_default();
    if !valid_id(&id) || !valid_token(&token) {
        st.fail(ip);
        return gone();
    }
    match st.core.check_token(&id, &token) {
        TokenCheck::Unknown => {
            st.fail(ip);
            return gone();
        }
        TokenCheck::Mismatch => {
            st.fail(ip);
            st.audit(
                AuditEvent::new("admin_action")
                    .request(&id)
                    .outcome("bad_approval_token")
                    .source(Some(ip)),
            );
            return simple_page(StatusCode::FORBIDDEN, "Forbidden", "Access denied.");
        }
        TokenCheck::Ok => {}
    }
    let Some(sid) = st.session_id(&headers) else {
        return redirect(&st.login_url(&id, &token));
    };
    match st.core.pending_info(&id) {
        Some((info, desc, _remaining)) => {
            approve_page(&st, &sid, &info, desc.as_deref(), &token, None)
        }
        None => gone(),
    }
}

async fn post_approve(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let ip = st.client_ip(peer, &headers);
    if st.limited(ip) {
        return st.rate_limited_response(ip);
    }
    let mut token = String::new();
    let mut action = String::new();
    let mut csrf = String::new();
    let mut passphrase: Zeroizing<String> = Zeroizing::new(String::new());
    for (k, v) in url::form_urlencoded::parse(&body) {
        match k.as_ref() {
            "t" => token = v.into_owned(),
            "action" => action = v.into_owned(),
            "csrf" => csrf = v.into_owned(),
            "passphrase" => passphrase = Zeroizing::new(v.into_owned()),
            _ => {}
        }
    }
    if !valid_id(&id) || !valid_token(&token) {
        st.fail(ip);
        return gone();
    }
    match st.core.check_token(&id, &token) {
        TokenCheck::Unknown => {
            st.fail(ip);
            return gone();
        }
        TokenCheck::Mismatch => {
            st.fail(ip);
            return simple_page(StatusCode::FORBIDDEN, "Forbidden", "Access denied.");
        }
        TokenCheck::Ok => {}
    }
    let Some(sid) = st.session_id(&headers) else {
        return redirect(&format!("/approve/{id}?t={token}"));
    };
    if !st.csrf_ok(&sid, &id, &csrf) {
        st.fail(ip);
        st.audit(
            AuditEvent::new("admin_action")
                .request(&id)
                .outcome("bad_csrf")
                .source(Some(ip)),
        );
        return simple_page(StatusCode::FORBIDDEN, "Forbidden", "Invalid form token.");
    }
    match action.as_str() {
        "deny" => match st.core.deny(&id, Source::Http(ip)) {
            DenyOutcome::Denied => simple_page(StatusCode::OK, "Denied", "The request was denied."),
            DenyOutcome::Gone => gone(),
        },
        "approve" => {
            if passphrase.is_empty() {
                return match st.core.pending_info(&id) {
                    Some((info, desc, _)) => approve_page(
                        &st,
                        &sid,
                        &info,
                        desc.as_deref(),
                        &token,
                        Some("Enter the store passphrase."),
                    ),
                    None => gone(),
                };
            }
            match st.core.approve(&id, passphrase, Source::Http(ip)).await {
                ApproveOutcome::Released => simple_page(
                    StatusCode::OK,
                    "Approved",
                    "The secret was released to the waiting process.",
                ),
                ApproveOutcome::WrongPassphrase { remaining } => {
                    st.fail(ip);
                    let msg = format!(
                        "Wrong passphrase. {remaining} of {MAX_ATTEMPTS} attempts remaining."
                    );
                    match st.core.pending_info(&id) {
                        Some((info, desc, _)) => {
                            approve_page(&st, &sid, &info, desc.as_deref(), &token, Some(&msg))
                        }
                        None => gone(),
                    }
                }
                ApproveOutcome::Failed => {
                    st.fail(ip);
                    simple_page(
                        StatusCode::FORBIDDEN,
                        "Denied",
                        "Too many wrong passphrases. The request was denied.",
                    )
                }
                ApproveOutcome::Gone => gone(),
                ApproveOutcome::Busy => simple_page(
                    StatusCode::CONFLICT,
                    "Busy",
                    "This request is already being processed.",
                ),
                ApproveOutcome::CallerChanged => simple_page(
                    StatusCode::CONFLICT,
                    "Caller changed",
                    "The requesting process changed identity. The request was aborted.",
                ),
                ApproveOutcome::NotInStore => simple_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Not in store",
                    "The secret is configured but missing from the store.",
                ),
                ApproveOutcome::Internal => simple_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Error",
                    "Internal error.",
                ),
            }
        }
        _ => simple_page(StatusCode::BAD_REQUEST, "Bad request", "Unknown action."),
    }
}

async fn auth_login(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let ip = st.client_ip(peer, &headers);
    if st.limited(ip) {
        return st.rate_limited_response(ip);
    }
    let next = match q.get("next") {
        Some(n) => match parse_next(n) {
            Some((id, t)) => Some(format!("/approve/{id}?t={t}")),
            None => {
                return simple_page(
                    StatusCode::BAD_REQUEST,
                    "Bad request",
                    "Invalid return path.",
                )
            }
        },
        None => None,
    };
    let req = match st.oidc.start().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("cannot start OIDC login: {e}");
            return simple_page(
                StatusCode::BAD_GATEWAY,
                "Sign-in unavailable",
                "The identity provider is not reachable. Try again later.",
            );
        }
    };
    {
        let mut l = st.logins.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        l.retain(|_, v| now.duration_since(v.created) < LOGIN_TTL);
        if l.len() >= MAX_STATES {
            return simple_page(
                StatusCode::SERVICE_UNAVAILABLE,
                "Busy",
                "Too many sign-ins in progress.",
            );
        }
        l.insert(
            req.state.clone(),
            LoginState {
                pkce_verifier: req.pkce_verifier,
                nonce: req.nonce,
                next,
                created: now,
            },
        );
    }
    let mut r = redirect(&req.url);
    set_cookie(&mut r, LOGIN_COOKIE, &req.state, LOGIN_TTL.as_secs());
    r
}

async fn auth_callback(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let ip = st.client_ip(peer, &headers);
    if st.limited(ip) {
        return st.rate_limited_response(ip);
    }
    let forbidden = |st: &AppState, why: &str| {
        st.fail(ip);
        st.audit(
            AuditEvent::new("admin_action")
                .outcome("oidc_rejected")
                .detail(why)
                .source(Some(ip)),
        );
        simple_page(StatusCode::FORBIDDEN, "Forbidden", "Access denied.")
    };
    let (Some(state), Some(code)) = (q.get("state"), q.get("code")) else {
        return forbidden(&st, "missing_params");
    };
    // The state must match the browser that started the login, and is single-use.
    let cookie = cookie_value(&headers, LOGIN_COOKIE);
    let login = st
        .logins
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(state);
    let Some(login) = login else {
        return forbidden(&st, "unknown_state");
    };
    if cookie.as_deref() != Some(state.as_str()) || login.created.elapsed() > LOGIN_TTL {
        return forbidden(&st, "state_mismatch");
    }
    let ident = match st
        .oidc
        .complete(code, &login.pkce_verifier, &login.nonce)
        .await
    {
        Ok(i) => i,
        Err(e) => {
            let why = match e {
                OidcError::NotAllowed => "email_not_allowed",
                OidcError::EmailUnverified => "email_unverified",
                OidcError::Verification => "token_invalid",
                OidcError::NoEmail => "no_email",
                OidcError::Exchange | OidcError::NoIdToken => "exchange_failed",
                OidcError::Provider => "provider_error",
            };
            return forbidden(&st, why);
        }
    };
    let sid = random_b64(32);
    let ttl = st.cfg.oidc.session_ttl_secs;
    {
        let mut s = st.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        s.retain(|_, v| v.expires > now);
        if s.len() >= MAX_STATES {
            return simple_page(
                StatusCode::SERVICE_UNAVAILABLE,
                "Busy",
                "Too many sessions.",
            );
        }
        s.insert(
            sid.clone(),
            Session {
                expires: now + Duration::from_secs(ttl),
            },
        );
    }
    st.audit(
        AuditEvent::new("admin_action")
            .outcome("oidc_login")
            .detail(&format!(
                "email={} amr={}",
                sanitize::clean(&ident.email, 100),
                sanitize::clean(ident.amr.as_deref().unwrap_or("none"), 100)
            ))
            .source(Some(ip)),
    );
    let mut r = match &login.next {
        Some(n) => redirect(n),
        None => simple_page(StatusCode::OK, "Signed in", "You are signed in."),
    };
    set_cookie(&mut r, SESSION_COOKIE, &sid, ttl);
    set_cookie(&mut r, LOGIN_COOKIE, "", 0);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_validation() {
        let id = "0123456789abcdef0123456789abcdef";
        assert!(parse_next(&format!("/approve/{id}?t=abc-_DEF123")).is_some());
        assert!(parse_next("/approve/short?t=abc").is_none());
        assert!(parse_next(&format!("/approve/{id}?t=a&x=y")).is_none());
        assert!(parse_next("https://evil.example/").is_none());
        assert!(parse_next(&format!("//evil.example/approve/{id}?t=a")).is_none());
        assert!(parse_next(&format!("/approve/{id}?t=")).is_none());
    }

    #[test]
    fn escaping() {
        assert_eq!(
            esc("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(unhex(&hex(&[1, 2, 255])), Some(vec![1, 2, 255]));
        assert_eq!(unhex("zz"), None);
        assert_eq!(unhex("abc"), None);
    }
}
