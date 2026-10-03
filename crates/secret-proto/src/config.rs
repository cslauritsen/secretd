//! Configuration model (`/etc/secretd/config.toml`), validation and helpers.

use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

fn err<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(msg.into()))
}

// ---------------------------------------------------------------- raw TOML

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    daemon: DaemonCfg,
    #[serde(default)]
    limits: LimitsCfg,
    notify: NotifyCfg,
    approval: RawApproval,
    #[serde(default, rename = "secret")]
    secrets: Vec<RawSecret>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IdSpec {
    Num(u32),
    Name(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecret {
    name: String,
    description: Option<String>,
    #[serde(default)]
    allow_uids: Vec<IdSpec>,
    #[serde(default)]
    allow_gids: Vec<IdSpec>,
    #[serde(default)]
    allow_exes: Vec<String>,
    #[serde(default)]
    allow_any_exe: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApproval {
    #[serde(default = "default_listen")]
    listen: String,
    external_url: String,
    #[serde(default = "default_proxies")]
    trusted_proxies: Vec<String>,
    #[serde(default)]
    allow_non_loopback: bool,
    #[serde(default = "default_fail_limit")]
    max_failed_attempts_per_min: u32,
    #[serde(default = "default_login_limit")]
    max_login_starts_per_min: u32,
    #[serde(default = "default_max_connections")]
    max_connections: usize,
    #[serde(default = "default_header_timeout")]
    header_read_timeout_secs: u64,
    #[serde(default = "default_request_timeout")]
    request_timeout_secs: u64,
    oidc: RawOidc,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOidc {
    #[serde(default = "default_issuer")]
    issuer: String,
    client_id: String,
    client_secret_file: PathBuf,
    redirect_url: Option<String>,
    owner_emails: Vec<String>,
    #[serde(default = "default_session_ttl")]
    session_ttl_secs: u64,
}

fn default_listen() -> String {
    "127.0.0.1:8443".into()
}
fn default_proxies() -> Vec<String> {
    vec!["127.0.0.1/32".into(), "::1/128".into()]
}
fn default_fail_limit() -> u32 {
    5
}
fn default_login_limit() -> u32 {
    10
}
fn default_max_connections() -> usize {
    64
}
fn default_header_timeout() -> u64 {
    10
}
fn default_request_timeout() -> u64 {
    30
}
fn default_issuer() -> String {
    "https://accounts.google.com".into()
}
fn default_session_ttl() -> u64 {
    3600
}

// ------------------------------------------------------------ public model

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DaemonCfg {
    pub user: String,
    pub socket: PathBuf,
    pub admin_socket: PathBuf,
    pub store: PathBuf,
    pub audit_log: PathBuf,
    /// Server-side maximum (and default) time a request may wait for approval.
    pub request_timeout_secs: u64,
    /// Mode of the client socket: 0o660 or 0o666 (`socket_mode = 0o660`).
    pub socket_mode: u32,
}

impl Default for DaemonCfg {
    fn default() -> Self {
        DaemonCfg {
            user: "secretd".into(),
            socket: "/run/secretd/secretd.sock".into(),
            admin_socket: "/run/secretd/admin.sock".into(),
            store: "/var/lib/secretd/store.age".into(),
            audit_log: "/var/log/secretd/audit.jsonl".into(),
            request_timeout_secs: 300,
            socket_mode: 0o660,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsCfg {
    pub max_pending_per_uid: usize,
    pub max_pending_total: usize,
    pub max_gets_per_uid_per_min: usize,
    pub max_conns_per_uid: usize,
    pub max_conns_total: usize,
    pub idle_timeout_secs: u64,
    /// Rejections (rate limit, ACL miss, changed caller, malformed request)
    /// after which a client connection is closed.
    pub max_rejections_per_conn: usize,
    /// Idle timeout of an admin socket connection (no request in flight).
    pub admin_idle_timeout_secs: u64,
}

impl Default for LimitsCfg {
    fn default() -> Self {
        LimitsCfg {
            max_pending_per_uid: 3,
            max_pending_total: 32,
            max_gets_per_uid_per_min: 10,
            max_conns_per_uid: 8,
            max_conns_total: 128,
            idle_timeout_secs: 30,
            max_rejections_per_conn: 8,
            admin_idle_timeout_secs: 600,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotifyKind {
    Ntfy,
    Webhook,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyCfg {
    pub kind: NotifyKind,
    pub url: String,
    /// File holding the ntfy bearer token (never inline).
    pub auth_token_file: Option<PathBuf>,
    /// File holding the webhook HMAC-SHA256 key.
    pub hmac_secret_file: Option<PathBuf>,
    #[serde(default = "default_notify_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_attempts")]
    pub attempts: u32,
    #[serde(default = "default_backoff")]
    pub backoff_ms: u64,
    #[serde(default = "default_priority")]
    pub priority: String,
}

fn default_notify_timeout() -> u64 {
    10
}
fn default_attempts() -> u32 {
    3
}
fn default_backoff() -> u64 {
    500
}
fn default_priority() -> String {
    "high".into()
}

/// An IP network for `trusted_proxies`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

fn normalise(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Cidr, ConfigError> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a
            .trim()
            .parse()
            .map_err(|_| ConfigError(format!("invalid trusted_proxies entry {s:?}")))?;
        let addr = normalise(addr);
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| ConfigError(format!("invalid prefix in trusted_proxies {s:?}")))?,
            None => max,
        };
        Ok(Cidr { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, normalise(ip)) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                u32::from(n) & mask == u32::from(i) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                u128::from(n) & mask == u128::from(i) & mask
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OidcCfg {
    pub issuer: String,
    pub client_id: String,
    pub client_secret_file: PathBuf,
    pub redirect_url: String,
    /// Lower-cased allowlist.
    pub owner_emails: Vec<String>,
    pub session_ttl_secs: u64,
}

#[derive(Debug, Clone)]
pub struct ApprovalCfg {
    pub listen: SocketAddr,
    /// `https://host[:port]` without trailing slash.
    pub external_url: String,
    /// `host[:port]` as it must appear in the Host header.
    pub external_host: String,
    pub trusted_proxies: Vec<Cidr>,
    pub allow_non_loopback: bool,
    pub max_failed_attempts_per_min: u32,
    /// `/auth/login` starts per source IP per minute before HTTP 429.
    pub max_login_starts_per_min: u32,
    /// Simultaneous HTTP connections; further ones are closed at accept.
    pub max_connections: usize,
    /// Time a client has to send complete request headers.
    pub header_read_timeout_secs: u64,
    /// Time a whole request (headers, body, handler) may take.
    pub request_timeout_secs: u64,
    pub oidc: OidcCfg,
}

/// A secret's name, description and resolved ACL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretAcl {
    pub name: String,
    pub description: Option<String>,
    pub uids: Vec<u32>,
    pub gids: Vec<u32>,
    pub exes: Vec<String>,
    pub allow_any_exe: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub daemon: DaemonCfg,
    pub limits: LimitsCfg,
    pub notify: NotifyCfg,
    pub approval: ApprovalCfg,
    pub secrets: Vec<SecretAcl>,
    /// Non-fatal findings from validation.
    pub warnings: Vec<String>,
}

/// Resolves user and group names to numeric ids.
pub trait NameResolver {
    fn uid(&self, name: &str) -> Option<u32>;
    fn gid(&self, name: &str) -> Option<u32>;
}

/// Resolver backed by the system user and group databases.
pub struct SystemResolver;

impl NameResolver for SystemResolver {
    fn uid(&self, name: &str) -> Option<u32> {
        nix::unistd::User::from_name(name)
            .ok()
            .flatten()
            .map(|u| u.uid.as_raw())
    }
    fn gid(&self, name: &str) -> Option<u32> {
        nix::unistd::Group::from_name(name)
            .ok()
            .flatten()
            .map(|g| g.gid.as_raw())
    }
}

impl Config {
    /// Parse and validate configuration text. Does not touch the filesystem
    /// other than canonicalising `allow_exes` entries that exist.
    pub fn parse(text: &str, resolver: &dyn NameResolver) -> Result<Config, ConfigError> {
        let raw: RawConfig = toml::from_str(text).map_err(|e| ConfigError(e.to_string()))?;
        let mut warnings = Vec::new();

        // daemon
        let d = &raw.daemon;
        if d.request_timeout_secs == 0 {
            return err("daemon.request_timeout_secs must be > 0");
        }
        if d.socket_mode != 0o660 && d.socket_mode != 0o666 {
            return err("daemon.socket_mode must be 0o660 or 0o666");
        }
        for (n, p) in [
            ("socket", &d.socket),
            ("admin_socket", &d.admin_socket),
            ("store", &d.store),
            ("audit_log", &d.audit_log),
        ] {
            if !p.is_absolute() {
                return err(format!("daemon.{n} must be an absolute path"));
            }
        }
        if d.socket_mode == 0o666 {
            warnings.push(
                "daemon.socket_mode is 0o666: any local user can connect (ACLs still apply)".into(),
            );
        }

        // limits
        let l = &raw.limits;
        if l.max_pending_per_uid == 0
            || l.max_pending_total == 0
            || l.max_conns_per_uid == 0
            || l.max_conns_total == 0
            || l.max_gets_per_uid_per_min == 0
            || l.max_rejections_per_conn == 0
            || l.admin_idle_timeout_secs == 0
        {
            return err("limits must be non-zero");
        }

        // notify
        let n = &raw.notify;
        if !(n.url.starts_with("https://") || n.url.starts_with("http://")) {
            return err("notify.url must be an http(s) URL");
        }
        if n.url.starts_with("http://") {
            warnings.push("notify.url uses plain http".into());
        }
        if n.attempts == 0 {
            return err("notify.attempts must be >= 1");
        }
        if n.kind == NotifyKind::Ntfy && n.hmac_secret_file.is_some() {
            warnings.push("notify.hmac_secret_file is ignored for kind = \"ntfy\"".into());
        }
        if n.kind == NotifyKind::Webhook && n.auth_token_file.is_some() {
            warnings.push("notify.auth_token_file is ignored for kind = \"webhook\"".into());
        }

        // approval
        let a = &raw.approval;
        let listen: SocketAddr = a
            .listen
            .parse()
            .map_err(|_| ConfigError(format!("approval.listen {:?} is not host:port", a.listen)))?;
        if !listen.ip().is_loopback() {
            if !a.allow_non_loopback {
                return err(format!(
                    "approval.listen {listen} is not a loopback address; \
                     set approval.allow_non_loopback = true to allow it"
                ));
            }
            warnings.push(format!(
                "approval.listen {listen} is not loopback: ensure only the TLS reverse proxy can reach it"
            ));
        }
        let ext = url::Url::parse(&a.external_url)
            .map_err(|_| ConfigError("approval.external_url is not a valid URL".into()))?;
        if ext.scheme() != "https" {
            return err("approval.external_url must be an https:// URL");
        }
        let host = ext
            .host_str()
            .ok_or_else(|| ConfigError("approval.external_url has no host".into()))?;
        if ext.path() != "/" && !ext.path().is_empty() || ext.query().is_some() {
            return err("approval.external_url must not contain a path or query");
        }
        let external_host = match ext.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        };
        let external_url = format!("https://{external_host}");
        let trusted_proxies = a
            .trusted_proxies
            .iter()
            .map(|s| Cidr::parse(s))
            .collect::<Result<Vec<_>, _>>()?;

        if a.max_connections == 0
            || a.header_read_timeout_secs == 0
            || a.request_timeout_secs == 0
            || a.max_login_starts_per_min == 0
        {
            return err("approval connection limits and timeouts must be non-zero");
        }

        let o = &a.oidc;
        let issuer = url::Url::parse(&o.issuer)
            .map_err(|_| ConfigError("approval.oidc.issuer is not a valid URL".into()))?;
        match issuer.scheme() {
            "https" => {}
            // Plain http is tolerated only towards this machine (local mock
            // providers); a network issuer over http would let anyone on the
            // path forge the discovery document and the signing keys.
            "http" if issuer_is_loopback(&issuer) => warnings.push(
                "approval.oidc.issuer uses plain http (loopback only; for local testing)".into(),
            ),
            _ => return err("approval.oidc.issuer must be an https:// URL"),
        }
        if o.client_id.trim().is_empty() {
            return err("approval.oidc.client_id is empty");
        }
        if o.owner_emails.is_empty() || o.owner_emails.iter().any(|e| !e.contains('@')) {
            return err("approval.oidc.owner_emails must list at least one email address");
        }
        if o.session_ttl_secs == 0 {
            return err("approval.oidc.session_ttl_secs must be > 0");
        }
        let redirect_url = match &o.redirect_url {
            Some(r) => {
                let u = url::Url::parse(r)
                    .map_err(|_| ConfigError("approval.oidc.redirect_url is invalid".into()))?;
                if u.scheme() != "https" {
                    return err("approval.oidc.redirect_url must be https");
                }
                r.clone()
            }
            None => format!("{external_url}/auth/callback"),
        };
        let oidc = OidcCfg {
            issuer: o.issuer.clone(),
            client_id: o.client_id.clone(),
            client_secret_file: o.client_secret_file.clone(),
            redirect_url,
            owner_emails: o.owner_emails.iter().map(|e| e.to_lowercase()).collect(),
            session_ttl_secs: o.session_ttl_secs,
        };

        // secrets
        let mut secrets: Vec<SecretAcl> = Vec::new();
        for s in &raw.secrets {
            if !crate::valid_secret_name(&s.name) {
                return err(format!("invalid secret name {:?}", s.name));
            }
            if secrets.iter().any(|x| x.name == s.name) {
                return err(format!("duplicate secret {:?}", s.name));
            }
            let mut uids = Vec::new();
            for id in &s.allow_uids {
                uids.push(match id {
                    IdSpec::Num(n) => *n,
                    IdSpec::Name(nm) => resolver.uid(nm).ok_or_else(|| {
                        ConfigError(format!("secret {:?}: unknown user {nm:?}", s.name))
                    })?,
                });
            }
            let mut gids = Vec::new();
            for id in &s.allow_gids {
                gids.push(match id {
                    IdSpec::Num(n) => *n,
                    IdSpec::Name(nm) => resolver.gid(nm).ok_or_else(|| {
                        ConfigError(format!("secret {:?}: unknown group {nm:?}", s.name))
                    })?,
                });
            }
            let mut exes = Vec::new();
            for e in &s.allow_exes {
                let p = Path::new(e);
                if !p.is_absolute() {
                    return err(format!(
                        "secret {:?}: allow_exes entry {e:?} is not absolute",
                        s.name
                    ));
                }
                match std::fs::canonicalize(p) {
                    Ok(c) => exes.push(c.to_string_lossy().into_owned()),
                    Err(_) => {
                        warnings.push(format!(
                            "secret {:?}: allow_exes entry {e:?} does not exist; using it verbatim",
                            s.name
                        ));
                        exes.push(e.clone());
                    }
                }
            }
            if exes.is_empty() && !s.allow_any_exe {
                return err(format!(
                    "secret {:?}: allow_exes is empty; set allow_any_exe = true to explicitly \
                     allow any executable",
                    s.name
                ));
            }
            if !exes.is_empty() && s.allow_any_exe {
                return err(format!(
                    "secret {:?}: allow_exes and allow_any_exe = true are contradictory",
                    s.name
                ));
            }
            if exes.is_empty() {
                warnings.push(format!(
                    "secret {:?}: allow_any_exe = true, executable is not restricted",
                    s.name
                ));
            }
            if uids.is_empty() && gids.is_empty() {
                warnings.push(format!(
                    "secret {:?} has no allow_uids/allow_gids and is unreachable",
                    s.name
                ));
            }
            secrets.push(SecretAcl {
                name: s.name.clone(),
                description: s.description.clone(),
                uids,
                gids,
                exes,
                allow_any_exe: s.allow_any_exe,
            });
        }

        Ok(Config {
            daemon: raw.daemon,
            limits: raw.limits,
            notify: raw.notify,
            approval: ApprovalCfg {
                listen,
                external_url,
                external_host,
                trusted_proxies,
                allow_non_loopback: a.allow_non_loopback,
                max_failed_attempts_per_min: a.max_failed_attempts_per_min,
                max_login_starts_per_min: a.max_login_starts_per_min,
                max_connections: a.max_connections,
                header_read_timeout_secs: a.header_read_timeout_secs,
                request_timeout_secs: a.request_timeout_secs,
                oidc,
            },
            secrets,
            warnings,
        })
    }

    /// Read, permission-check and parse a config file.  `trusted_uids` are the
    /// uids allowed to own the file (normally root and the daemon user).
    pub fn load(
        path: &Path,
        trusted_uids: &[u32],
        resolver: &dyn NameResolver,
    ) -> Result<Config, ConfigError> {
        check_file_perms(path, trusted_uids)?;
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError(format!("cannot read {}: {e}", path.display())))?;
        Config::parse(&text, resolver)
    }

    pub fn secret(&self, name: &str) -> Option<&SecretAcl> {
        self.secrets.iter().find(|s| s.name == name)
    }
}

fn issuer_is_loopback(u: &url::Url) -> bool {
    match u.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// The file must be owned by one of `trusted_uids` and not group/world writable.
pub fn check_file_perms(path: &Path, trusted_uids: &[u32]) -> Result<(), ConfigError> {
    let md = std::fs::metadata(path)
        .map_err(|e| ConfigError(format!("cannot stat {}: {e}", path.display())))?;
    if !trusted_uids.contains(&md.uid()) {
        return err(format!(
            "{} is owned by uid {}, expected root or the secretd user",
            path.display(),
            md.uid()
        ));
    }
    if md.mode() & 0o022 != 0 {
        return err(format!(
            "{} is group or world writable (mode {:o})",
            path.display(),
            md.mode() & 0o7777
        ));
    }
    Ok(())
}

/// Read a one-line secret file (token, client secret), trimming whitespace.
pub fn read_secret_file(path: &Path) -> Result<zeroize::Zeroizing<String>, ConfigError> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| ConfigError(format!("cannot read {}: {e}", path.display())))?;
    let t = zeroize::Zeroizing::new(s.trim().to_string());
    drop(zeroize::Zeroizing::new(s));
    if t.is_empty() {
        return err(format!("{} is empty", path.display()));
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct R;
    impl NameResolver for R {
        fn uid(&self, n: &str) -> Option<u32> {
            (n == "alice").then_some(1000)
        }
        fn gid(&self, n: &str) -> Option<u32> {
            (n == "devs").then_some(100)
        }
    }

    pub const BASE: &str = r#"
[notify]
kind = "ntfy"
url = "https://ntfy.example.com/t"
[approval]
external_url = "https://secretd.example.com"
[approval.oidc]
client_id = "abc"
client_secret_file = "/etc/secretd/oidc-client-secret"
owner_emails = ["Owner@Example.com"]
"#;

    fn parse(extra: &str) -> Result<Config, ConfigError> {
        Config::parse(&format!("{BASE}\n{extra}"), &R)
    }

    #[test]
    fn defaults() {
        let c = parse("").unwrap();
        assert_eq!(c.approval.listen.to_string(), "127.0.0.1:8443");
        assert_eq!(c.approval.external_host, "secretd.example.com");
        assert_eq!(
            c.approval.oidc.redirect_url,
            "https://secretd.example.com/auth/callback"
        );
        assert_eq!(c.approval.oidc.owner_emails, vec!["owner@example.com"]);
        assert_eq!(c.limits.max_pending_per_uid, 3);
        assert_eq!(c.daemon.request_timeout_secs, 300);
        assert_eq!(c.approval.trusted_proxies.len(), 2);
    }

    #[test]
    fn resolves_names_and_exes() {
        let c = parse(
            "[[secret]]\nname='a'\nallow_uids=['alice', 5]\nallow_gids=['devs']\nallow_exes=['/nonexistent/bin/x']\n",
        )
        .unwrap();
        assert_eq!(c.secrets[0].uids, vec![1000, 5]);
        assert_eq!(c.secrets[0].gids, vec![100]);
        assert!(c.warnings.iter().any(|w| w.contains("does not exist")));
        assert!(Config::parse(
            &format!("{BASE}\n[[secret]]\nname='a'\nallow_uids=['bob']\nallow_exes=['/x']"),
            &R
        )
        .is_err());
    }

    #[test]
    fn exe_rules() {
        let e = parse("[[secret]]\nname='a'\nallow_uids=[1]\n").unwrap_err();
        assert!(e.0.contains("allow_any_exe"));
        let c = parse("[[secret]]\nname='a'\nallow_uids=[1]\nallow_any_exe=true\n").unwrap();
        assert!(c.warnings.iter().any(|w| w.contains("not restricted")));
        assert!(parse(
            "[[secret]]\nname='a'\nallow_uids=[1]\nallow_exes=['/x']\nallow_any_exe=true\n"
        )
        .is_err());
        assert!(parse("[[secret]]\nname='a'\nallow_uids=[1]\nallow_exes=['rel/x']\n").is_err());
    }

    #[test]
    fn no_acl_warns_unreachable() {
        let c = parse("[[secret]]\nname='a'\nallow_exes=['/x']\n").unwrap();
        assert!(c.warnings.iter().any(|w| w.contains("unreachable")));
    }

    #[test]
    fn bad_names_and_duplicates() {
        assert!(parse("[[secret]]\nname='a b'\nallow_exes=['/x']\n").is_err());
        assert!(parse(
            "[[secret]]\nname='a'\nallow_exes=['/x']\n[[secret]]\nname='a'\nallow_exes=['/x']\n"
        )
        .is_err());
    }

    #[test]
    fn listen_must_be_loopback() {
        let t = |l: &str, extra: &str| {
            let base = BASE.replace(
                "[approval]\n",
                &format!("[approval]\nlisten = \"{l}\"\n{extra}\n"),
            );
            Config::parse(&base, &R)
        };
        assert!(t("127.0.0.1:9", "").is_ok());
        assert!(t("[::1]:9", "").is_ok());
        assert!(t("0.0.0.0:9", "").is_err());
        let c = t("10.0.0.5:9", "allow_non_loopback = true").unwrap();
        assert!(c.warnings.iter().any(|w| w.contains("not loopback")));
        assert!(t("nonsense", "").is_err());
    }

    #[test]
    fn external_url_must_be_https() {
        let b = BASE.replace("https://secretd.example.com", "http://secretd.example.com");
        assert!(Config::parse(&b, &R).is_err());
        let b = BASE.replace("https://secretd.example.com", "https://x.example.com:8444/");
        let c = Config::parse(&b, &R).unwrap();
        assert_eq!(c.approval.external_host, "x.example.com:8444");
        let b = BASE.replace("https://secretd.example.com", "https://x.example.com/sub");
        assert!(Config::parse(&b, &R).is_err());
    }

    #[test]
    fn oidc_issuer_must_be_https() {
        let t = |iss: &str| {
            Config::parse(
                &BASE.replace(
                    "[approval.oidc]\n",
                    &format!("[approval.oidc]\nissuer = \"{iss}\"\n"),
                ),
                &R,
            )
        };
        assert!(t("https://accounts.google.com").is_ok());
        assert!(t("http://accounts.google.com").is_err());
        assert!(t("http://idp.example.com:8080").is_err());
        assert!(t("ftp://idp.example.com").is_err());
        assert!(t("not a url").is_err());
        // Loopback http is allowed for local mock providers, with a warning.
        for l in [
            "http://127.0.0.1:9000",
            "http://localhost:9000",
            "http://[::1]:9",
        ] {
            let c = t(l).unwrap();
            assert!(c.warnings.iter().any(|w| w.contains("plain http")), "{l}");
        }
        // Look-alike hosts are not loopback.
        assert!(t("http://127.0.0.1.evil.example").is_err());
    }

    #[test]
    fn zero_limits_are_rejected() {
        assert!(parse("[limits]\nmax_conns_total = 0\n").is_err());
        assert!(parse("[limits]\nmax_conns_per_uid = 0\n").is_err());
        assert!(parse("[limits]\nadmin_idle_timeout_secs = 0\n").is_err());
        assert!(parse("[limits]\nmax_conns_total = 1\n").is_ok());
        assert!(Config::parse(
            &BASE.replace("[approval]\n", "[approval]\nmax_connections = 0\n"),
            &R
        )
        .is_err());
    }

    #[test]
    fn unknown_fields_rejected() {
        assert!(parse("[daemon]\nbogus=1\n").is_err());
        let b = BASE.replace(
            "kind = \"ntfy\"",
            "kind = \"ntfy\"\nauth_token = \"inline\"",
        );
        assert!(Config::parse(&b, &R).is_err());
    }

    #[test]
    fn cidr() {
        let c = Cidr::parse("10.1.0.0/16").unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(!c.contains("10.2.0.1".parse().unwrap()));
        assert!(!c.contains("::1".parse().unwrap()));
        let l = Cidr::parse("::1/128").unwrap();
        assert!(l.contains("::1".parse().unwrap()));
        assert!(!l.contains("::2".parse().unwrap()));
        let m = Cidr::parse("127.0.0.1/32").unwrap();
        assert!(m.contains("::ffff:127.0.0.1".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.4/33").is_err());
        assert!(Cidr::parse("junk").is_err());
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn packaged_example_config_parses() {
        let text = include_str!("../../../packaging/config.example.toml");
        let c = Config::parse(text, &R).unwrap();
        assert_eq!(c.secrets[0].name, "db-password");
        assert_eq!(c.daemon.socket_mode, 0o660);
        assert_eq!(c.approval.external_host, "secretd.example.com");
        assert_eq!(c.notify.attempts, 3);
    }

    #[test]
    fn file_perms() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.toml");
        std::fs::write(&p, BASE).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let me = std::fs::metadata(&p).unwrap().uid();
        assert!(check_file_perms(&p, &[me]).is_ok());
        assert!(check_file_perms(&p, &[me + 1]).is_err());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(check_file_perms(&p, &[me]).is_err());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o602)).unwrap();
        assert!(check_file_perms(&p, &[me]).is_err());
    }
}
