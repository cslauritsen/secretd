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
    #[serde(default)]
    channels: Option<RawChannels>,
    notify: Option<NotifyCfg>,
    approval: Option<RawApproval>,
    homeassistant: Option<RawHa>,
    #[serde(default, rename = "secret")]
    secrets: Vec<RawSecret>,
    #[serde(default, rename = "fifo")]
    fifos: Vec<RawFifo>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFifo {
    path: PathBuf,
    secret: String,
    /// Owner of the pipe (default: the daemon user).
    owner: Option<IdSpec>,
    group: IdSpec,
    /// Octal string, e.g. "0640". A TOML integer is refused on purpose (440 vs 0o440).
    #[serde(default = "default_fifo_mode")]
    mode: String,
    #[serde(default)]
    enforce_acl: bool,
    #[serde(default = "default_fifo_attempts")]
    attempts_per_min: usize,
    #[serde(default = "default_fifo_cooldown")]
    cooldown_secs: u64,
    #[serde(default = "default_fifo_deadline")]
    write_deadline_secs: u64,
}

fn default_fifo_mode() -> String {
    "0640".into()
}
fn default_fifo_attempts() -> usize {
    10
}
fn default_fifo_cooldown() -> u64 {
    5
}
fn default_fifo_deadline() -> u64 {
    5
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawChannels {
    enabled: Vec<ChannelKind>,
}

/// An approval channel (spec section 19.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelKind {
    /// Push notification plus the OIDC-protected approval page.
    Web,
    /// The root-only admin socket (`secretctl approve|deny`).
    Admin,
    /// Home Assistant (notification actions and a passphrase entity).
    HomeAssistant,
}

impl ChannelKind {
    /// The name used in the configuration and in the audit log `channel` field.
    pub fn as_str(self) -> &'static str {
        match self {
            ChannelKind::Web => "web",
            ChannelKind::Admin => "admin",
            ChannelKind::HomeAssistant => "homeassistant",
        }
    }
}

/// Which channels are enabled. Without a `[channels]` table: `web` and `admin`
/// (the behaviour before channels existed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelsCfg {
    pub enabled: Vec<ChannelKind>,
}

impl ChannelsCfg {
    pub fn has(&self, k: ChannelKind) -> bool {
        self.enabled.contains(&k)
    }
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHa {
    url: String,
    token_file: PathBuf,
    notify_service: String,
    passphrase_entity: String,
    #[serde(default)]
    owner_user_ids: Vec<String>,
    #[serde(default)]
    allow_insecure_http: bool,
    ca_file: Option<PathBuf>,
    #[serde(default = "default_true")]
    ha_require_user_id: bool,
    #[serde(default = "default_ha_backoff_min")]
    backoff_min_ms: u64,
    #[serde(default = "default_ha_backoff_max")]
    backoff_max_ms: u64,
}

fn default_true() -> bool {
    true
}
fn default_ha_backoff_min() -> u64 {
    1000
}
fn default_ha_backoff_max() -> u64 {
    60_000
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
    /// Group that owns the client socket when secretd binds it itself (under
    /// systemd the `.socket` unit's `SocketGroup=` decides). Members of this
    /// group may connect; give it a dedicated group (`secretd-clients`), not
    /// the group that can read the daemon's credential files. Default: the
    /// daemon user's primary group.
    pub socket_group: Option<String>,
}

impl Default for DaemonCfg {
    fn default() -> Self {
        DaemonCfg {
            user: "secretd".into(),
            socket: crate::DEFAULT_SOCKET.into(),
            admin_socket: crate::DEFAULT_ADMIN_SOCKET.into(),
            store: "/var/lib/secretd/store.age".into(),
            audit_log: "/var/log/secretd/audit.jsonl".into(),
            request_timeout_secs: 300,
            socket_mode: 0o660,
            socket_group: None,
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

/// Home Assistant channel settings (spec section 19.2).
#[derive(Debug, Clone)]
pub struct HaCfg {
    /// Base URL as configured, without a trailing slash.
    pub url: String,
    /// `ws://` or `wss://` URL of the WebSocket API (`<url>/api/websocket`).
    pub ws_url: String,
    /// File with the long-lived access token (never inline).
    pub token_file: PathBuf,
    /// `notify.<service>` that reaches the owner's phone.
    pub notify_service: String,
    /// `input_text.<name>`: where the owner types the store passphrase.
    pub passphrase_entity: String,
    /// HA user ids whose notification actions are accepted.
    pub owner_user_ids: Vec<String>,
    pub allow_insecure_http: bool,
    /// Optional CA certificate (PEM) that pins the trust anchor for `https`.
    pub ca_file: Option<PathBuf>,
    /// Require `context.user_id` on action events (default). `false` is the
    /// documented opt-out (`ha_require_user_id = false`).
    pub require_user_id: bool,
    /// Reconnect backoff bounds in milliseconds (default 1 s up to 60 s).
    pub backoff_min_ms: u64,
    pub backoff_max_ms: u64,
}

/// A named-pipe secret (spec section 20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FifoCfg {
    pub path: PathBuf,
    /// Name of the secret released through this pipe (exists in `[[secret]]`).
    pub secret: String,
    /// `None`: the daemon user (the pipe is then not chown'ed).
    pub owner: Option<u32>,
    pub gid: u32,
    /// Permission bits (octal), at most `0660`.
    pub mode: u32,
    /// Require the single identified reader to satisfy the secret's ACL.
    pub enforce_acl: bool,
    /// Reader detections per minute before further ones are refused.
    pub attempts_per_min: usize,
    /// Seconds to wait after a request ends before the pipe is armed again.
    pub cooldown_secs: u64,
    /// Seconds allowed to push the value into the pipe.
    pub write_deadline_secs: u64,
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
    pub channels: ChannelsCfg,
    /// Push notification settings; present exactly when `web` is enabled.
    pub notify: Option<NotifyCfg>,
    /// Approval endpoint and OIDC settings; present exactly when `web` is enabled.
    pub approval: Option<ApprovalCfg>,
    /// Home Assistant settings; present exactly when `homeassistant` is enabled.
    pub homeassistant: Option<HaCfg>,
    pub fifos: Vec<FifoCfg>,
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
        if d.socket_group
            .as_deref()
            .is_some_and(|g| g.trim().is_empty())
        {
            return err("daemon.socket_group must not be empty");
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

        // channels
        let enabled = match &raw.channels {
            Some(c) => c.enabled.clone(),
            None => vec![ChannelKind::Web, ChannelKind::Admin],
        };
        if enabled.is_empty() {
            return err("channels.enabled is empty: at least one approval channel must be enabled");
        }
        for (i, k) in enabled.iter().enumerate() {
            if enabled[..i].contains(k) {
                return err(format!("channels.enabled lists {:?} twice", k.as_str()));
            }
        }
        let channels = ChannelsCfg { enabled };
        let web = channels.has(ChannelKind::Web);
        if web && (raw.notify.is_none() || raw.approval.is_none()) {
            return err(
                "channel \"web\" is enabled but [notify], [approval] and [approval.oidc] are \
                 not all configured",
            );
        }
        if !web && (raw.notify.is_some() || raw.approval.is_some()) {
            warnings.push(
                "[notify]/[approval] are configured but the \"web\" channel is not enabled; \
                 they are ignored"
                    .into(),
            );
        }

        let ha_on = channels.has(ChannelKind::HomeAssistant);
        if ha_on && raw.homeassistant.is_none() {
            return err(
                "channel \"homeassistant\" is enabled but [homeassistant] is not configured",
            );
        }
        if !ha_on && raw.homeassistant.is_some() {
            warnings.push(
                "[homeassistant] is configured but the \"homeassistant\" channel is not enabled; \
                 it is ignored"
                    .into(),
            );
        }
        let homeassistant = match (ha_on, &raw.homeassistant) {
            (true, Some(h)) => Some(parse_ha(h, &mut warnings)?),
            _ => None,
        };
        let (notify, approval) = match (web, &raw.notify, &raw.approval) {
            (true, Some(n), Some(a)) => (Some(n.clone()), Some(parse_web(n, a, &mut warnings)?)),
            _ => (None, None),
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

        // fifos
        let mut fifos: Vec<FifoCfg> = Vec::new();
        for f in &raw.fifos {
            let id = |spec: &IdSpec, user: bool| -> Result<u32, ConfigError> {
                match spec {
                    IdSpec::Num(n) => Ok(*n),
                    IdSpec::Name(nm) => (if user {
                        resolver.uid(nm)
                    } else {
                        resolver.gid(nm)
                    })
                    .ok_or_else(|| {
                        ConfigError(format!(
                            "fifo {}: unknown {} {nm:?}",
                            f.path.display(),
                            if user { "user" } else { "group" }
                        ))
                    }),
                }
            };
            fifos.push(parse_fifo(
                f,
                &secrets,
                &fifos,
                &raw.daemon,
                id(&f.group, false)?,
                f.owner.as_ref().map(|o| id(o, true)).transpose()?,
                &mut warnings,
            )?);
        }

        Ok(Config {
            daemon: raw.daemon,
            limits: raw.limits,
            channels,
            homeassistant,
            notify,
            approval,
            secrets,
            fifos,
            warnings,
        })
    }

    /// Read, permission-check and parse a config file.
    ///
    /// The file must be owned by one of `trusted_uids` (callers pass root and
    /// their own euid) or by the daemon user named *in the file* (`daemon.user`,
    /// default `secretd`), and must not be group/world writable. The file is
    /// opened once and the checks use that descriptor, so the file that was
    /// checked is the file that was read. Naming the daemon user inside the
    /// file is circular by nature: the path itself must be one only the
    /// administrator can write (`/etc/secretd`); the check catches
    /// misconfigured ownership, it is not a defence against a hostile path.
    pub fn load(
        path: &Path,
        trusted_uids: &[u32],
        resolver: &dyn NameResolver,
    ) -> Result<Config, ConfigError> {
        use std::io::Read;
        let mut f = std::fs::File::open(path)
            .map_err(|e| ConfigError(format!("cannot read {}: {e}", path.display())))?;
        let md = f
            .metadata()
            .map_err(|e| ConfigError(format!("cannot stat {}: {e}", path.display())))?;
        let mut text = String::new();
        f.read_to_string(&mut text)
            .map_err(|e| ConfigError(format!("cannot read {}: {e}", path.display())))?;
        let cfg = Config::parse(&text, resolver)?;
        let mut uids = trusted_uids.to_vec();
        if let Some(u) = resolver.uid(&cfg.daemon.user) {
            uids.push(u);
        }
        check_metadata_perms(path, &md, &uids)?;
        Ok(cfg)
    }

    pub fn secret(&self, name: &str) -> Option<&SecretAcl> {
        self.secrets.iter().find(|s| s.name == name)
    }
}

/// Validate the `[notify]` and `[approval]` tables (the `web` channel).
fn parse_web(
    n: &NotifyCfg,
    a: &RawApproval,
    warnings: &mut Vec<String>,
) -> Result<ApprovalCfg, ConfigError> {
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
        "http" if issuer_is_loopback(&issuer) => warnings
            .push("approval.oidc.issuer uses plain http (loopback only; for local testing)".into()),
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

    Ok(ApprovalCfg {
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
    })
}

/// Validate `[homeassistant]` (spec section 19.2, 19.4).
fn parse_ha(h: &RawHa, warnings: &mut Vec<String>) -> Result<HaCfg, ConfigError> {
    let u = url::Url::parse(&h.url)
        .map_err(|_| ConfigError("homeassistant.url is not a valid URL".into()))?;
    let secure = match u.scheme() {
        "https" => true,
        "http" => false,
        _ => return err("homeassistant.url must be an http:// or https:// URL"),
    };
    if u.host_str().is_none() {
        return err("homeassistant.url has no host");
    }
    if u.query().is_some() || u.fragment().is_some() {
        return err("homeassistant.url must not contain a query or fragment");
    }
    if !secure {
        // The long-lived token (and the passphrase) travel over this connection.
        let loopback = match u.host() {
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        };
        if !loopback {
            if !h.allow_insecure_http {
                return err(
                    "homeassistant.url is plain http to a non-loopback host: the access token \
                     and the passphrase would cross the network unencrypted. Use https:// or set \
                     homeassistant.allow_insecure_http = true",
                );
            }
            warnings.push(
                "homeassistant.url uses plain http (allow_insecure_http = true): the access token \
                 and the store passphrase travel unencrypted; acceptable only on a trusted LAN"
                    .into(),
            );
        }
        if h.ca_file.is_some() {
            warnings.push("homeassistant.ca_file is ignored for an http:// url".into());
        }
    }
    let service_ok = |s: &str, domain: &str| {
        s.strip_prefix(domain)
            .and_then(|r| r.strip_prefix('.'))
            .is_some_and(|n| {
                !n.is_empty()
                    && n.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            })
    };
    if !service_ok(&h.notify_service, "notify") {
        return err("homeassistant.notify_service must look like notify.mobile_app_<device>");
    }
    if !service_ok(&h.passphrase_entity, "input_text") {
        return err("homeassistant.passphrase_entity must look like input_text.<name>");
    }
    if h.owner_user_ids
        .iter()
        .any(|i| i.trim().is_empty() || i.chars().any(char::is_whitespace))
    {
        return err("homeassistant.owner_user_ids entries must be non-empty ids without spaces");
    }
    if h.owner_user_ids.is_empty() && h.ha_require_user_id {
        return err(
            "homeassistant.owner_user_ids is empty: list the HA user id(s) allowed to approve",
        );
    }
    if !h.ha_require_user_id {
        warnings.push(
            "homeassistant.ha_require_user_id = false: action events without a user id are \
             accepted; only the per-request token protects approvals from other HA users"
                .into(),
        );
        if h.owner_user_ids.is_empty() {
            warnings.push(
                "homeassistant.owner_user_ids is empty: any event carrying the token is accepted"
                    .into(),
            );
        }
    }
    if h.backoff_min_ms == 0 || h.backoff_max_ms < h.backoff_min_ms {
        return err("homeassistant.backoff_min_ms must be > 0 and <= backoff_max_ms");
    }
    let base = h.url.trim_end_matches('/').to_string();
    let ws_url = format!(
        "{}{}/api/websocket",
        if secure { "wss" } else { "ws" },
        &base[base.find("://").unwrap_or(0)..]
    );
    Ok(HaCfg {
        url: base,
        ws_url,
        token_file: h.token_file.clone(),
        notify_service: h.notify_service.clone(),
        passphrase_entity: h.passphrase_entity.clone(),
        owner_user_ids: h.owner_user_ids.clone(),
        allow_insecure_http: h.allow_insecure_http,
        ca_file: h.ca_file.clone(),
        require_user_id: h.ha_require_user_id,
        backoff_min_ms: h.backoff_min_ms,
        backoff_max_ms: h.backoff_max_ms,
    })
}

/// Validate one `[[fifo]]` entry (spec section 20.1).
fn parse_fifo(
    f: &RawFifo,
    secrets: &[SecretAcl],
    done: &[FifoCfg],
    daemon: &DaemonCfg,
    gid: u32,
    owner: Option<u32>,
    warnings: &mut Vec<String>,
) -> Result<FifoCfg, ConfigError> {
    let label = f.path.display().to_string();
    if !f.path.is_absolute() {
        return err(format!("fifo path {label} must be absolute"));
    }
    if f.path.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) || f.path.file_name().is_none()
        || label.ends_with('/')
    {
        return err(format!(
            "fifo path {label} must be a normalised file path (no `.`, `..` or trailing `/`)"
        ));
    }
    if done.iter().any(|d| d.path == f.path) {
        return err(format!("fifo path {label} is configured twice"));
    }
    for (n, p) in [
        ("socket", &daemon.socket),
        ("admin_socket", &daemon.admin_socket),
        ("store", &daemon.store),
        ("audit_log", &daemon.audit_log),
    ] {
        if *p == f.path {
            return err(format!("fifo path {label} is the same as daemon.{n}"));
        }
    }
    if !secrets.iter().any(|s| s.name == f.secret) {
        return err(format!(
            "fifo {label}: secret {:?} is not defined in [[secret]]",
            f.secret
        ));
    }
    let mode = f
        .mode
        .strip_prefix('0')
        .filter(|m| !m.is_empty() && m.bytes().all(|b| (b'0'..=b'7').contains(&b)))
        .and_then(|m| u32::from_str_radix(m, 8).ok())
        .ok_or_else(|| {
            ConfigError(format!(
                "fifo {label}: mode {:?} must be an octal string such as \"0640\"",
                f.mode
            ))
        })?;
    if mode & !0o660 != 0 {
        return err(format!(
            "fifo {label}: mode {:04o} grants access beyond owner/group read-write (max 0660, \
             no `other`, setuid, setgid or sticky bits)",
            mode
        ));
    }
    if mode & 0o440 == 0 {
        return err(format!(
            "fifo {label}: mode {mode:04o} lets nobody read the pipe"
        ));
    }
    if mode & 0o220 != 0 {
        warnings.push(format!(
            "fifo {label}: mode {mode:04o} lets its owner/group write to the pipe as well as the \
             daemon; any process they run may feed the reader data of its own"
        ));
    }
    if f.attempts_per_min == 0 {
        return err(format!("fifo {label}: attempts_per_min must be > 0"));
    }
    if f.write_deadline_secs == 0 {
        return err(format!("fifo {label}: write_deadline_secs must be > 0"));
    }
    if !f.enforce_acl {
        warnings.push(format!(
            "fifo {label}: enforce_acl = false: the pipe's owner/group/mode is the only gate and \
             no executable is pinned; the reader identity shown to the owner is best effort"
        ));
    }
    Ok(FifoCfg {
        path: f.path.clone(),
        secret: f.secret.clone(),
        owner,
        gid,
        mode,
        enforce_acl: f.enforce_acl,
        attempts_per_min: f.attempts_per_min,
        cooldown_secs: f.cooldown_secs,
        write_deadline_secs: f.write_deadline_secs,
    })
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
    check_metadata_perms(path, &md, trusted_uids)
}

fn check_metadata_perms(
    path: &Path,
    md: &std::fs::Metadata,
    trusted_uids: &[u32],
) -> Result<(), ConfigError> {
    if !trusted_uids.contains(&md.uid()) {
        return err(format!(
            "{} is owned by uid {}, expected root, the invoking user or the daemon user (daemon.user)",
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
        assert_eq!(
            c.approval.as_ref().unwrap().listen.to_string(),
            "127.0.0.1:8443"
        );
        assert_eq!(
            c.approval.as_ref().unwrap().external_host,
            "secretd.example.com"
        );
        assert_eq!(
            c.approval.as_ref().unwrap().oidc.redirect_url,
            "https://secretd.example.com/auth/callback"
        );
        assert_eq!(
            c.approval.as_ref().unwrap().oidc.owner_emails,
            vec!["owner@example.com"]
        );
        assert_eq!(c.limits.max_pending_per_uid, 3);
        assert_eq!(c.daemon.request_timeout_secs, 300);
        assert_eq!(c.approval.as_ref().unwrap().trusted_proxies.len(), 2);
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
        assert_eq!(
            c.approval.as_ref().unwrap().external_host,
            "x.example.com:8444"
        );
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
    fn channels_default_and_rules() {
        let c = parse("").unwrap();
        assert_eq!(
            c.channels.enabled,
            vec![ChannelKind::Web, ChannelKind::Admin]
        );
        let with = |ch: &str| Config::parse(&format!("{BASE}\n[channels]\nenabled = {ch}\n"), &R);
        // Explicit subset, web off: [notify]/[approval] are ignored with a warning.
        let c = with("[\"admin\"]").unwrap();
        assert!(c.notify.is_none() && c.approval.is_none());
        assert!(c.warnings.iter().any(|w| w.contains("ignored")));
        // At least one approval channel.
        assert!(with("[]").unwrap_err().0.contains("at least one"));
        assert!(with("[\"web\", \"web\"]").unwrap_err().0.contains("twice"));
        assert!(with("[\"carrier-pigeon\"]").is_err());
        // Web needs its tables.
        let no_web = "[channels]\nenabled = [\"web\"]\n";
        let e = Config::parse(no_web, &R).unwrap_err();
        assert!(e.0.contains("web"), "{e}");
        // Admin only, no [notify]/[approval] at all: valid.
        let c = Config::parse("[channels]\nenabled = [\"admin\"]\n", &R).unwrap();
        assert_eq!(c.channels.enabled, vec![ChannelKind::Admin]);
        assert_eq!(ChannelKind::HomeAssistant.as_str(), "homeassistant");
    }

    #[test]
    fn homeassistant_rules() {
        let ha = |extra: &str| {
            Config::parse(
                &format!(
                    "{BASE}\n[channels]\nenabled = [\"homeassistant\"]\n[homeassistant]\n\
                     token_file = \"/etc/secretd/ha.token\"\n\
                     notify_service = \"notify.mobile_app_owner_phone\"\n\
                     passphrase_entity = \"input_text.secretd_passphrase\"\n\
                     owner_user_ids = [\"abc123\"]\n{extra}\n"
                ),
                &R,
            )
        };
        let url = |u: &str, extra: &str| ha(&format!("url = \"{u}\"\n{extra}"));
        // https is fine; the WebSocket URL is derived.
        let c = url("https://ha.example.com:8123/", "").unwrap();
        let h = c.homeassistant.unwrap();
        assert_eq!(h.ws_url, "wss://ha.example.com:8123/api/websocket");
        assert!(
            c.approval.is_none() && c.notify.is_none(),
            "HA-only needs no web"
        );
        // Plain http: refused off-loopback unless opted in (then a warning).
        let e = url("http://homeassistant.local:8123", "").unwrap_err();
        assert!(e.0.contains("allow_insecure_http"), "{e}");
        let c = url(
            "http://homeassistant.local:8123",
            "allow_insecure_http = true",
        )
        .unwrap();
        assert!(c.warnings.iter().any(|w| w.contains("unencrypted")));
        assert_eq!(
            c.homeassistant.unwrap().ws_url,
            "ws://homeassistant.local:8123/api/websocket"
        );
        // Loopback http needs no opt-in and no warning.
        for l in [
            "http://127.0.0.1:8123",
            "http://localhost:8123",
            "http://[::1]:8123",
        ] {
            let c = url(l, "").unwrap();
            assert!(!c.warnings.iter().any(|w| w.contains("unencrypted")), "{l}");
        }
        assert!(url("http://127.0.0.1.evil.example", "").is_err());
        assert!(url("ftp://ha", "").is_err());
        // Shape of the service and entity names.
        let bad = |k: &str, v: &str| {
            Config::parse(
                &format!(
                    "{BASE}\n[channels]\nenabled = [\"homeassistant\"]\n[homeassistant]\n\
                     url = \"https://ha\"\ntoken_file = \"/t\"\nowner_user_ids = [\"a\"]\n\
                     notify_service = \"{}\"\npassphrase_entity = \"{}\"\n",
                    if k == "svc" { v } else { "notify.mobile_app_x" },
                    if k == "ent" { v } else { "input_text.p" }
                ),
                &R,
            )
        };
        assert!(bad("svc", "light.turn_on").is_err());
        assert!(bad("ent", "sensor.x").is_err());
        assert!(bad("ent", "input_text.p").is_ok());
        // owner_user_ids is mandatory unless the user-id requirement is opted out.
        let no_ids = |extra: &str| {
            Config::parse(
                &format!(
                    "{BASE}\n[channels]\nenabled = [\"homeassistant\"]\n[homeassistant]\n\
                     url = \"https://ha\"\ntoken_file = \"/t\"\n\
                     notify_service = \"notify.mobile_app_x\"\n\
                     passphrase_entity = \"input_text.p\"\n{extra}\n"
                ),
                &R,
            )
        };
        assert!(no_ids("").is_err());
        let c = no_ids("ha_require_user_id = false").unwrap();
        assert!(c.warnings.iter().any(|w| w.contains("ha_require_user_id")));
        assert!(!c.homeassistant.unwrap().require_user_id);
        // Enabled without the table, and the table without the channel.
        assert!(Config::parse(
            &format!("{BASE}\n[channels]\nenabled = [\"homeassistant\"]\n"),
            &R
        )
        .is_err());
        let c = Config::parse(
            &format!(
                "{BASE}\n[homeassistant]\nurl = \"https://ha\"\ntoken_file = \"/t\"\n\
                 notify_service = \"notify.x\"\npassphrase_entity = \"input_text.p\"\n"
            ),
            &R,
        )
        .unwrap();
        assert!(c.homeassistant.is_none());
        assert!(c.warnings.iter().any(|w| w.contains("homeassistant")));
    }

    #[test]
    fn fifo_rules() {
        let fifo = |body: &str| {
            Config::parse(
                &format!(
                    "{BASE}\n[[secret]]\nname='db'\nallow_uids=[1000]\nallow_exes=['/x']\n\
                     [[fifo]]\npath = \"/run/secretd/pipes/db\"\nsecret = \"db\"\n\
                     group = \"devs\"\n{body}\n"
                ),
                &R,
            )
        };
        let c = fifo("").unwrap();
        let f = &c.fifos[0];
        assert_eq!((f.gid, f.owner, f.mode), (100, None, 0o640));
        assert!(!f.enforce_acl);
        assert_eq!(
            (f.attempts_per_min, f.cooldown_secs, f.write_deadline_secs),
            (10, 5, 5)
        );
        assert!(c.warnings.iter().any(|w| w.contains("enforce_acl = false")));
        let c = fifo("owner = \"alice\"\nmode = \"0460\"\nenforce_acl = true").unwrap();
        assert_eq!((c.fifos[0].owner, c.fifos[0].mode), (Some(1000), 0o460));
        assert!(!c.warnings.iter().any(|w| w.contains("enforce_acl = false")));
        // Modes: octal strings only, nothing for `other`, nobody unable to read.
        for bad in [
            "\"0644\"", "\"0666\"", "\"4640\"", "\"0200\"", "\"640\"", "\"0x40\"", "\"0480\"",
            "440",
        ] {
            assert!(fifo(&format!("mode = {bad}")).is_err(), "{bad}");
        }
        assert!(fifo("mode = \"0440\"").is_ok());
        assert!(fifo("mode = \"0660\"")
            .unwrap()
            .warnings
            .iter()
            .any(|w| w.contains("write")));
        // Secret must exist, names must resolve, paths must be sane and unique.
        let raw = |path: &str, secret: &str, extra: &str| {
            Config::parse(
                &format!(
                    "{BASE}\n[[secret]]\nname='db'\nallow_uids=[1000]\nallow_exes=['/x']\n\
                     [[fifo]]\npath = \"{path}\"\nsecret = \"{secret}\"\ngroup = 100\n{extra}\n"
                ),
                &R,
            )
        };
        assert!(raw("/p/a", "db", "").is_ok());
        assert!(raw("/p/a", "missing", "")
            .unwrap_err()
            .0
            .contains("not defined"));
        assert!(raw("rel/p", "db", "").is_err());
        assert!(raw("/p/../a", "db", "").is_err());
        assert!(raw("/p/a/", "db", "").is_err());
        assert!(raw("/p/a", "db", "owner = \"bob\"").is_err());
        assert!(raw("/p/a", "db", "attempts_per_min = 0").is_err());
        assert!(raw("/p/a", "db", "write_deadline_secs = 0").is_err());
        assert!(raw("/p/a", "db", "cooldown_secs = 0").is_ok());
        assert!(raw("/var/lib/secretd/store.age", "db", "").is_err());
        // Two pipes may serve the same secret; the same path twice is an error.
        let two = |p2: &str| {
            Config::parse(
                &format!(
                    "{BASE}\n[[secret]]\nname='db'\nallow_uids=[1000]\nallow_exes=['/x']\n\
                     [[fifo]]\npath = \"/p/a\"\nsecret = \"db\"\ngroup = 100\n\
                     [[fifo]]\npath = \"{p2}\"\nsecret = \"db\"\ngroup = 100\n"
                ),
                &R,
            )
        };
        assert_eq!(two("/p/b").unwrap().fifos.len(), 2);
        assert!(two("/p/a").is_err());
    }

    #[test]
    fn packaged_example_config_parses() {
        let text = include_str!("../../../packaging/config.example.toml");
        let c = Config::parse(text, &R).unwrap();
        assert_eq!(c.secrets[0].name, "db-password");
        assert_eq!(c.daemon.socket_mode, 0o660);
        assert_eq!(
            c.approval.as_ref().unwrap().external_host,
            "secretd.example.com"
        );
        assert_eq!(c.notify.as_ref().unwrap().attempts, 3);
    }

    #[test]
    fn ownership_check_uses_the_configured_daemon_user() {
        use std::os::unix::fs::PermissionsExt;
        // Needs root to give the file to another uid.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("not root; skipping");
            return;
        }
        struct Svc;
        impl NameResolver for Svc {
            fn uid(&self, n: &str) -> Option<u32> {
                (n == "svc").then_some(54321)
            }
            fn gid(&self, _: &str) -> Option<u32> {
                None
            }
        }
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.toml");
        let write = |daemon_user: &str| {
            std::fs::write(&p, format!("[daemon]\nuser = \"{daemon_user}\"\n{}", BASE)).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
            std::os::unix::fs::chown(&p, Some(54321), None).unwrap();
        };
        // Owned by `svc`, which is the configured daemon user: accepted even
        // though only root is passed as trusted (no hard-coded "secretd").
        write("svc");
        assert!(Config::load(&p, &[0], &Svc).is_ok());
        // Same owner but the file names a different daemon user: rejected.
        write("other");
        let e = Config::load(&p, &[0], &Svc).unwrap_err();
        assert!(e.0.contains("owned by uid 54321"), "{e}");
        // A file owned by a user called "secretd" is no longer special.
        struct Secretd;
        impl NameResolver for Secretd {
            fn uid(&self, n: &str) -> Option<u32> {
                (n == "secretd").then_some(54321)
            }
            fn gid(&self, _: &str) -> Option<u32> {
                None
            }
        }
        write("svc");
        assert!(Config::load(&p, &[0], &Secretd).is_err());
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
