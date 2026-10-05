//! Request broker: ACL checks, rate limits, the pending-request registry and
//! the approve/deny/release logic shared by the HTTP and admin endpoints.

use crate::audit::{Audit, AuditEvent};
use crate::channel::{AdminChannel, Channel, Closed, WebChannel};
use crate::notify::{Notification, Notifier};
use crate::peer::PeerCred;
use crate::procinfo::{ProcInfo, ProcInfoReader};
use secret_proto::acl::{self, CallerIds};
use secret_proto::config::{ChannelKind, Config};
use secret_proto::rpc::{ErrorKind, GetParams, PendingInfo, RpcError};
use secret_proto::sanitize;
use secret_proto::store::{self, Passphrase, StoreError};
use secret_proto::{valid_secret_name, Encoding, MAX_REASON_CHARS};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use time::format_description::well_known::Rfc3339;
use tokio::sync::oneshot;
use tokio::time::Instant;
use zeroize::Zeroizing;

/// Passphrase attempts allowed per request.
pub const MAX_ATTEMPTS: u8 = 3;

/// Identity of a connected client, captured once at connect time.
#[derive(Debug, Clone)]
pub struct Caller {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub username: String,
    /// `None` when process resolution (`/proc`, libproc) failed: every request is then denied.
    pub proc: Option<ProcInfo>,
    /// `SO_PEERPIDFD` handle, when the kernel provides one: lets a recycled
    /// pid be told apart from the process that connected.
    pub pidfd: Option<Arc<OwnedFd>>,
}

/// A decrypted secret on its way to the client.
pub struct Released {
    pub name: String,
    pub value: Zeroizing<String>,
    pub encoding: Encoding,
}

enum Outcome {
    /// The secret, plus a channel on which the waiting request handler
    /// confirms that the `released` audit event was written (so the owner is
    /// only told "released" when that is true).
    Released {
        rel: Released,
        source: Source,
        ack: oneshot::Sender<Delivery>,
    },
    Denied,
    DecryptFailed,
    CallerChanged,
    NotFound,
    Internal,
}

/// Where an owner action came from (for the audit log).
#[derive(Debug, Clone, Copy)]
pub enum Source {
    Http(IpAddr),
    Admin,
    HomeAssistant,
}

impl Source {
    /// Source address of an HTTP action; `None` for other channels.
    pub fn ip(self) -> Option<IpAddr> {
        match self {
            Source::Http(ip) => Some(ip),
            Source::Admin | Source::HomeAssistant => None,
        }
    }

    /// The approval channel the action arrived through.
    pub fn channel(self) -> ChannelKind {
        match self {
            Source::Http(_) => ChannelKind::Web,
            Source::Admin => ChannelKind::Admin,
            Source::HomeAssistant => ChannelKind::HomeAssistant,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ApproveOutcome {
    /// The secret was released to the waiting client.
    Released,
    /// Wrong passphrase; the owner may retry.
    WrongPassphrase {
        remaining: u8,
    },
    /// Final wrong passphrase; the client got `DECRYPT_FAILED`.
    Failed,
    /// Unknown, expired, cancelled or already-resolved request.
    Gone,
    /// Another approval of the same request is in progress.
    Busy,
    /// The client stopped waiting (timeout, disconnect) while the store was
    /// being unsealed; nothing was released.
    Aborted,
    /// Caller identity changed; request aborted with `CALLER_CHANGED`.
    CallerChanged,
    /// The secret is not in the store (config/store mismatch).
    NotInStore,
    Internal,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DenyOutcome {
    Denied,
    /// Denied, but the audit log could not be written (reported, not hidden).
    DeniedUnaudited,
    Gone,
    /// An approval of this request is being processed right now; it can no
    /// longer be denied (the client will receive the secret or an abort).
    Busy,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TokenCheck {
    Unknown,
    Mismatch,
    Ok,
}

/// Where a request came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// A client on the Unix socket (`secret.get`).
    Socket,
    /// A reader that opened the named pipe at this path (section 20).
    Fifo(String),
}

/// What [`Core::request_approval`] needs to know about a request.
pub struct RequestSpec {
    pub origin: Origin,
    pub secret: String,
    /// Already sanitised.
    pub reason: Option<String>,
    /// The client (socket) or the one identified reader (FIFO; `None` when no
    /// reader process could be identified).
    pub caller: Option<Caller>,
    /// How long the owner has to answer.
    pub wait: Duration,
}

/// What became of an approved value (reported back to the approver).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Fully delivered (and audited, for socket clients).
    Released,
    /// The requester could not be re-verified at release time; nothing was sent.
    CallerChanged,
    /// The requester went away or the write failed; nothing (complete) was sent.
    Aborted,
    /// Any other failure (for example the audit log).
    Failed,
}

/// An approved request on its way to the requester. The approver is told
/// "released" only after [`Grant::finish`] confirmed that the value really
/// reached the requester (and was audited).
pub struct Grant {
    pub id: String,
    pub rel: Released,
    pub source: Source,
    ack: oneshot::Sender<Delivery>,
}

impl Grant {
    /// Report the delivery result to the approver and take the value.
    pub fn finish(self, result: Delivery) -> Released {
        let _ = self.ack.send(result);
        self.rel
    }
}

struct Pending {
    token: String,
    caller: Option<Caller>,
    origin: Origin,
    secret: String,
    description: Option<String>,
    reason: Option<String>,
    expires: Instant,
    expires_at: SystemTime,
    attempts: u8,
    busy: bool,
    tx: Option<oneshot::Sender<Outcome>>,
}

#[derive(Default)]
struct State {
    pending: HashMap<String, Pending>,
    gets: HashMap<u32, VecDeque<Instant>>,
    conns_by_uid: HashMap<u32, usize>,
    conns_total: usize,
}

/// How long an announcement that is still in flight when its request is
/// resolved may keep going before it is abandoned.
const ANNOUNCE_GRACE: Duration = Duration::from_secs(15);

/// Announcements still running when their request was resolved.
struct LateAnnounces {
    tasks: tokio::task::JoinSet<(usize, ChannelKind, Result<(), ()>)>,
    /// Task id -> index into the channel list.
    idx: HashMap<tokio::task::Id, usize>,
}

/// Add the identity of the requester (and the pipe) to an audit event.
fn stamp(mut ev: AuditEvent, caller: Option<&Caller>, origin: &Origin) -> AuditEvent {
    if let Origin::Fifo(p) = origin {
        ev.fifo = Some(p.clone());
    }
    if let Some(c) = caller {
        ev.uid = Some(c.uid);
        ev.gid = Some(c.gid);
        ev.pid = Some(c.pid);
        ev.exe = c.proc.as_ref().map(|p| p.exe.clone());
    }
    ev
}

/// Default window over which repeated rejections are folded into one summary line.
pub const COALESCE_WINDOW: Duration = Duration::from_secs(60);
const COALESCE_MAX_KEYS: usize = 4096;

/// One (event, outcome, subject) bucket of the audit coalescer.
struct Slot {
    start: Instant,
    suppressed: u64,
    template: AuditEvent,
}

type CoalesceKey = (&'static str, String, String);

pub struct Core {
    cfg: RwLock<Arc<Config>>,
    state: Mutex<State>,
    coalesce: Mutex<HashMap<CoalesceKey, Slot>>,
    coalesce_window: Mutex<Duration>,
    audit: Arc<Audit>,
    channels: Vec<Arc<dyn Channel>>,
    procs: Arc<dyn ProcInfoReader>,
    /// Serialises unsealing: one scrypt derivation can need hundreds of MiB.
    unseal_gate: tokio::sync::Semaphore,
    /// Test hook: artificial delay inside the blocking unseal task, to widen
    /// the race window between approve and deny/timeout/disconnect.
    unseal_delay: Mutex<Duration>,
    /// How long announcements still running after their request resolved may
    /// continue (test hook; defaults to [`ANNOUNCE_GRACE`]).
    announce_grace: Mutex<Duration>,
}

/// Decrements the connection counters when dropped.
pub struct ConnGuard {
    core: Arc<Core>,
    uid: u32,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut st = self.core.lock();
        st.conns_total = st.conns_total.saturating_sub(1);
        if let Some(n) = st.conns_by_uid.get_mut(&self.uid) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                st.conns_by_uid.remove(&self.uid);
            }
        }
    }
}

fn random_hex(n: usize) -> Option<String> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).ok()?;
    Some(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn random_token() -> Option<String> {
    use base64::Engine;
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).ok()?;
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b))
}

fn rfc3339(t: SystemTime) -> String {
    time::OffsetDateTime::from(t)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

fn internal() -> RpcError {
    RpcError::new(ErrorKind::Internal)
}

impl Core {
    /// A core with the classic channel pair: `web` (announcing through
    /// `notifier`) and `admin`.
    pub fn new(
        cfg: Config,
        audit: Audit,
        notifier: Arc<dyn Notifier>,
        procs: Arc<dyn ProcInfoReader>,
    ) -> Arc<Core> {
        Self::with_channels(
            cfg,
            audit,
            vec![Arc::new(WebChannel::new(notifier)), Arc::new(AdminChannel)],
            procs,
        )
    }

    /// A core with an explicit set of enabled channels.
    pub fn with_channels(
        cfg: Config,
        audit: Audit,
        channels: Vec<Arc<dyn Channel>>,
        procs: Arc<dyn ProcInfoReader>,
    ) -> Arc<Core> {
        Arc::new(Core {
            cfg: RwLock::new(Arc::new(cfg)),
            state: Mutex::new(State::default()),
            coalesce: Mutex::new(HashMap::new()),
            coalesce_window: Mutex::new(COALESCE_WINDOW),
            audit: Arc::new(audit),
            channels,
            procs,
            unseal_gate: tokio::sync::Semaphore::new(1),
            unseal_delay: Mutex::new(Duration::ZERO),
            announce_grace: Mutex::new(ANNOUNCE_GRACE),
        })
    }

    /// Test hook: make every unseal take at least `d` longer.
    #[doc(hidden)]
    pub fn set_unseal_delay(&self, d: Duration) {
        *self.unseal_delay.lock().unwrap_or_else(|e| e.into_inner()) = d;
    }

    /// Test hook: shorten the grace period of in-flight announcements.
    #[doc(hidden)]
    pub fn set_announce_grace(&self, d: Duration) {
        *self
            .announce_grace
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = d;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn config(&self) -> Arc<Config> {
        self.cfg.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Swap in a reloaded configuration (SIGHUP).
    pub fn set_config(&self, cfg: Config) {
        *self.cfg.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(cfg);
    }

    pub fn audit(&self, ev: &AuditEvent) -> std::io::Result<()> {
        self.audit.log(ev).inspect_err(|e| {
            tracing::error!("audit log write failed: {e}");
        })
    }

    fn audit_for(&self, ev: AuditEvent, caller: &Caller) -> std::io::Result<()> {
        let mut ev = ev;
        ev.uid = Some(caller.uid);
        ev.gid = Some(caller.gid);
        ev.pid = Some(caller.pid);
        ev.exe = caller.proc.as_ref().map(|p| p.exe.clone());
        self.audit(&ev)
    }

    /// Audit an event about a request: identity of the requester when known,
    /// and the FIFO path for pipe requests.
    pub fn audit_req(
        &self,
        ev: AuditEvent,
        caller: Option<&Caller>,
        origin: &Origin,
    ) -> io::Result<()> {
        self.audit(&stamp(ev, caller, origin))
    }

    fn rejection_event(
        &self,
        event: &'static str,
        name: &str,
        outcome: &str,
        caller: &Caller,
    ) -> AuditEvent {
        let mut ev = AuditEvent::new(event).secret(name).outcome(outcome);
        ev.uid = Some(caller.uid);
        ev.gid = Some(caller.gid);
        ev.pid = Some(caller.pid);
        ev.exe = caller.proc.as_ref().map(|p| p.exe.clone());
        ev
    }

    /// Reopen the audit log file (SIGHUP, after log rotation).
    pub fn reopen_audit(&self) -> io::Result<()> {
        self.audit.reopen()
    }

    fn window(&self) -> Duration {
        *self
            .coalesce_window
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Test hook: shorten the coalescing window.
    #[doc(hidden)]
    pub fn set_coalesce_window(&self, d: Duration) {
        *self
            .coalesce_window
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = d;
    }

    fn summary_for(slot: &Slot, window: Duration) -> AuditEvent {
        let mut ev = slot.template.clone();
        ev.secret_name = None;
        ev.request_id = None;
        ev.pid = None;
        ev.exe = None;
        ev.detail = Some(format!(
            "summary: {} further event(s) suppressed in {}s window",
            slot.suppressed,
            window.as_secs().max(1)
        ));
        ev
    }

    /// Audit a rejection that anyone local can trigger at will (rate limit,
    /// ACL miss, changed caller, HTTP failure limiter). The first event per
    /// `(event, outcome, subject)` in each window is written in full; the
    /// rest only bump a counter, flushed as one summary line per window. This
    /// bounds the audit volume a local user can cause. A write error is
    /// returned only for lines actually written.
    pub fn audit_coalesced(&self, ev: AuditEvent, subject: &str) -> io::Result<()> {
        let now = Instant::now();
        let window = self.window();
        let key: CoalesceKey = (
            ev.event,
            ev.outcome.clone().unwrap_or_default(),
            subject.to_string(),
        );
        let mut summaries = Vec::new();
        let write_now = {
            let mut c = self.coalesce.lock().unwrap_or_else(|e| e.into_inner());
            if c.len() >= COALESCE_MAX_KEYS && !c.contains_key(&key) {
                for (_, slot) in c.drain() {
                    if slot.suppressed > 0 {
                        summaries.push(Self::summary_for(&slot, window));
                    }
                }
            }
            match c.get_mut(&key) {
                Some(slot) if now.duration_since(slot.start) < window => {
                    slot.suppressed += 1;
                    false
                }
                Some(slot) => {
                    if slot.suppressed > 0 {
                        summaries.push(Self::summary_for(slot, window));
                    }
                    slot.start = now;
                    slot.suppressed = 0;
                    slot.template = ev.clone();
                    true
                }
                None => {
                    c.insert(
                        key,
                        Slot {
                            start: now,
                            suppressed: 0,
                            template: ev.clone(),
                        },
                    );
                    true
                }
            }
        };
        for s in &summaries {
            let _ = self.audit(s);
        }
        if write_now {
            self.audit(&ev)
        } else {
            Ok(())
        }
    }

    /// Write out summaries for buckets whose window has elapsed (all of them
    /// when `force`, e.g. at shutdown). Called periodically by the daemon.
    pub fn flush_audit_summaries(&self, force: bool) {
        let now = Instant::now();
        let window = self.window();
        let mut out = Vec::new();
        {
            let mut c = self.coalesce.lock().unwrap_or_else(|e| e.into_inner());
            c.retain(|_, slot| {
                let due = force || now.duration_since(slot.start) >= window;
                if due && slot.suppressed > 0 {
                    out.push(Self::summary_for(slot, window));
                }
                !due
            });
        }
        for s in &out {
            let _ = self.audit(s);
        }
    }

    // ------------------------------------------------------------ identity

    /// First step after `accept`: snapshot the peer's `/proc` identity. This
    /// is deliberately synchronous and does nothing else (no name lookups, no
    /// cap checks), to keep the window small in which a process can connect,
    /// fork and exec an allowed binary before the daemon looks.
    pub fn capture(&self, cred: PeerCred, pidfd: Option<OwnedFd>) -> Caller {
        let proc = match self.procs.read(cred.pid) {
            Ok(p) => Some(p),
            Err(e) => {
                tracing::warn!("cannot resolve /proc for pid {}: {e}", cred.pid);
                None
            }
        };
        // A pidfd that does not name the SO_PEERCRED pid (pid namespaces) is
        // not trusted for liveness checks.
        let pidfd = pidfd.filter(|fd| crate::peer::pidfd_pid(fd.as_fd()) == Some(cred.pid));
        Caller {
            uid: cred.uid,
            gid: cred.gid,
            pid: cred.pid,
            username: String::new(),
            proc,
            pidfd: pidfd.map(Arc::new),
        }
    }

    /// Fill in the (possibly slow, NSS-backed) user name.
    pub fn resolve_username(&self, caller: &mut Caller) {
        caller.username = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(caller.uid))
            .ok()
            .flatten()
            .map(|u| sanitize::clean(&u.name, 64))
            .unwrap_or_else(|| format!("uid{}", caller.uid));
    }

    /// Build a [`Caller`] from kernel-verified credentials, capturing `/proc`
    /// details once.
    pub fn identify(&self, cred: PeerCred) -> Caller {
        let mut c = self.capture(cred, None);
        self.resolve_username(&mut c);
        c
    }

    /// Does `caller` pass the ACL of secret `name` (uid/gid and executable)?
    pub fn allowed(cfg: &Config, caller: &Caller, name: &str) -> bool {
        let Some(proc) = &caller.proc else {
            return false;
        };
        match cfg.secret(name) {
            Some(s) => acl::is_allowed(
                s,
                &CallerIds {
                    uid: caller.uid,
                    gid: caller.gid,
                    exe: &proc.exe,
                },
            ),
            None => false,
        }
    }

    /// Names the caller passes the ACL for.
    pub fn list_names(&self, caller: &Caller) -> Vec<String> {
        if caller.proc.is_some() && !self.verify_caller(caller) {
            return Vec::new();
        }
        let cfg = self.config();
        cfg.secrets
            .iter()
            .filter(|s| Self::allowed(&cfg, caller, &s.name))
            .map(|s| s.name.clone())
            .collect()
    }

    // --------------------------------------------------------- connections

    /// Enforce the connection caps. `None` means a cap was hit.
    pub fn acquire_conn(self: &Arc<Self>, uid: u32) -> Option<ConnGuard> {
        let cfg = self.config();
        let mut st = self.lock();
        let per_uid = st.conns_by_uid.get(&uid).copied().unwrap_or(0);
        if st.conns_total >= cfg.limits.max_conns_total || per_uid >= cfg.limits.max_conns_per_uid {
            return None;
        }
        st.conns_total += 1;
        *st.conns_by_uid.entry(uid).or_insert(0) += 1;
        Some(ConnGuard {
            core: self.clone(),
            uid,
        })
    }

    // ------------------------------------------------------------- get flow

    /// Handle `secret.get`: blocks until approved, denied, timed out, or the
    /// client disconnects (`disconnect` resolves).
    pub async fn get(
        &self,
        caller: &Caller,
        params: GetParams,
        disconnect: impl Future<Output = ()>,
    ) -> Result<Released, RpcError> {
        if !valid_secret_name(&params.name) {
            return Err(RpcError::new(ErrorKind::InvalidParams));
        }
        let name = params.name;
        let reason = params
            .reason
            .as_deref()
            .map(|r| sanitize::clean(r, MAX_REASON_CHARS))
            .filter(|r| !r.is_empty());
        let cfg = self.config();

        let subject = caller.uid.to_string();

        // Re-read /proc now: the connection may have been inherited by (or
        // outlived) the process we looked at when it was accepted. Any change
        // of executable or start time, or the process being gone, is refused.
        if caller.proc.is_some() && !self.verify_caller(caller) {
            // Refusing is the safe direction; the audit result is only logged.
            let _ = self.audit_coalesced(
                self.rejection_event("caller_changed", &name, "at_request", caller),
                &subject,
            );
            return Err(RpcError::new(ErrorKind::CallerChanged));
        }

        // Per-uid attempt rate limit comes first and applies to every name,
        // so a rate-limit response reveals nothing about ACLs.
        if !self.record_get_attempt(caller.uid, cfg.limits.max_gets_per_uid_per_min) {
            self.audit_coalesced(
                self.rejection_event("rate_limited", &name, "attempt_rate", caller),
                &subject,
            )
            .map_err(|_| internal())?;
            return Err(RpcError::new(ErrorKind::RateLimited));
        }

        if !Self::allowed(&cfg, caller, &name) {
            let why = if caller.proc.is_none() {
                "proc_unavailable"
            } else {
                "acl"
            };
            self.audit_coalesced(
                self.rejection_event("acl_denied", &name, why, caller),
                &subject,
            )
            .map_err(|_| internal())?;
            return Err(RpcError::new(ErrorKind::NotFound));
        }

        // Only requests that can actually reach the owner are logged one by
        // one (and fail closed when the log is dead): rejections above are
        // coalesced, and the attempt limiter above bounds how many requests per
        // minute and uid get this far.
        self.audit_for(AuditEvent::new("request_received").secret(&name), caller)
            .map_err(|_| internal())?;
        if caller.proc.is_none() {
            return Err(internal());
        }

        let max_wait = cfg.daemon.request_timeout_secs;
        let wait = params
            .timeout_secs
            .map_or(max_wait, |t| t.clamp(1, max_wait));
        let grant = self
            .request_approval(
                RequestSpec {
                    origin: Origin::Socket,
                    secret: name.clone(),
                    reason,
                    caller: Some(caller.clone()),
                    wait: Duration::from_secs(wait),
                },
                disconnect,
            )
            .await?;
        // The handler that waits for the client audits the release; the
        // approver is told "released" only if that succeeded.
        let audited = self
            .audit_for(
                AuditEvent::new("released")
                    .request(&grant.id)
                    .secret(&name)
                    .source(grant.source.ip())
                    .channel(grant.source.channel()),
                caller,
            )
            .is_ok();
        let rel = grant.finish(if audited {
            Delivery::Released
        } else {
            Delivery::Failed
        });
        if audited {
            Ok(rel)
        } else {
            Err(internal())
        }
    }

    /// Create a pending request, announce it on every notification channel and
    /// wait for the owner: the part of a release that is the same for socket
    /// clients and named pipes. Returns the [`Grant`] once approved; the caller
    /// delivers the value, audits `released` and calls [`Grant::finish`].
    /// `disconnect` resolves when the requester went away.
    pub async fn request_approval(
        &self,
        spec: RequestSpec,
        disconnect: impl Future<Output = ()>,
    ) -> Result<Grant, RpcError> {
        let RequestSpec {
            origin,
            secret: name,
            reason,
            caller,
            wait,
        } = spec;
        let cfg = self.config();
        let secret_cfg = cfg.secret(&name).ok_or_else(internal)?;
        let caller = caller.as_ref();
        let proc = caller.and_then(|c| c.proc.as_ref());
        if origin == Origin::Socket && proc.is_none() {
            return Err(internal());
        }
        let now = Instant::now();
        let deadline = now + wait;
        let id = random_hex(16).ok_or_else(internal)?;
        let token = random_token().ok_or_else(internal)?;
        let (tx, mut rx) = oneshot::channel();

        let expires_at = SystemTime::now() + wait;
        {
            let mut st = self.lock();
            let limited = match &origin {
                Origin::Socket => {
                    let c = caller.ok_or_else(internal)?;
                    let socket = |p: &&Pending| p.origin == Origin::Socket;
                    let dup = st.pending.values().filter(socket).any(|p| {
                        p.secret == name
                            && p.caller.as_ref().map(|x| x.uid) == Some(c.uid)
                            && p.caller
                                .as_ref()
                                .and_then(|x| x.proc.as_ref())
                                .map(|x| &x.exe)
                                == proc.map(|x| &x.exe)
                    });
                    let per_uid = st
                        .pending
                        .values()
                        .filter(socket)
                        .filter(|p| p.caller.as_ref().map(|x| x.uid) == Some(c.uid))
                        .count();
                    if dup {
                        Some("duplicate")
                    } else if per_uid >= cfg.limits.max_pending_per_uid {
                        Some("pending_per_uid")
                    } else if st.pending.len() >= cfg.limits.max_pending_total {
                        Some("pending_total")
                    } else {
                        None
                    }
                }
                // Per-request limits of a pipe are keyed on the pipe: one
                // pending request at a time, plus the global cap.
                Origin::Fifo(path) => {
                    if st
                        .pending
                        .values()
                        .any(|p| p.origin == Origin::Fifo(path.clone()))
                    {
                        Some("fifo_pending")
                    } else if st.pending.len() >= cfg.limits.max_pending_total {
                        Some("pending_total")
                    } else {
                        None
                    }
                }
            };
            if let Some(why) = limited {
                drop(st);
                let (ev, subject) = match (&origin, caller) {
                    (Origin::Socket, Some(c)) => (
                        self.rejection_event("rate_limited", &name, why, c),
                        c.uid.to_string(),
                    ),
                    (Origin::Fifo(path), _) => {
                        let mut ev = AuditEvent::new("rate_limited").secret(&name).outcome(why);
                        ev.fifo = Some(path.clone());
                        (ev, path.clone())
                    }
                    _ => return Err(internal()),
                };
                self.audit_coalesced(ev, &subject).map_err(|_| internal())?;
                return Err(RpcError::new(ErrorKind::RateLimited));
            }
            st.pending.insert(
                id.clone(),
                Pending {
                    token: token.clone(),
                    caller: caller.cloned(),
                    origin: origin.clone(),
                    secret: name.clone(),
                    description: secret_cfg.description.clone(),
                    reason: reason.clone(),
                    expires: deadline,
                    expires_at,
                    attempts: 0,
                    busy: false,
                    tx: Some(tx),
                },
            );
        }

        let notification = Arc::new(Notification {
            request_id: id.clone(),
            secret_name: name.clone(),
            description: secret_cfg.description.clone(),
            uid: caller.map_or(0, |c| c.uid),
            username: caller.map_or_else(|| "unknown".into(), |c| c.username.clone()),
            pid: caller.map_or(0, |c| c.pid),
            exe: proc.map_or_else(|| "unknown".into(), |p| sanitize::clean(&p.exe, 512)),
            cmdline: proc.map(|p| p.cmdline.clone()).unwrap_or_default(),
            reason,
            expires_at: rfc3339(expires_at),
            approval_url: cfg
                .approval
                .as_ref()
                .map(|a| format!("{}/approve/{id}?t={token}", a.external_url))
                .unwrap_or_default(),
            approval_token: token.clone(),
            via: match &origin {
                Origin::Socket => None,
                Origin::Fifo(p) => Some(format!("via FIFO {}", sanitize::clean(p, 512))),
            },
            identified: caller.is_some(),
        });

        // Announce on every enabled notification channel at once.
        let mut announces: tokio::task::JoinSet<(usize, ChannelKind, Result<(), ()>)> =
            tokio::task::JoinSet::new();
        let mut task_idx: HashMap<tokio::task::Id, usize> = HashMap::new();
        for (idx, ch) in self
            .channels
            .iter()
            .enumerate()
            .filter(|(_, c)| c.announces())
        {
            let (ch, n) = (ch.clone(), notification.clone());
            let handle = announces.spawn(async move {
                let kind = ch.kind();
                match ch.announce(&n).await {
                    Ok(()) => (idx, kind, Ok(())),
                    Err(e) => {
                        tracing::error!("{} channel: {e}", kind.as_str());
                        (idx, kind, Err(()))
                    }
                }
            });
            task_idx.insert(handle.id(), idx);
        }
        // With no announcing channel (admin only) the request is armed at once.
        let mut notified = announces.is_empty();
        tokio::pin!(disconnect);

        enum Done {
            Outcome(Option<Outcome>),
            NotifyFailed,
            Timeout,
            Gone,
        }
        // The owner cannot act before the first `notified` is audited, so the
        // outcome channel is only polled afterwards (keeps the audit order
        // stable). A channel that fails is audited (`notify_failed`) but only
        // ends the request when every announcing channel failed.
        let mut done = loop {
            tokio::select! {
                Some(joined) = announces.join_next_with_id(), if !announces.is_empty() => {
                    let (tid, joined) = match joined {
                        Ok((tid, v)) => (tid, Ok(v)),
                        Err(e) => (e.id(), Err(e)),
                    };
                    task_idx.remove(&tid);
                    let Ok((_, kind, res)) = joined else {
                        // The announce task itself panicked: count it as a failure.
                        if announces.is_empty() && !notified {
                            break Done::NotifyFailed;
                        }
                        continue;
                    };
                    match res {
                        Ok(()) => {
                            let ev = AuditEvent::new("notified")
                                .request(&id)
                                .secret(&name)
                                .channel(kind);
                            if self.audit_req(ev, caller, &origin).is_err() {
                                // Fail closed: an unlogged notification must not arm the request.
                                break Done::NotifyFailed;
                            }
                            notified = true;
                        }
                        Err(()) => {
                            let ev = AuditEvent::new("notify_failed")
                                .request(&id)
                                .secret(&name)
                                .channel(kind);
                            let _ = self.audit_req(ev, caller, &origin);
                            if announces.is_empty() && !notified {
                                break Done::NotifyFailed;
                            }
                        }
                    }
                }
                o = &mut rx, if notified => break Done::Outcome(o.ok()),
                _ = tokio::time::sleep_until(deadline) => break Done::Timeout,
                _ = &mut disconnect => break Done::Gone,
            }
        };
        // Close the channel before deciding: from here on an approver's
        // `send` fails (and the owner is told), unless it already succeeded,
        // in which case the outcome is honoured. This makes "who won" atomic.
        if matches!(done, Done::Timeout | Done::Gone) {
            rx.close();
            if let Ok(o) = rx.try_recv() {
                done = Done::Outcome(Some(o));
            }
        }

        let (result, why) = match done {
            Done::Outcome(Some(outcome)) => match outcome {
                Outcome::Released { rel, source, ack } => (
                    Ok(Grant {
                        id: id.clone(),
                        rel,
                        source,
                        ack,
                    }),
                    Closed::Released,
                ),
                Outcome::Denied => (Err(RpcError::new(ErrorKind::Denied)), Closed::Denied),
                Outcome::DecryptFailed => {
                    (Err(RpcError::new(ErrorKind::DecryptFailed)), Closed::Failed)
                }
                Outcome::CallerChanged => {
                    (Err(RpcError::new(ErrorKind::CallerChanged)), Closed::Failed)
                }
                Outcome::NotFound => (Err(RpcError::new(ErrorKind::NotFound)), Closed::Failed),
                Outcome::Internal => (Err(internal()), Closed::Failed),
            },
            Done::Outcome(None) => {
                self.remove(&id);
                (Err(internal()), Closed::Failed)
            }
            Done::NotifyFailed => {
                // Each failing channel was audited above.
                self.remove(&id);
                (Err(internal()), Closed::Failed)
            }
            Done::Timeout => {
                self.remove(&id);
                let audited = self.audit_req(
                    AuditEvent::new("timeout").request(&id).secret(&name),
                    caller,
                    &origin,
                );
                let r = if audited.is_ok() {
                    Err(RpcError::new(ErrorKind::Timeout))
                } else {
                    Err(internal())
                };
                (r, Closed::Timeout)
            }
            Done::Gone => {
                self.remove(&id);
                let outcome = match origin {
                    Origin::Socket => "cancelled",
                    Origin::Fifo(_) => "reader_gone",
                };
                let _ = self.audit_req(
                    AuditEvent::new("client_disconnected")
                        .request(&id)
                        .secret(&name)
                        .outcome(outcome),
                    caller,
                    &origin,
                );
                (Err(internal()), Closed::Cancelled)
            }
        };
        // Tell every channel that the request is closed (first resolution
        // wins: a Home Assistant notification is cleared, the web URL already
        // answers 410). Detached so a slow channel never delays the client.
        // Announcements still in flight are not abandoned: they finish (within
        // a grace period), are audited, and only then is their channel told.
        let late = (!announces.is_empty()).then(|| LateAnnounces {
            tasks: announces,
            idx: task_idx,
        });
        self.close_channels(&id, &name, why, late, caller.cloned(), origin);
        result
    }

    fn close_channels(
        &self,
        id: &str,
        name: &str,
        why: Closed,
        late: Option<LateAnnounces>,
        caller: Option<Caller>,
        origin: Origin,
    ) {
        let waiting: HashSet<usize> = late
            .as_ref()
            .map(|l| l.idx.values().copied().collect())
            .unwrap_or_default();
        for (i, ch) in self.channels.iter().enumerate() {
            if !waiting.contains(&i) {
                let (ch, id) = (ch.clone(), id.to_string());
                tokio::spawn(async move { ch.closed(&id, why).await });
            }
        }
        let Some(mut late) = late else { return };
        let (chans, audit) = (self.channels.clone(), self.audit.clone());
        let (id, name) = (id.to_string(), name.to_string());
        let grace = *self
            .announce_grace
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        tokio::spawn(async move {
            let deadline = Instant::now() + grace;
            let log = |ev: AuditEvent| {
                let ev = stamp(ev.request(&id).secret(&name), caller.as_ref(), &origin);
                if let Err(e) = audit.log(&ev) {
                    tracing::error!("audit log write failed: {e}");
                }
            };
            let close = |idx: usize| {
                let (ch, id) = (chans[idx].clone(), id.clone());
                tokio::spawn(async move { ch.closed(&id, why).await });
            };
            let mut waiting = waiting;
            loop {
                match tokio::time::timeout_at(deadline, late.tasks.join_next_with_id()).await {
                    Ok(None) => break,
                    Ok(Some(Ok((_, (idx, kind, res))))) => {
                        let ev = match res {
                            Ok(()) => AuditEvent::new("notified"),
                            Err(()) => AuditEvent::new("notify_failed"),
                        };
                        log(ev
                            .channel(kind)
                            .detail("announcement finished after the request was closed"));
                        waiting.remove(&idx);
                        close(idx);
                    }
                    Ok(Some(Err(e))) => {
                        if let Some(idx) = late.idx.get(&e.id()).copied() {
                            waiting.remove(&idx);
                            close(idx);
                        }
                    }
                    Err(_) => {
                        // Grace period over: give up on the stragglers.
                        late.tasks.abort_all();
                        while late.tasks.join_next().await.is_some() {}
                        for idx in waiting.drain() {
                            log(AuditEvent::new("notify_failed")
                                .channel(chans[idx].kind())
                                .outcome("timeout")
                                .detail("still announcing after the request was closed"));
                            close(idx);
                        }
                        break;
                    }
                }
            }
        });
    }

    /// Returns false if the uid exceeded its per-minute `secret.get` budget.
    fn record_get_attempt(&self, uid: u32, max: usize) -> bool {
        let now = Instant::now();
        let mut st = self.lock();
        let q = st.gets.entry(uid).or_default();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            q.pop_front();
        }
        if q.len() >= max {
            return false;
        }
        q.push_back(now);
        true
    }

    fn remove(&self, id: &str) -> Option<Pending> {
        self.lock().pending.remove(id)
    }

    // ----------------------------------------------------- owner interface

    pub fn pending_count(&self) -> usize {
        self.lock().pending.len()
    }

    fn info(id: &str, p: &Pending) -> PendingInfo {
        let (exe, cmdline) = p
            .caller
            .as_ref()
            .and_then(|c| c.proc.as_ref())
            .map(|x| (sanitize::clean(&x.exe, 512), x.cmdline.clone()))
            .unwrap_or_else(|| ("unknown".to_string(), String::new()));
        PendingInfo {
            request_id: id.to_string(),
            secret_name: p.secret.clone(),
            uid: p.caller.as_ref().map_or(0, |c| c.uid),
            username: p
                .caller
                .as_ref()
                .map_or_else(|| "unknown".to_string(), |c| c.username.clone()),
            pid: p.caller.as_ref().map_or(0, |c| c.pid),
            via: match &p.origin {
                Origin::Socket => None,
                Origin::Fifo(path) => Some(format!("via FIFO {}", sanitize::clean(path, 512))),
            },
            exe,
            cmdline,
            reason: p.reason.clone(),
            expires_at: rfc3339(p.expires_at),
        }
    }

    /// Details of one live pending request.
    pub fn pending_info(&self, id: &str) -> Option<(PendingInfo, Option<String>, u8)> {
        let st = self.lock();
        let p = st.pending.get(id)?;
        if p.expires <= Instant::now() {
            return None;
        }
        Some((
            Self::info(id, p),
            p.description.clone(),
            MAX_ATTEMPTS - p.attempts,
        ))
    }

    /// All live pending requests (admin socket).
    pub fn pending_list(&self) -> Vec<PendingInfo> {
        let st = self.lock();
        let now = Instant::now();
        let mut v: Vec<_> = st
            .pending
            .iter()
            .filter(|(_, p)| p.expires > now)
            .map(|(id, p)| Self::info(id, p))
            .collect();
        v.sort_by(|a, b| a.expires_at.cmp(&b.expires_at));
        v
    }

    /// Constant-time comparison of an approval token against a live request.
    pub fn check_token(&self, id: &str, token: &str) -> TokenCheck {
        let st = self.lock();
        match st.pending.get(id) {
            Some(p) if p.expires > Instant::now() => {
                if ct_eq(p.token.as_bytes(), token.as_bytes()) {
                    TokenCheck::Ok
                } else {
                    TokenCheck::Mismatch
                }
            }
            _ => TokenCheck::Unknown,
        }
    }

    /// Owner denies the request. A request whose approval is being processed
    /// (store unsealing) can no longer be denied.
    pub fn deny(&self, id: &str, source: Source) -> DenyOutcome {
        let mut p = {
            let mut st = self.lock();
            match st.pending.get(id) {
                None => return DenyOutcome::Gone,
                Some(p) if p.expires <= Instant::now() => {
                    st.pending.remove(id);
                    return DenyOutcome::Gone;
                }
                Some(p) if p.busy => return DenyOutcome::Busy,
                Some(_) => {}
            }
            st.pending.remove(id).expect("checked above")
        };
        let audited = self
            .audit_req(
                AuditEvent::new("denied")
                    .request(id)
                    .secret(&p.secret)
                    .source(source.ip())
                    .channel(source.channel()),
                p.caller.as_ref(),
                &p.origin,
            )
            .is_ok();
        if let Some(tx) = p.tx.take() {
            let _ = tx.send(Outcome::Denied);
        }
        // Denial is the fail-safe direction, so it proceeds even when the
        // audit log is dead; the caller is told that it was not recorded.
        if audited {
            DenyOutcome::Denied
        } else {
            DenyOutcome::DeniedUnaudited
        }
    }

    /// Re-read `/proc/<pid>` and compare with the connect-time snapshot
    /// (and, where available, check the pidfd still refers to a live process).
    fn verify_caller(&self, caller: &Caller) -> bool {
        let Some(orig) = &caller.proc else {
            return false;
        };
        if let Some(fd) = &caller.pidfd {
            if !crate::peer::pidfd_alive(fd.as_fd()) {
                return false;
            }
        }
        match self.procs.read(caller.pid) {
            Ok(now) => orig.exe == now.exe && orig.start_time == now.start_time,
            Err(_) => false,
        }
    }

    /// Remove the request and deliver `outcome`; false if the client is no
    /// longer waiting.
    fn conclude(&self, id: &str, tx: oneshot::Sender<Outcome>, outcome: Outcome) -> bool {
        self.remove(id);
        tx.send(outcome).is_ok()
    }

    /// Owner approves with the store passphrase: re-verify the caller, unseal
    /// the store for this one secret, release it to the waiting client.
    ///
    /// The request stays in the registry (counting against the caps) while
    /// the store is unsealed, but its reply sender is *taken out* and held
    /// here, so only this call can answer the client. A timeout or
    /// disconnect in that window makes the final delivery fail, which is
    /// reported truthfully (`Aborted`, audit `aborted`); a deny is refused as
    /// `Busy`.
    pub async fn approve(
        &self,
        id: &str,
        passphrase: Passphrase,
        source: Source,
    ) -> ApproveOutcome {
        // Claim the request.
        let (caller, origin, name, attempts, tx) = {
            let mut st = self.lock();
            match st.pending.get_mut(id) {
                Some(p) if p.expires > Instant::now() => {
                    if p.busy {
                        return ApproveOutcome::Busy;
                    }
                    let Some(tx) = p.tx.take() else {
                        return ApproveOutcome::Gone;
                    };
                    p.busy = true;
                    (
                        p.caller.clone(),
                        p.origin.clone(),
                        p.secret.clone(),
                        p.attempts,
                        tx,
                    )
                }
                _ => return ApproveOutcome::Gone,
            }
        };
        let cfg = self.config();

        // Record the attempt before doing anything with the passphrase. This
        // is *not* an approval: that is audited only after the store opened.
        if self
            .audit_req(
                AuditEvent::new("approve_attempt")
                    .request(id)
                    .secret(&name)
                    .source(source.ip())
                    .channel(source.channel()),
                caller.as_ref(),
                &origin,
            )
            .is_err()
        {
            self.conclude(id, tx, Outcome::Internal);
            return ApproveOutcome::Internal;
        }

        // Re-verify the caller (pid reuse / exec-after-connect) and the ACL.
        // Pipe requests are re-verified by the reader-set check that the pipe
        // handler runs just before it writes (section 20.3).
        let socket_caller = match (&origin, caller.as_ref()) {
            (Origin::Socket, Some(c)) => Some(c),
            _ => None,
        };
        if socket_caller.is_some_and(|c| !self.verify_caller(c)) {
            // The request is aborted either way (fail-safe), so a dead audit
            // log is only logged (Core::audit reports the error).
            let _ = self.audit_req(
                AuditEvent::new("caller_changed")
                    .request(id)
                    .secret(&name)
                    .outcome("at_release")
                    .source(source.ip())
                    .channel(source.channel()),
                caller.as_ref(),
                &origin,
            );
            self.conclude(id, tx, Outcome::CallerChanged);
            return ApproveOutcome::CallerChanged;
        }
        if socket_caller.is_some_and(|c| !Self::allowed(&cfg, c, &name)) {
            let _ = self.audit_req(
                AuditEvent::new("acl_denied")
                    .request(id)
                    .secret(&name)
                    .outcome("acl_changed")
                    .source(source.ip())
                    .channel(source.channel()),
                caller.as_ref(),
                &origin,
            );
            self.conclude(id, tx, Outcome::NotFound);
            return ApproveOutcome::Gone;
        }

        // Unseal on a blocking thread; the passphrase is zeroized inside.
        let store_path = cfg.daemon.store.clone();
        let want = name.clone();
        let delay = *self.unseal_delay.lock().unwrap_or_else(|e| e.into_inner());
        let permit = self.unseal_gate.acquire().await;
        let res = tokio::task::spawn_blocking(move || {
            let mut pass = passphrase;
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            store::unseal_one(&store_path, &mut pass, &want)
        })
        .await;
        drop(permit);

        match res {
            Ok(Ok(entry)) => {
                let released = Released {
                    name: name.clone(),
                    value: Zeroizing::new(entry.value.as_str().to_owned()),
                    encoding: entry.encoding,
                };
                drop(entry);
                // The passphrase opened the store: this is the approval.
                if self
                    .audit_req(
                        AuditEvent::new("approved")
                            .request(id)
                            .secret(&name)
                            .source(source.ip())
                            .channel(source.channel()),
                        caller.as_ref(),
                        &origin,
                    )
                    .is_err()
                {
                    self.conclude(id, tx, Outcome::Internal);
                    return ApproveOutcome::Internal;
                }
                // Hand the value to the waiting handler. If it has already
                // given up the send fails and nothing was released.
                self.remove(id);
                let (ack, ack_rx) = oneshot::channel();
                let sent = tx.send(Outcome::Released {
                    rel: released,
                    source,
                    ack,
                });
                if sent.is_err() {
                    let _ = self.audit_req(
                        AuditEvent::new("aborted")
                            .request(id)
                            .secret(&name)
                            .outcome("client_gone")
                            .source(source.ip())
                            .channel(source.channel()),
                        caller.as_ref(),
                        &origin,
                    );
                    return ApproveOutcome::Aborted;
                }
                // The handler audits `released` and confirms; only then is
                // the owner told that the secret was released.
                match ack_rx.await {
                    Ok(Delivery::Released) => ApproveOutcome::Released,
                    Ok(Delivery::CallerChanged) => ApproveOutcome::CallerChanged,
                    Ok(Delivery::Aborted) => ApproveOutcome::Aborted,
                    _ => ApproveOutcome::Internal,
                }
            }
            Ok(Err(StoreError::WrongPassphrase)) => {
                let remaining = MAX_ATTEMPTS.saturating_sub(attempts + 1);
                let audited = self
                    .audit_req(
                        AuditEvent::new("decrypt_failed")
                            .request(id)
                            .secret(&name)
                            .outcome(if remaining == 0 { "final" } else { "retry" })
                            .source(source.ip())
                            .channel(source.channel()),
                        caller.as_ref(),
                        &origin,
                    )
                    .is_ok();
                if !audited {
                    // Do not grant further guesses we cannot record.
                    self.conclude(id, tx, Outcome::Internal);
                    return ApproveOutcome::Internal;
                }
                if remaining == 0 {
                    self.conclude(id, tx, Outcome::DecryptFailed);
                    return ApproveOutcome::Failed;
                }
                // Put the reply sender back and allow a retry, unless the
                // request was cancelled meanwhile.
                let mut st = self.lock();
                match st.pending.get_mut(id) {
                    Some(p) => {
                        p.attempts = attempts + 1;
                        p.busy = false;
                        p.tx = Some(tx);
                        ApproveOutcome::WrongPassphrase { remaining }
                    }
                    None => ApproveOutcome::Gone,
                }
            }
            Ok(Err(StoreError::NoSuchSecret)) => {
                tracing::warn!("secret {name:?} is configured but missing from the store");
                let _ = self.audit_req(
                    AuditEvent::new("decrypt_failed")
                        .request(id)
                        .secret(&name)
                        .outcome("not_in_store")
                        .source(source.ip())
                        .channel(source.channel()),
                    caller.as_ref(),
                    &origin,
                );
                self.conclude(id, tx, Outcome::NotFound);
                ApproveOutcome::NotInStore
            }
            Ok(Err(e)) => {
                tracing::error!("store error: {e}");
                let _ = self.audit_req(
                    AuditEvent::new("decrypt_failed")
                        .request(id)
                        .secret(&name)
                        .outcome("store_error")
                        .source(source.ip())
                        .channel(source.channel()),
                    caller.as_ref(),
                    &origin,
                );
                self.conclude(id, tx, Outcome::Internal);
                ApproveOutcome::Internal
            }
            Err(e) => {
                tracing::error!("unseal task failed: {e}");
                self.conclude(id, tx, Outcome::Internal);
                ApproveOutcome::Internal
            }
        }
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    // Length is not secret (tokens are fixed size); content compare is constant time.
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
