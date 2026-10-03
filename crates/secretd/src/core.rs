//! Request broker: ACL checks, rate limits, the pending-request registry and
//! the approve/deny/release logic shared by the HTTP and admin endpoints.

use crate::audit::{Audit, AuditEvent};
use crate::notify::{Notification, Notifier};
use crate::peer::PeerCred;
use crate::procinfo::{ProcInfo, ProcReader};
use secret_proto::acl::{self, CallerIds};
use secret_proto::config::Config;
use secret_proto::rpc::{ErrorKind, GetParams, PendingInfo, RpcError};
use secret_proto::sanitize;
use secret_proto::store::{self, Passphrase, StoreError};
use secret_proto::{valid_secret_name, Encoding, MAX_REASON_CHARS};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::IpAddr;
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
    /// `None` when `/proc` resolution failed: every request is then denied.
    pub proc: Option<ProcInfo>,
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
        source_ip: Option<IpAddr>,
        ack: oneshot::Sender<bool>,
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
}

impl Source {
    fn ip(self) -> Option<IpAddr> {
        match self {
            Source::Http(ip) => Some(ip),
            Source::Admin => None,
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

struct Pending {
    token: String,
    caller: Caller,
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

pub struct Core {
    cfg: RwLock<Arc<Config>>,
    state: Mutex<State>,
    audit: Audit,
    notifier: Arc<dyn Notifier>,
    procs: Arc<dyn ProcReader>,
    /// Serialises unsealing: one scrypt derivation can need hundreds of MiB.
    unseal_gate: tokio::sync::Semaphore,
    /// Test hook: artificial delay inside the blocking unseal task, to widen
    /// the race window between approve and deny/timeout/disconnect.
    unseal_delay: Mutex<Duration>,
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
    pub fn new(
        cfg: Config,
        audit: Audit,
        notifier: Arc<dyn Notifier>,
        procs: Arc<dyn ProcReader>,
    ) -> Arc<Core> {
        Arc::new(Core {
            cfg: RwLock::new(Arc::new(cfg)),
            state: Mutex::new(State::default()),
            audit,
            notifier,
            procs,
            unseal_gate: tokio::sync::Semaphore::new(1),
            unseal_delay: Mutex::new(Duration::ZERO),
        })
    }

    /// Test hook: make every unseal take at least `d` longer.
    #[doc(hidden)]
    pub fn set_unseal_delay(&self, d: Duration) {
        *self.unseal_delay.lock().unwrap_or_else(|e| e.into_inner()) = d;
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

    // ------------------------------------------------------------ identity

    /// Build a [`Caller`] from kernel-verified credentials, capturing `/proc`
    /// details once.
    pub fn identify(&self, cred: PeerCred) -> Caller {
        let proc = match self.procs.read(cred.pid) {
            Ok(p) => Some(p),
            Err(e) => {
                tracing::warn!("cannot resolve /proc for pid {}: {e}", cred.pid);
                None
            }
        };
        let username = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(cred.uid))
            .ok()
            .flatten()
            .map(|u| sanitize::clean(&u.name, 64))
            .unwrap_or_else(|| format!("uid{}", cred.uid));
        Caller {
            uid: cred.uid,
            gid: cred.gid,
            pid: cred.pid,
            username,
            proc,
        }
    }

    fn allowed(cfg: &Config, caller: &Caller, name: &str) -> bool {
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

        self.audit_for(AuditEvent::new("request_received").secret(&name), caller)
            .map_err(|_| internal())?;

        // Per-uid attempt rate limit comes first and applies to every name,
        // so a rate-limit response reveals nothing about ACLs.
        if !self.record_get_attempt(caller.uid, cfg.limits.max_gets_per_uid_per_min) {
            self.audit_for(
                AuditEvent::new("rate_limited")
                    .secret(&name)
                    .outcome("attempt_rate"),
                caller,
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
            self.audit_for(
                AuditEvent::new("acl_denied").secret(&name).outcome(why),
                caller,
            )
            .map_err(|_| internal())?;
            return Err(RpcError::new(ErrorKind::NotFound));
        }
        let secret_cfg = cfg.secret(&name).ok_or_else(internal)?;
        let proc = caller.proc.as_ref().ok_or_else(internal)?;

        let max_wait = cfg.daemon.request_timeout_secs;
        let wait = params
            .timeout_secs
            .map_or(max_wait, |t| t.clamp(1, max_wait));
        let now = Instant::now();
        let deadline = now + Duration::from_secs(wait);
        let id = random_hex(16).ok_or_else(internal)?;
        let token = random_token().ok_or_else(internal)?;
        let (tx, mut rx) = oneshot::channel();

        let expires_at = SystemTime::now() + Duration::from_secs(wait);
        {
            let mut st = self.lock();
            let dup = st.pending.values().any(|p| {
                p.secret == name
                    && p.caller.uid == caller.uid
                    && p.caller.proc.as_ref().map(|x| &x.exe) == Some(&proc.exe)
            });
            let per_uid = st
                .pending
                .values()
                .filter(|p| p.caller.uid == caller.uid)
                .count();
            let limited = if dup {
                Some("duplicate")
            } else if per_uid >= cfg.limits.max_pending_per_uid {
                Some("pending_per_uid")
            } else if st.pending.len() >= cfg.limits.max_pending_total {
                Some("pending_total")
            } else {
                None
            };
            if let Some(why) = limited {
                drop(st);
                self.audit_for(
                    AuditEvent::new("rate_limited").secret(&name).outcome(why),
                    caller,
                )
                .map_err(|_| internal())?;
                return Err(RpcError::new(ErrorKind::RateLimited));
            }
            st.pending.insert(
                id.clone(),
                Pending {
                    token: token.clone(),
                    caller: caller.clone(),
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

        let notification = Notification {
            request_id: id.clone(),
            secret_name: name.clone(),
            description: secret_cfg.description.clone(),
            uid: caller.uid,
            username: caller.username.clone(),
            pid: caller.pid,
            exe: sanitize::clean(&proc.exe, 512),
            cmdline: proc.cmdline.clone(),
            reason,
            expires_at: rfc3339(expires_at),
            approval_url: format!("{}/approve/{id}?t={token}", cfg.approval.external_url),
        };

        let notify_fut = async {
            if let Err(e) = self.notifier.notify(&notification).await {
                tracing::error!("{e}");
                return Err(());
            }
            self.audit_for(
                AuditEvent::new("notified").request(&id).secret(&name),
                caller,
            )
            .map_err(|_| ())
        };
        tokio::pin!(notify_fut);
        tokio::pin!(disconnect);

        enum Done {
            Outcome(Option<Outcome>),
            NotifyFailed,
            Timeout,
            Gone,
        }
        // The owner cannot act before `notified` is audited, so the outcome
        // channel is only polled afterwards (keeps the audit order stable).
        let mut notified = false;
        let mut done = loop {
            tokio::select! {
                r = &mut notify_fut, if !notified => match r {
                    Ok(()) => notified = true,
                    Err(()) => break Done::NotifyFailed,
                },
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

        match done {
            Done::Outcome(Some(outcome)) => match outcome {
                Outcome::Released {
                    rel,
                    source_ip,
                    ack,
                } => {
                    let audited = self
                        .audit_for(
                            AuditEvent::new("released")
                                .request(&id)
                                .secret(&name)
                                .source(source_ip),
                            caller,
                        )
                        .is_ok();
                    let _ = ack.send(audited);
                    if audited {
                        Ok(rel)
                    } else {
                        Err(internal())
                    }
                }
                Outcome::Denied => Err(RpcError::new(ErrorKind::Denied)),
                Outcome::DecryptFailed => Err(RpcError::new(ErrorKind::DecryptFailed)),
                Outcome::CallerChanged => Err(RpcError::new(ErrorKind::CallerChanged)),
                Outcome::NotFound => Err(RpcError::new(ErrorKind::NotFound)),
                Outcome::Internal => Err(internal()),
            },
            Done::Outcome(None) => {
                self.remove(&id);
                Err(internal())
            }
            Done::NotifyFailed => {
                self.remove(&id);
                let _ = self.audit_for(
                    AuditEvent::new("notify_failed").request(&id).secret(&name),
                    caller,
                );
                Err(internal())
            }
            Done::Timeout => {
                self.remove(&id);
                self.audit_for(
                    AuditEvent::new("timeout").request(&id).secret(&name),
                    caller,
                )
                .map_err(|_| internal())?;
                Err(RpcError::new(ErrorKind::Timeout))
            }
            Done::Gone => {
                self.remove(&id);
                let _ = self.audit_for(
                    AuditEvent::new("client_disconnected")
                        .request(&id)
                        .secret(&name),
                    caller,
                );
                Err(internal())
            }
        }
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
            .proc
            .as_ref()
            .map(|x| (sanitize::clean(&x.exe, 512), x.cmdline.clone()))
            .unwrap_or_default();
        PendingInfo {
            request_id: id.to_string(),
            secret_name: p.secret.clone(),
            uid: p.caller.uid,
            username: p.caller.username.clone(),
            pid: p.caller.pid,
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
            .audit_for(
                AuditEvent::new("denied")
                    .request(id)
                    .secret(&p.secret)
                    .source(source.ip()),
                &p.caller,
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
        let (caller, name, attempts, tx) = {
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
                    (p.caller.clone(), p.secret.clone(), p.attempts, tx)
                }
                _ => return ApproveOutcome::Gone,
            }
        };
        let cfg = self.config();

        // Record the attempt before doing anything with the passphrase. This
        // is *not* an approval: that is audited only after the store opened.
        if self
            .audit_for(
                AuditEvent::new("approve_attempt")
                    .request(id)
                    .secret(&name)
                    .source(source.ip()),
                &caller,
            )
            .is_err()
        {
            self.conclude(id, tx, Outcome::Internal);
            return ApproveOutcome::Internal;
        }

        // Re-verify the caller (pid reuse / exec-after-connect) and the ACL.
        if !self.verify_caller(&caller) {
            // The request is aborted either way (fail-safe), so a dead audit
            // log is only logged (Core::audit reports the error).
            let _ = self.audit_for(
                AuditEvent::new("caller_changed")
                    .request(id)
                    .secret(&name)
                    .outcome("at_release")
                    .source(source.ip()),
                &caller,
            );
            self.conclude(id, tx, Outcome::CallerChanged);
            return ApproveOutcome::CallerChanged;
        }
        if !Self::allowed(&cfg, &caller, &name) {
            let _ = self.audit_for(
                AuditEvent::new("acl_denied")
                    .request(id)
                    .secret(&name)
                    .outcome("acl_changed"),
                &caller,
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
                    .audit_for(
                        AuditEvent::new("approved")
                            .request(id)
                            .secret(&name)
                            .source(source.ip()),
                        &caller,
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
                    source_ip: source.ip(),
                    ack,
                });
                if sent.is_err() {
                    let _ = self.audit_for(
                        AuditEvent::new("aborted")
                            .request(id)
                            .secret(&name)
                            .outcome("client_gone")
                            .source(source.ip()),
                        &caller,
                    );
                    return ApproveOutcome::Aborted;
                }
                // The handler audits `released` and confirms; only then is
                // the owner told that the secret was released.
                match ack_rx.await {
                    Ok(true) => ApproveOutcome::Released,
                    _ => ApproveOutcome::Internal,
                }
            }
            Ok(Err(StoreError::WrongPassphrase)) => {
                let remaining = MAX_ATTEMPTS.saturating_sub(attempts + 1);
                let audited = self
                    .audit_for(
                        AuditEvent::new("decrypt_failed")
                            .request(id)
                            .secret(&name)
                            .outcome(if remaining == 0 { "final" } else { "retry" })
                            .source(source.ip()),
                        &caller,
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
                let _ = self.audit_for(
                    AuditEvent::new("decrypt_failed")
                        .request(id)
                        .secret(&name)
                        .outcome("not_in_store")
                        .source(source.ip()),
                    &caller,
                );
                self.conclude(id, tx, Outcome::NotFound);
                ApproveOutcome::NotInStore
            }
            Ok(Err(e)) => {
                tracing::error!("store error: {e}");
                let _ = self.audit_for(
                    AuditEvent::new("decrypt_failed")
                        .request(id)
                        .secret(&name)
                        .outcome("store_error")
                        .source(source.ip()),
                    &caller,
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
