//! Named-pipe (FIFO) secrets (spec section 20).
//!
//! A legacy program reads a secret by opening a named pipe. `secretd` keeps
//! each configured pipe armed by trying `open(O_WRONLY | O_NONBLOCK)` every
//! 100 ms (it fails with `ENXIO` until a reader exists), turns a detected
//! reader into the same pending request as `secret.get` (identifying the
//! reader best-effort from `/proc/*/fd` on Linux, libproc on macOS), and, once
//! the owner approved,
//! writes the raw value into the pipe and closes it so the reader sees EOF.
//!
//! Safety rules implemented here: the pipe is created and verified without
//! following symlinks and regardless of umask; at most one distinct reader
//! may hold the pipe (`fifo_ambiguous`); with `enforce_acl` the single
//! identified reader must satisfy the secret's ACL; the reader set is checked
//! again right before the write (`caller_changed`); the write has a deadline;
//! a cool-down and a per-minute attempt limit stop a program that retries in a
//! loop from flooding the owner.

use crate::audit::AuditEvent;
use crate::core::{Caller, Core, Delivery, Grant, Origin, RequestSpec};
use crate::procinfo::{ProcInfo, ProcInfoReader};
use secret_proto::config::FifoCfg;
use secret_proto::sanitize;
use secret_proto::Encoding;
use std::collections::{BTreeMap, VecDeque};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::watch;
use tokio::time::Instant;
use zeroize::Zeroizing;

/// How often an armed pipe is probed for a reader.
const POLL_EVERY: Duration = Duration::from_millis(100);
/// Minimum pause after a request before the pipe is armed again, whatever
/// `cooldown_secs` says. A reader blocked in `read()` only sees EOF if the pipe
/// has no writer at the moment it wakes up; if the daemon re-opened the write
/// end at once, the reader would go back to sleep and never get its EOF.
const SETTLE: Duration = Duration::from_millis(250);
/// How often a waiting request checks that its reader is still there.
const WATCH_EVERY: Duration = Duration::from_millis(100);

// -------------------------------------------------------------- scanning

/// A process found holding the pipe open for reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderIdent {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    /// `None` when `/proc/<pid>` could not be read (the process exited, or the
    /// daemon lacks the access): such a reader still counts for the ambiguity
    /// rule but cannot be identified.
    pub proc: Option<ProcInfo>,
}

/// Finds the readers of a pipe. Abstracted so tests can script what the scan
/// sees (the real scan excludes the daemon's own process).
pub trait ReaderScanner: Send + Sync {
    /// Processes other than `secretd` that hold the file `(dev, ino)` open with
    /// read access: one entry per process.
    fn readers(&self, dev: u64, ino: u64) -> io::Result<Vec<ReaderIdent>>;
}

/// Scans `/proc/*/fd` (best effort: processes the daemon may not look into are
/// skipped, and the scan is inherently racy).
pub struct ProcScanner {
    procs: Arc<dyn ProcInfoReader>,
}

impl ProcScanner {
    pub fn new(procs: Arc<dyn ProcInfoReader>) -> Self {
        ProcScanner { procs }
    }
}

/// Effective uid and gid of `pid` from `/proc/<pid>/status`.
#[cfg(target_os = "linux")]
fn proc_ids(pid: u32) -> Option<(u32, u32)> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let field = |key: &str| -> Option<u32> {
        status
            .lines()
            .find_map(|l| l.strip_prefix(key))?
            .split_whitespace()
            .nth(1)? // real, *effective*, saved, fs
            .parse()
            .ok()
    };
    Some((field("Uid:")?, field("Gid:")?))
}

/// Parses the `flags:` line of `/proc/<pid>/fdinfo/<fd>` (octal).
#[cfg(target_os = "linux")]
fn fdinfo_flags(text: &str) -> Option<u32> {
    let v = text.lines().find_map(|l| l.strip_prefix("flags:"))?.trim();
    u32::from_str_radix(v, 8).ok()
}

impl ReaderScanner for ProcScanner {
    fn readers(&self, dev: u64, ino: u64) -> io::Result<Vec<ReaderIdent>> {
        self.scan(dev, ino)
    }
}

#[cfg(target_os = "macos")]
impl ProcScanner {
    /// macOS: `proc_listpids`, then per process `PROC_PIDLISTFDS` and, for the
    /// vnode descriptors, `PROC_PIDFDVNODEPATHINFO`, which reports the file's
    /// device and inode and the open flags (`FREAD`). Other users' processes
    /// are visible only to root (`EPERM` => skipped, like on Linux without
    /// `CAP_SYS_PTRACE`).
    fn scan(&self, dev: u64, ino: u64) -> io::Result<Vec<ReaderIdent>> {
        use crate::macos;
        let me = std::process::id();
        let want_dev = macos::dev32(dev);
        let mut found: BTreeMap<u32, ReaderIdent> = BTreeMap::new();
        for pid in macos::list_pids()? {
            if pid == me || found.contains_key(&pid) {
                continue;
            }
            let Ok(fds) = macos::list_fds(pid) else {
                continue;
            };
            for (fd, ty) in fds {
                if ty != libc::PROX_FDTYPE_VNODE as u32 {
                    continue;
                }
                let Ok(v) = macos::vnode_fd(pid, fd) else {
                    continue;
                };
                // Only a descriptor opened for reading is a reader.
                if v.dev != want_dev || v.ino != ino || !v.readable {
                    continue;
                }
                let ids = macos::bsd_info(pid).ok().map(|b| (b.pbi_uid, b.pbi_gid));
                let proc = self.procs.read(pid).ok();
                found.insert(
                    pid,
                    ReaderIdent {
                        pid,
                        uid: ids.map_or(0, |i| i.0),
                        gid: ids.map_or(0, |i| i.1),
                        proc: proc.filter(|_| ids.is_some()),
                    },
                );
                break;
            }
        }
        Ok(found.into_values().collect())
    }
}

#[cfg(target_os = "linux")]
impl ProcScanner {
    fn scan(&self, dev: u64, ino: u64) -> io::Result<Vec<ReaderIdent>> {
        let me = std::process::id();
        let mut found: BTreeMap<u32, ReaderIdent> = BTreeMap::new();
        for entry in std::fs::read_dir("/proc")? {
            let Ok(entry) = entry else { continue };
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            if pid == me || found.contains_key(&pid) {
                continue;
            }
            // Other users' descriptor tables need the same access as `exe`
            // (CAP_SYS_PTRACE); without it the process is simply not seen.
            let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                let link = fd.path();
                // Pipes, sockets and anonymous inodes read back as "pipe:[..]",
                // "socket:[..]", "anon_inode:..": only paths can be our pipe.
                match std::fs::read_link(&link) {
                    Ok(t) if t.is_absolute() => {}
                    _ => continue,
                }
                let Ok(md) = std::fs::metadata(&link) else {
                    continue;
                };
                if md.dev() != dev || md.ino() != ino {
                    continue;
                }
                let name = fd.file_name();
                let Ok(info) = std::fs::read_to_string(format!(
                    "/proc/{pid}/fdinfo/{}",
                    name.to_string_lossy()
                )) else {
                    continue;
                };
                // O_WRONLY (1) is the one access mode without read access.
                if fdinfo_flags(&info).is_none_or(|f| f & 0o3 == 1) {
                    continue;
                }
                let ids = proc_ids(pid);
                let proc = self.procs.read(pid).ok();
                found.insert(
                    pid,
                    ReaderIdent {
                        pid,
                        uid: ids.map_or(0, |i| i.0),
                        gid: ids.map_or(0, |i| i.1),
                        proc: proc.filter(|_| ids.is_some()),
                    },
                );
                break;
            }
        }
        Ok(found.into_values().collect())
    }
}

// ----------------------------------------------------------------- setup

/// Identity of the pipe inode we created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FifoId {
    pub dev: u64,
    pub ino: u64,
}

fn fail<T>(path: &Path, msg: impl std::fmt::Display) -> io::Result<T> {
    Err(io::Error::other(format!("fifo {}: {msg}", path.display())))
}

fn cstr(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

/// Create (or take over a leftover of ours) and verify the pipe for `cfg`.
///
/// `daemon_uid` is the uid the daemon runs as. The parent directory must be a
/// real directory (not a symlink) owned by that uid and not writable by
/// group/others, so nobody else can plant or swap entries. An existing path
/// must be a FIFO (never a symlink or anything else) owned by the daemon user
/// or by the configured owner (a leftover of a crashed run); it is replaced.
/// Ownership and mode are applied with `fchown`/`fchmod` on an open
/// descriptor, so the process umask plays no role, and verified afterwards,
/// including that the daemon itself can open the pipe for writing.
pub fn setup(cfg: &FifoCfg, daemon_uid: u32) -> io::Result<FifoId> {
    let path = cfg.path.as_path();
    let Some(parent) = path.parent() else {
        return fail(path, "has no parent directory");
    };
    match std::fs::symlink_metadata(parent) {
        Ok(md) => {
            if md.file_type().is_symlink() || !md.is_dir() {
                return fail(
                    path,
                    format!("{} is not a directory (or is a symlink)", parent.display()),
                );
            }
            if md.uid() != daemon_uid {
                return fail(
                    path,
                    format!(
                        "directory {} is owned by uid {}, not by the daemon user (uid {daemon_uid})",
                        parent.display(),
                        md.uid()
                    ),
                );
            }
            if md.mode() & 0o022 != 0 {
                return fail(
                    path,
                    format!(
                        "directory {} is writable by group or others (mode {:o})",
                        parent.display(),
                        md.mode() & 0o7777
                    ),
                );
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o755)
                .create(parent)?;
        }
        Err(e) => return Err(e),
    }

    // What is at the path now?
    match std::fs::symlink_metadata(path) {
        Ok(md) => {
            let ft = md.file_type();
            if ft.is_symlink() {
                return fail(path, "exists and is a symlink; refusing to start");
            }
            if !ft.is_fifo() {
                return fail(path, "exists and is not a FIFO; refusing to start");
            }
            if md.uid() != daemon_uid && Some(md.uid()) != cfg.owner {
                return fail(
                    path,
                    format!(
                        "exists and is owned by uid {}, not by the daemon user; refusing to start",
                        md.uid()
                    ),
                );
            }
            std::fs::remove_file(path)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let c = cstr(path)?;
    // SAFETY: `c` is a valid NUL-terminated path; mkfifo has no other inputs.
    if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let created = std::fs::symlink_metadata(path)?;
    if !created.file_type().is_fifo() || created.uid() != daemon_uid {
        return fail(path, "the new pipe was replaced while it was being set up");
    }
    // The umask may have taken bits away from 0600 already; we own the file
    // and nobody else can reach the directory, so a path based chmod is safe.
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    // Open it read-write (never blocks on a FIFO) so the rest works on the
    // descriptor and cannot be redirected by a swapped path.
    // SAFETY: valid path; flags are plain constants.
    let raw = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` was just returned by open and is owned by nobody else.
    let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) });
    let md = file.metadata()?;
    if !md.file_type().is_fifo()
        || md.uid() != daemon_uid
        || md.dev() != created.dev()
        || md.ino() != created.ino()
    {
        return fail(path, "the new pipe was replaced while it was being set up");
    }
    let uid = cfg.owner.unwrap_or(u32::MAX); // (uid_t)-1: leave unchanged
                                             // SAFETY: `file` is a valid descriptor for the duration of both calls.
    let chown = unsafe { libc::fchown(file.as_raw_fd(), uid, cfg.gid) };
    if chown != 0 {
        let e = io::Error::last_os_error();
        let _ = std::fs::remove_file(path);
        return fail(
            path,
            format!(
                "cannot set owner/group ({e}): an unprivileged daemon can only chown to its own \
                 user and to groups it belongs to; use `owner = <daemon user>` and a group the \
                 daemon is a member of, or create the pipe with systemd-tmpfiles"
            ),
        );
    }
    // SAFETY: as above.
    #[allow(clippy::unnecessary_cast)] // mode_t is u16 on macOS
    let mode = cfg.mode as libc::mode_t;
    if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
        let e = io::Error::last_os_error();
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    let md = file.metadata()?;
    let want_uid = cfg.owner.unwrap_or(daemon_uid);
    if md.uid() != want_uid || md.gid() != cfg.gid || md.mode() & 0o7777 != cfg.mode {
        let _ = std::fs::remove_file(path);
        return fail(
            path,
            format!(
                "verification failed: owner {}:{} mode {:o}, wanted {want_uid}:{} mode {:o}",
                md.uid(),
                md.gid(),
                md.mode() & 0o7777,
                cfg.gid,
                cfg.mode
            ),
        );
    }
    drop(file);
    // The daemon must be able to open it for writing, or it could never answer.
    // SAFETY: valid path; plain flags.
    let writable =
        unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::W_OK, libc::AT_EACCESS) };
    if writable != 0 {
        let _ = std::fs::remove_file(path);
        return fail(
            path,
            format!(
                "owner {want_uid}, group {}, mode {:04o}: the daemon user (uid {daemon_uid}) cannot \
                 open it for writing. The daemon must be the owner, or a member of the group, with \
                 the matching write bit (for example owner = the daemon user, mode = \"0640\", \
                 group = the readers' group)",
                cfg.gid, cfg.mode
            ),
        );
    }
    Ok(FifoId {
        dev: md.dev(),
        ino: md.ino(),
    })
}

/// Remove the pipe if it is still the inode we created.
pub fn remove(path: &Path, id: FifoId) {
    if let Ok(md) = std::fs::symlink_metadata(path) {
        if md.file_type().is_fifo() && md.dev() == id.dev && md.ino() == id.ino {
            let _ = std::fs::remove_file(path);
        }
    }
}

// --------------------------------------------------------------- helpers

/// `open(O_WRONLY | O_NONBLOCK)`: `Ok(None)` while no reader has the pipe open
/// (`ENXIO`), the write end as soon as one does. Never blocks.
///
/// POSIX specifies `ENXIO` for this case and both Linux and macOS (XNU's
/// `fifo_open`) implement it, including counting a reader that is still
/// blocked in its own `open(O_RDONLY)`. Differences to keep in mind on macOS:
/// a write end whose readers left is expected to show up as `POLLHUP`
/// (Linux: `POLLERR`); [`reader_gone_now`] accepts either, and the write path
/// does not depend on it (a vanished reader gives `EPIPE`, `SIGPIPE` being
/// ignored). tokio's `AsyncFd` waits with `kqueue` instead of epoll. These
/// macOS behaviours are exercised by `tests/fifo.rs` in the macOS CI job.
fn try_open_writer(path: &Path, id: FifoId) -> io::Result<Option<OwnedFd>> {
    let c = cstr(path)?;
    // SAFETY: valid NUL-terminated path, constant flags.
    let raw = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_WRONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let e = io::Error::last_os_error();
        return if e.raw_os_error() == Some(libc::ENXIO) {
            Ok(None)
        } else {
            Err(e)
        };
    }
    // SAFETY: `raw` was just returned by open and is owned by nobody else.
    let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) });
    let md = file.metadata()?;
    if !md.file_type().is_fifo() || md.dev() != id.dev || md.ino() != id.ino {
        return Err(io::Error::other("the pipe was replaced"));
    }
    Ok(Some(file.into()))
}

/// True once nobody has the read end open any more (`POLLERR` on a pipe's
/// write end).
fn reader_gone_now(fd: RawFd) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: `p` is a valid pollfd and nfds is 1; timeout 0 never blocks.
    let r = unsafe { libc::poll(&mut p, 1, 0) };
    r > 0 && p.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
}

async fn wait_stop(rx: &mut watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Resolves when the reader closed its end or shutdown was requested.
async fn reader_gone(fd: RawFd, mut stop: watch::Receiver<bool>) {
    loop {
        if reader_gone_now(fd) {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep(WATCH_EVERY) => {}
            _ = wait_stop(&mut stop) => return,
        }
    }
}

enum Verdict {
    Ok,
    Ambiguous,
    Changed,
}

/// Compare the reader snapshot taken at request time with a fresh one.
fn verify(before: &[ReaderIdent], now: &[ReaderIdent], reader_present: bool) -> Verdict {
    if now.len() > 1 {
        return Verdict::Ambiguous;
    }
    match (before.first(), now.first()) {
        // Nobody could be seen either time: all that can be checked is that
        // somebody still has the read end open.
        (None, None) if reader_present => Verdict::Ok,
        (Some(a), Some(b)) if a.pid == b.pid && a.proc == b.proc && reader_present => Verdict::Ok,
        _ => Verdict::Changed,
    }
}

enum WriteEnd {
    Done,
    ReaderGone,
    Timeout,
    Error,
}

/// Push `data` into the (non-blocking) pipe with a deadline, then close it.
/// Returns how it ended and how many bytes were written.
async fn write_all_deadline(fd: OwnedFd, data: &[u8], deadline: Duration) -> (WriteEnd, usize) {
    let afd = match AsyncFd::with_interest(fd, Interest::WRITABLE) {
        Ok(a) => a,
        Err(_) => return (WriteEnd::Error, 0),
    };
    let mut written = 0usize;
    let res = tokio::time::timeout(deadline, async {
        while written < data.len() {
            let mut guard = afd.writable().await?;
            let r = guard.try_io(|inner| {
                let rest = &data[written..];
                // SAFETY: `rest` is valid for `rest.len()` bytes and the
                // descriptor is open for the duration of the call.
                let n = unsafe { libc::write(inner.as_raw_fd(), rest.as_ptr().cast(), rest.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match r {
                Ok(Ok(n)) => written += n,
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
        Ok::<(), io::Error>(())
    })
    .await;
    // Dropping the AsyncFd closes the write end: the reader sees EOF after the
    // data (or the partial data) it can still drain.
    drop(afd);
    match res {
        Ok(Ok(())) => (WriteEnd::Done, written),
        Ok(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe => (WriteEnd::ReaderGone, written),
        Ok(Err(_)) => (WriteEnd::Error, written),
        Err(_) => (WriteEnd::Timeout, written),
    }
}

// ------------------------------------------------------------ supervisor

struct Ctx {
    core: Arc<Core>,
    scanner: Arc<dyn ReaderScanner>,
    cfg: FifoCfg,
    id: FifoId,
}

impl Ctx {
    fn path(&self) -> String {
        self.cfg.path.display().to_string()
    }

    fn event(&self, name: &'static str) -> AuditEvent {
        AuditEvent::new(name)
            .secret(&self.cfg.secret)
            .fifo(&self.path())
    }

    async fn scan(&self) -> io::Result<Vec<ReaderIdent>> {
        let (s, dev, ino) = (self.scanner.clone(), self.id.dev, self.id.ino);
        tokio::task::spawn_blocking(move || s.readers(dev, ino))
            .await
            .map_err(io::Error::other)?
    }

    /// Scan for the reader that just opened the pipe. Our `open` can complete a
    /// moment before the reader's own `open` has installed its descriptor, so
    /// an empty answer is retried briefly before the reader counts as unknown.
    async fn scan_for_new_reader(&self) -> io::Result<Vec<ReaderIdent>> {
        let mut last = self.scan().await?;
        for _ in 0..8 {
            if !last.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
            last = self.scan().await?;
        }
        Ok(last)
    }

    /// A reader was detected: run one request to its end. Dropping `wfd`
    /// (on every path out) closes the pipe, which is what gives the reader
    /// EOF when nothing was written.
    async fn handle(
        &self,
        wfd: OwnedFd,
        attempts: &mut VecDeque<Instant>,
        stop: &watch::Receiver<bool>,
    ) {
        let path = self.path();
        let origin = Origin::Fifo(path.clone());

        // Per-pipe attempt limit.
        let now = Instant::now();
        while attempts
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            attempts.pop_front();
        }
        if attempts.len() >= self.cfg.attempts_per_min {
            let _ = self.core.audit_coalesced(
                self.event("rate_limited").outcome("fifo_attempt_rate"),
                &path,
            );
            return;
        }
        attempts.push_back(now);

        // Who is reading? (best effort)
        let readers = match self.scan_for_new_reader().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("fifo {path}: reader scan failed: {e}");
                Vec::new()
            }
        };
        if readers.len() > 1 {
            let _ = self
                .core
                .audit_coalesced(self.event("fifo_ambiguous").outcome("at_request"), &path);
            return;
        }
        let mut caller: Option<Caller> = readers.first().and_then(|r| {
            r.proc.clone().map(|p| Caller {
                uid: r.uid,
                gid: r.gid,
                pid: r.pid,
                username: String::new(),
                proc: Some(p),
                pidfd: None,
            })
        });
        if let Some(c) = caller.as_mut() {
            self.core.resolve_username(c);
        }
        if self.cfg.enforce_acl {
            match &caller {
                None => {
                    let _ = self.core.audit_coalesced(
                        self.event("fifo_reader_unknown").outcome("at_request"),
                        &path,
                    );
                    return;
                }
                Some(c) => {
                    let cfg = self.core.config();
                    if !Core::allowed(&cfg, c, &self.cfg.secret) {
                        let _ = self.core.audit_coalesced(
                            {
                                let mut ev = self.event("acl_denied").outcome("fifo_acl");
                                ev.uid = Some(c.uid);
                                ev.gid = Some(c.gid);
                                ev.pid = Some(c.pid);
                                ev.exe = c.proc.as_ref().map(|p| p.exe.clone());
                                ev
                            },
                            &path,
                        );
                        return;
                    }
                }
            }
        }

        // Same bookkeeping as `secret.get`: logged one by one, fails closed.
        if self
            .core
            .audit_req(
                AuditEvent::new("request_received")
                    .secret(&self.cfg.secret)
                    .outcome("fifo_open"),
                caller.as_ref(),
                &origin,
            )
            .is_err()
        {
            return;
        }
        let wait = Duration::from_secs(self.core.config().daemon.request_timeout_secs);
        let spec = RequestSpec {
            origin: origin.clone(),
            secret: self.cfg.secret.clone(),
            reason: Some(sanitize::clean(&format!("read of {path}"), 600)),
            caller: caller.clone(),
            wait,
        };
        let gone = reader_gone(wfd.as_raw_fd(), stop.clone());
        match self.core.request_approval(spec, gone).await {
            // Denied, timed out, reader left, notification failed ...: the core
            // audited it; closing the pipe is the whole answer.
            Err(_) => {}
            Ok(grant) => self.deliver(grant, wfd, &readers, caller.as_ref()).await,
        }
    }

    /// Re-verify the reader, write the value, close the pipe, audit.
    async fn deliver(
        &self,
        grant: Grant,
        wfd: OwnedFd,
        before: &[ReaderIdent],
        caller: Option<&Caller>,
    ) {
        let path = self.path();
        let origin = Origin::Fifo(path.clone());
        let id = grant.id.clone();
        let src = grant.source;
        let tag = |ev: AuditEvent| ev.request(&id).source(src.ip()).channel(src.channel());

        // Just before writing: is it still the reader the owner saw?
        let now = match self.scan().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("fifo {path}: re-verification scan failed: {e}");
                // Cannot look: fail closed.
                let _ = self.core.audit_req(
                    tag(self.event("caller_changed").outcome("at_release")),
                    caller,
                    &origin,
                );
                drop(grant.finish(Delivery::CallerChanged));
                return;
            }
        };
        match verify(before, &now, !reader_gone_now(wfd.as_raw_fd())) {
            Verdict::Ok => {}
            Verdict::Ambiguous => {
                let _ = self.core.audit_req(
                    tag(self.event("fifo_ambiguous").outcome("at_release")),
                    caller,
                    &origin,
                );
                drop(grant.finish(Delivery::CallerChanged));
                return;
            }
            Verdict::Changed => {
                let _ = self.core.audit_req(
                    tag(self.event("caller_changed").outcome("at_release")),
                    caller,
                    &origin,
                );
                drop(grant.finish(Delivery::CallerChanged));
                return;
            }
        }

        // The raw value: base64 secrets are decoded, nothing is appended.
        let (end, written, total) = {
            use base64::Engine;
            let value: Option<Zeroizing<Vec<u8>>> = match grant.rel.encoding {
                Encoding::Utf8 => None,
                Encoding::Base64 => {
                    let mut buf = Zeroizing::new(Vec::with_capacity(grant.rel.value.len()));
                    match base64::engine::general_purpose::STANDARD
                        .decode_vec(grant.rel.value.trim().as_bytes(), &mut buf)
                    {
                        Ok(()) => Some(buf),
                        Err(_) => {
                            tracing::error!("fifo {path}: stored base64 value is invalid");
                            let _ = self.core.audit_req(
                                tag(self.event("aborted").outcome("bad_value")),
                                caller,
                                &origin,
                            );
                            drop(grant.finish(Delivery::Failed));
                            return;
                        }
                    }
                }
            };
            let data: &[u8] = match &value {
                Some(v) => v.as_slice(),
                None => grant.rel.value.as_bytes(),
            };
            let deadline = Duration::from_secs(self.cfg.write_deadline_secs);
            let (end, written) = write_all_deadline(wfd, data, deadline).await;
            (end, written, data.len())
        };

        match end {
            WriteEnd::Done => {
                // `released` only after the whole value was written. If this
                // line cannot be written the value is out already; say so.
                if self
                    .core
                    .audit_req(tag(self.event("released")), caller, &origin)
                    .is_err()
                {
                    tracing::error!("fifo {path}: released, but the audit log write failed");
                }
                drop(grant.finish(Delivery::Released));
            }
            other => {
                let why = match other {
                    WriteEnd::ReaderGone => "reader_gone",
                    WriteEnd::Timeout => "write_timeout",
                    _ => "write_error",
                };
                // Byte counts only, never data.
                let _ = self.core.audit_req(
                    tag(self
                        .event("aborted")
                        .outcome(why)
                        .detail(&format!("wrote {written} of {total} bytes"))),
                    caller,
                    &origin,
                );
                drop(grant.finish(Delivery::Aborted));
            }
        }
    }
}

async fn run_fifo(ctx: Ctx, mut stop: watch::Receiver<bool>) {
    let path = ctx.cfg.path.clone();
    let mut attempts: VecDeque<Instant> = VecDeque::new();
    let mut last_err: Option<Instant> = None;
    'outer: loop {
        // Armed: probe until a reader shows up. Cancellable at every step.
        let wfd = loop {
            if *stop.borrow() {
                break 'outer;
            }
            match try_open_writer(&path, ctx.id) {
                Ok(Some(fd)) => break fd,
                Ok(None) => {}
                Err(e) => {
                    // Log at most every 30 s per pipe.
                    if last_err.is_none_or(|t| t.elapsed() > Duration::from_secs(30)) {
                        tracing::error!("fifo {}: cannot probe the pipe: {e}", path.display());
                        last_err = Some(Instant::now());
                    }
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(POLL_EVERY) => {}
                _ = wait_stop(&mut stop) => break 'outer,
            }
        };
        ctx.handle(wfd, &mut attempts, &stop).await;
        // Cool-down before the pipe is armed again (never less than SETTLE).
        let pause = Duration::from_secs(ctx.cfg.cooldown_secs).max(SETTLE);
        tokio::select! {
            _ = tokio::time::sleep(pause) => {}
            _ = wait_stop(&mut stop) => break 'outer,
        }
    }
    remove(&path, ctx.id);
}

/// Running pipes; [`FifoHandle::shutdown`] stops them and removes the pipes.
pub struct FifoHandle {
    stop: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    paths: Vec<(PathBuf, FifoId)>,
}

impl FifoHandle {
    /// Cancel every wait and remove the pipes. An approved request that is
    /// being written finishes within its write deadline.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        for t in self.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(15), t).await;
        }
        for (p, id) in &self.paths {
            remove(p, *id);
        }
    }
}

/// Set up every configured pipe (refusing to start if one is unsafe) and start
/// watching them. Ignores `SIGPIPE` process-wide: a reader that vanished
/// mid-write must give `EPIPE`, not kill the daemon.
pub fn start(
    core: Arc<Core>,
    scanner: Arc<dyn ReaderScanner>,
    cfgs: &[FifoCfg],
    daemon_uid: u32,
) -> io::Result<FifoHandle> {
    // SAFETY: setting a signal disposition to SIG_IGN is async-signal-safe and
    // has no memory-safety implications.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    let mut created: Vec<(PathBuf, FifoId)> = Vec::new();
    for cfg in cfgs {
        match setup(cfg, daemon_uid) {
            Ok(id) => created.push((cfg.path.clone(), id)),
            Err(e) => {
                for (p, id) in &created {
                    remove(p, *id);
                }
                return Err(e);
            }
        }
    }
    let (stop, rx) = watch::channel(false);
    let mut tasks = Vec::new();
    for (cfg, (_, id)) in cfgs.iter().zip(&created) {
        tracing::info!(
            "fifo {} armed for secret {:?}",
            cfg.path.display(),
            cfg.secret
        );
        let ctx = Ctx {
            core: core.clone(),
            scanner: scanner.clone(),
            cfg: cfg.clone(),
            id: *id,
        };
        tasks.push(tokio::spawn(run_fifo(ctx, rx.clone())));
    }
    Ok(FifoHandle {
        stop,
        tasks,
        paths: created,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(pid: u32, exe: &str) -> ReaderIdent {
        ReaderIdent {
            pid,
            uid: 1,
            gid: 1,
            proc: Some(ProcInfo {
                exe: exe.into(),
                cmdline: String::new(),
                start_time: 5,
            }),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fdinfo_flags_are_octal() {
        assert_eq!(
            fdinfo_flags("pos:\t0\nflags:\t0100000\nmnt_id:\t7\n"),
            Some(0o100000)
        );
        assert_eq!(fdinfo_flags("flags:\t02\n"), Some(2));
        assert_eq!(fdinfo_flags("nothing"), None);
    }

    #[test]
    fn verdicts() {
        let a = ident(10, "/bin/cat");
        assert!(matches!(
            verify(std::slice::from_ref(&a), std::slice::from_ref(&a), true),
            Verdict::Ok
        ));
        // A different pid, exe or start time, or nobody left: changed.
        assert!(matches!(
            verify(std::slice::from_ref(&a), &[ident(11, "/bin/cat")], true),
            Verdict::Changed
        ));
        assert!(matches!(
            verify(std::slice::from_ref(&a), &[ident(10, "/bin/sh")], true),
            Verdict::Changed
        ));
        let mut b = a.clone();
        b.proc.as_mut().unwrap().start_time = 6;
        assert!(matches!(
            verify(std::slice::from_ref(&a), &[b], true),
            Verdict::Changed
        ));
        assert!(matches!(
            verify(std::slice::from_ref(&a), &[], true),
            Verdict::Changed
        ));
        assert!(matches!(
            verify(&[], std::slice::from_ref(&a), true),
            Verdict::Changed
        ));
        assert!(matches!(
            verify(std::slice::from_ref(&a), std::slice::from_ref(&a), false),
            Verdict::Changed
        ));
        // Two readers at release: ambiguous.
        assert!(matches!(
            verify(
                std::slice::from_ref(&a),
                &[a.clone(), ident(11, "/bin/cat")],
                true
            ),
            Verdict::Ambiguous
        ));
        // Unidentifiable both times: only the presence of a reader counts.
        assert!(matches!(verify(&[], &[], true), Verdict::Ok));
        assert!(matches!(verify(&[], &[], false), Verdict::Changed));
    }
}
