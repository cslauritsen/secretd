//! Append-only JSON Lines audit log.  Never records secret values,
//! passphrases, tokens or client-supplied reasons.

use serde::Serialize;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use time::format_description::well_known::Rfc3339;

#[derive(Debug, Default, Serialize, Clone)]
pub struct AuditEvent {
    pub event: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// Extra non-sensitive detail (for example the OIDC `amr` claim).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Every event carries an `outcome` (spec section 9). This is the default for
/// each event type; call sites override it with something more specific.
pub fn default_outcome(event: &str) -> &'static str {
    match event {
        "request_received" => "received",
        "acl_denied" => "denied",
        "rate_limited" => "limited",
        "notified" => "sent",
        "notify_failed" => "failed",
        "approve_attempt" => "attempt",
        "approved" => "approved",
        "denied" => "denied",
        "timeout" => "timeout",
        "client_disconnected" => "cancelled",
        "decrypt_failed" => "failed",
        "released" => "released",
        "caller_changed" => "denied",
        "aborted" => "aborted",
        "admin_action" => "ok",
        _ => "ok",
    }
}

impl AuditEvent {
    pub fn new(event: &'static str) -> Self {
        AuditEvent {
            event,
            outcome: Some(default_outcome(event).to_string()),
            ..Default::default()
        }
    }
    pub fn outcome(mut self, o: &str) -> Self {
        self.outcome = Some(o.to_string());
        self
    }
    pub fn request(mut self, id: &str) -> Self {
        self.request_id = Some(id.to_string());
        self
    }
    pub fn secret(mut self, n: &str) -> Self {
        self.secret_name = Some(n.to_string());
        self
    }
    pub fn source(mut self, ip: Option<std::net::IpAddr>) -> Self {
        self.source_ip = ip.map(|i| i.to_string());
        self
    }
    pub fn detail(mut self, d: &str) -> Self {
        self.detail = Some(d.to_string());
        self
    }
}

#[derive(Serialize)]
struct Line<'a> {
    ts: String,
    #[serde(flatten)]
    ev: &'a AuditEvent,
}

pub struct Audit {
    sink: Mutex<Box<dyn Write + Send>>,
    /// Where the log lives, so SIGHUP can reopen it (log rotation).
    path: Option<PathBuf>,
}

/// Open the log for appending with mode 0640 regardless of the process umask
/// (the unit sets `UMask=0077`, which would otherwise yield 0600), also
/// correcting the mode of a file that already exists.
fn open_log(path: &Path) -> std::io::Result<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o640)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o640))?;
    Ok(f)
}

impl Audit {
    /// Open (creating, mode 0640) the audit file for appending.
    pub fn open(path: &Path) -> std::io::Result<Audit> {
        Ok(Audit {
            sink: Mutex::new(Box::new(open_log(path)?)),
            path: Some(path.to_path_buf()),
        })
    }

    pub fn from_writer(w: Box<dyn Write + Send>) -> Audit {
        Audit {
            sink: Mutex::new(w),
            path: None,
        }
    }

    /// Reopen the log file (after rotation). On failure the old handle stays
    /// in use. A no-op for writer-backed logs.
    pub fn reopen(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let f = open_log(path)?;
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = Box::new(f);
        Ok(())
    }

    /// Write one event with a single `write` of the complete line.  An error
    /// means the caller must fail closed.
    pub fn log(&self, ev: &AuditEvent) -> std::io::Result<()> {
        let ts = time::OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(std::io::Error::other)?;
        let mut line = serde_json::to_vec(&Line { ts, ev }).map_err(std::io::Error::other)?;
        line.push(b'\n');
        let mut w = self.sink.lock().unwrap_or_else(|e| e.into_inner());
        w.write_all(&line)?;
        w.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_event_has_an_outcome() {
        for ev in [
            "request_received",
            "acl_denied",
            "rate_limited",
            "notified",
            "notify_failed",
            "approve_attempt",
            "approved",
            "denied",
            "timeout",
            "client_disconnected",
            "decrypt_failed",
            "released",
            "caller_changed",
            "aborted",
            "admin_action",
        ] {
            let e = AuditEvent::new(ev);
            assert!(
                e.outcome.as_deref().is_some_and(|o| !o.is_empty()),
                "{ev} has no default outcome"
            );
            if ev != "admin_action" {
                assert_ne!(
                    default_outcome(ev),
                    "ok",
                    "{ev} fell through to the catch-all"
                );
            }
        }
    }
}
