//! Append-only JSON Lines audit log.  Never records secret values,
//! passphrases, tokens or client-supplied reasons.

use serde::Serialize;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
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

impl AuditEvent {
    pub fn new(event: &'static str) -> Self {
        AuditEvent {
            event,
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
}

impl Audit {
    /// Open (creating, mode 0640) the audit file for appending.
    pub fn open(path: &Path) -> std::io::Result<Audit> {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .open(path)?;
        Ok(Audit::from_writer(Box::new(f)))
    }

    pub fn from_writer(w: Box<dyn Write + Send>) -> Audit {
        Audit {
            sink: Mutex::new(w),
        }
    }

    /// Write one event.  An error means the caller must fail closed.
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
