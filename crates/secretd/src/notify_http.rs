//! ntfy and generic webhook notifiers (HTTP POST with retries).

use crate::notify::{Notification, Notifier, NotifyError};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use secret_proto::config::{read_secret_file, NotifyCfg, NotifyKind};
use secret_proto::sanitize;
use sha2::Sha256;
use std::time::Duration;
use zeroize::Zeroizing;

pub struct HttpNotifier {
    client: reqwest::Client,
    cfg: NotifyCfg,
    token: Option<Zeroizing<String>>,
    hmac_key: Option<Zeroizing<String>>,
}

impl HttpNotifier {
    /// Build from config, reading the token / HMAC key files (never inline).
    pub fn new(cfg: &NotifyCfg) -> anyhow::Result<Self> {
        let token = match &cfg.auth_token_file {
            Some(p) => Some(read_secret_file(p).map_err(|e| anyhow::anyhow!("{e}"))?),
            None => None,
        };
        let hmac_key = match (&cfg.hmac_secret_file, cfg.kind) {
            (Some(p), NotifyKind::Webhook) => {
                Some(read_secret_file(p).map_err(|e| anyhow::anyhow!("{e}"))?)
            }
            _ => None,
        };
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.timeout_secs.max(1)))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(HttpNotifier {
            client,
            cfg: cfg.clone(),
            token,
            hmac_key,
        })
    }

    /// Plain-text ntfy body. All caller-controlled strings were sanitised when
    /// the request was created; they are re-cleaned here defensively.
    pub fn ntfy_body(n: &Notification) -> String {
        let mut b = String::new();
        b.push_str(&format!("Secret: {}", sanitize::clean(&n.secret_name, 256)));
        if let Some(d) = &n.description {
            b.push_str(&format!(" ({})", sanitize::clean(d, 120)));
        }
        b.push_str(&format!(
            "\nRequest ID: {}\nCaller: uid {} ({}), pid {}\nExecutable: {}\nCommand line: {}\n",
            n.request_id,
            n.uid,
            sanitize::clean(&n.username, 64),
            n.pid,
            sanitize::clean(&n.exe, 512),
            sanitize::clean(&n.cmdline, 256),
        ));
        if let Some(r) = &n.reason {
            b.push_str(&format!(
                "Reason (client-supplied, untrusted): {}\n",
                sanitize::clean(r, 200)
            ));
        }
        b.push_str(&format!(
            "Expires: {}\nApprove: {}\n",
            n.expires_at, n.approval_url
        ));
        b
    }

    pub fn webhook_body(n: &Notification) -> Vec<u8> {
        let v = serde_json::json!({
            "event": "secret_request",
            "request_id": n.request_id,
            "secret_name": sanitize::clean(&n.secret_name, 256),
            "description": n.description.as_deref().map(|d| sanitize::clean(d, 120)),
            "caller": {
                "uid": n.uid,
                "username": sanitize::clean(&n.username, 64),
                "pid": n.pid,
                "exe": sanitize::clean(&n.exe, 512),
                "cmdline": sanitize::clean(&n.cmdline, 256),
            },
            "reason": n.reason.as_deref().map(|r| sanitize::clean(r, 200)),
            "reason_source": "client-supplied, untrusted",
            "expires_at": n.expires_at,
            "approval_url": n.approval_url,
        });
        serde_json::to_vec(&v).unwrap_or_default()
    }

    fn signature(&self, body: &[u8]) -> Option<String> {
        let key = self.hmac_key.as_ref()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).ok()?;
        mac.update(body);
        let sig = mac.finalize().into_bytes();
        Some(format!(
            "sha256={}",
            sig.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ))
    }

    async fn send_once(&self, n: &Notification) -> Result<(), String> {
        let req = match self.cfg.kind {
            NotifyKind::Ntfy => {
                let mut r = self
                    .client
                    .post(&self.cfg.url)
                    .header(
                        "Title",
                        sanitize::ascii(&format!("Secret request: {}", n.secret_name), 120),
                    )
                    .header("Priority", &self.cfg.priority)
                    .header("Tags", "lock")
                    .header("Click", &n.approval_url)
                    .body(Self::ntfy_body(n));
                if let Some(t) = &self.token {
                    r = r.header("Authorization", format!("Bearer {}", t.as_str()));
                }
                r
            }
            NotifyKind::Webhook => {
                let body = Self::webhook_body(n);
                let mut r = self
                    .client
                    .post(&self.cfg.url)
                    .header("Content-Type", "application/json");
                if let Some(sig) = self.signature(&body) {
                    r = r.header("X-Secretd-Signature", sig);
                }
                r.body(body)
            }
        };
        match req.send().await {
            Ok(resp) if resp.status().is_success() => Ok(()),
            Ok(resp) => Err(format!("HTTP {}", resp.status().as_u16())),
            // `without_url` keeps the notify URL (which may embed a topic) out of logs.
            Err(e) => Err(e.without_url().to_string()),
        }
    }
}

#[async_trait]
impl Notifier for HttpNotifier {
    async fn notify(&self, n: &Notification) -> Result<(), NotifyError> {
        let mut last = String::new();
        for attempt in 0..self.cfg.attempts.max(1) {
            if attempt > 0 {
                let backoff = self
                    .cfg
                    .backoff_ms
                    .saturating_mul(1 << (attempt - 1).min(6));
                tokio::time::sleep(Duration::from_millis(backoff)).await;
            }
            match self.send_once(n).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::warn!("notify attempt {} failed: {e}", attempt + 1);
                    last = e;
                }
            }
        }
        Err(NotifyError(format!(
            "gave up after {} attempts: {last}",
            self.cfg.attempts.max(1)
        )))
    }
}
