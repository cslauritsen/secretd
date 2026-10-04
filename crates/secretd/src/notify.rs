//! Notification abstraction. Concrete ntfy/webhook senders live in
//! `notify_http` (added with the approval endpoint).

use async_trait::async_trait;

/// Everything shown to the owner. Never contains a secret or key.
#[derive(Clone)]
pub struct Notification {
    pub request_id: String,
    pub secret_name: String,
    pub description: Option<String>,
    pub uid: u32,
    pub username: String,
    pub pid: u32,
    pub exe: String,
    pub cmdline: String,
    /// Client supplied (untrusted), already sanitised.
    pub reason: Option<String>,
    pub expires_at: String,
    /// Web approval link (contains the token); empty when the web channel is off.
    pub approval_url: String,
    /// The per-request approval token. Channels other than web use it to build
    /// their action ids. Never shown in message text.
    pub approval_token: String,
}

impl std::fmt::Debug for Notification {
    // The URL and token are credentials: keep them out of any `{:?}` log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notification")
            .field("request_id", &self.request_id)
            .field("secret_name", &self.secret_name)
            .field("uid", &self.uid)
            .field("pid", &self.pid)
            .field("approval_url", &"<redacted>")
            .field("approval_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("notification failed: {0}")]
pub struct NotifyError(pub String);

#[async_trait]
pub trait Notifier: Send + Sync {
    async fn notify(&self, n: &Notification) -> Result<(), NotifyError>;
}

/// Drops notifications; for tests that approve through the core API directly.
pub struct NullNotifier;

#[async_trait]
impl Notifier for NullNotifier {
    async fn notify(&self, _n: &Notification) -> Result<(), NotifyError> {
        Ok(())
    }
}
