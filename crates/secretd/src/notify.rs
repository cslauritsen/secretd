//! Notification abstraction. Concrete ntfy/webhook senders live in
//! `notify_http` (added with the approval endpoint).

use async_trait::async_trait;

/// Everything shown to the owner. Never contains a secret or key.
#[derive(Debug, Clone)]
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
    pub approval_url: String,
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
