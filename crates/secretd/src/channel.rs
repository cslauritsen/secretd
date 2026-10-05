//! Approval channels (spec section 19.1).
//!
//! A channel can (a) announce a pending request to the owner and (b) deliver
//! an approve or deny decision (plus the passphrase) back to the [`Core`]. The
//! announce half is this trait; the decision half is a call to
//! [`Core::approve`] / [`Core::deny`] made with the matching
//! [`Source`](crate::core::Source), which keeps the "first valid resolution
//! wins" rule in one place (the core's pending registry).
//!
//! Channels:
//! * `web`: push notification (ntfy/webhook) plus the OIDC protected page
//!   served by [`crate::approval`].
//! * `admin`: the root-only admin socket. Pull based: it announces nothing,
//!   the operator runs `secretctl pending`.
//! * `homeassistant`: [`crate::homeassistant`].
//!
//! [`Core`]: crate::core::Core
//! [`Core::approve`]: crate::core::Core::approve
//! [`Core::deny`]: crate::core::Core::deny

use crate::notify::{Notification, Notifier, NotifyError};
use async_trait::async_trait;
use secret_proto::config::ChannelKind;
use std::sync::Arc;

/// Why a request left the pending state (told to every channel).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closed {
    /// The secret was released.
    Released,
    /// Denied by the owner (any channel).
    Denied,
    /// Nobody answered in time.
    Timeout,
    /// The client went away (disconnect, or the FIFO reader exited).
    Cancelled,
    /// Wrong passphrase limit reached, caller changed, store error ...
    Failed,
}

#[async_trait]
pub trait Channel: Send + Sync {
    fn kind(&self) -> ChannelKind;

    /// True if the channel pushes notifications. A request fails only when
    /// every announcing channel failed; a pull-based channel (admin) does not
    /// count either way.
    fn announces(&self) -> bool {
        true
    }

    /// Tell the owner about a new request. Must not contain secrets or keys.
    async fn announce(&self, n: &Notification) -> Result<(), NotifyError>;

    /// The request is no longer pending. Called exactly once per request, for
    /// every enabled channel, after the outcome is decided. Best effort:
    /// channels that showed the request clear it here (HA notification).
    async fn closed(&self, _request_id: &str, _why: Closed) {}
}

/// The `web` channel: ntfy/webhook push; the approval page needs no help here
/// because an unknown or resolved request already answers 410 Gone.
pub struct WebChannel {
    notifier: Arc<dyn Notifier>,
}

impl WebChannel {
    pub fn new(notifier: Arc<dyn Notifier>) -> Self {
        WebChannel { notifier }
    }
}

#[async_trait]
impl Channel for WebChannel {
    fn kind(&self) -> ChannelKind {
        ChannelKind::Web
    }

    async fn announce(&self, n: &Notification) -> Result<(), NotifyError> {
        self.notifier.notify(n).await
    }
}

/// The `admin` channel (root-only socket). Pull based.
pub struct AdminChannel;

#[async_trait]
impl Channel for AdminChannel {
    fn kind(&self) -> ChannelKind {
        ChannelKind::Admin
    }

    fn announces(&self) -> bool {
        false
    }

    async fn announce(&self, _n: &Notification) -> Result<(), NotifyError> {
        Ok(())
    }
}
