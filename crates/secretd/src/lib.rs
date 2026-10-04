//! secretd: a local secrets-release daemon.
//!
//! The daemon library is split so tests can run everything in-process with an
//! injectable peer-credential provider, process-table reader and notifier.
//! Linux and macOS are supported (spec section 22).

pub mod approval;
pub mod audit;
pub mod channel;
pub mod core;
pub mod fifo;
pub mod homeassistant;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod notify;
pub mod notify_http;
pub mod oidc;
pub mod peer;
pub mod platform;
pub mod procinfo;
pub mod runtime;
pub mod server;
