//! secretd: a local secrets-release daemon.
//!
//! The daemon library is split so tests can run everything in-process with an
//! injectable peer-credential provider, `/proc` reader and notifier.

pub mod approval;
pub mod audit;
pub mod channel;
pub mod core;
pub mod fifo;
pub mod homeassistant;
pub mod notify;
pub mod notify_http;
pub mod oidc;
pub mod peer;
pub mod procinfo;
pub mod runtime;
pub mod server;
