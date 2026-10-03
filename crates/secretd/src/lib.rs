//! secretd: a local secrets-release daemon.
//!
//! The daemon library is split so tests can run everything in-process with an
//! injectable peer-credential provider, `/proc` reader and notifier.

pub mod audit;
pub mod core;
pub mod notify;
pub mod peer;
pub mod procinfo;
pub mod runtime;
pub mod server;
