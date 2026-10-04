//! Shared types for secretd: JSON-RPC messages, error codes, framing and
//! text sanitisation.  With the `server` feature this crate also contains the
//! age-encrypted store, the configuration model and ACL evaluation.

pub mod b64;
pub mod framing;
pub mod rpc;
pub mod sanitize;

#[cfg(feature = "server")]
pub mod acl;
#[cfg(feature = "server")]
pub mod config;
#[cfg(feature = "server")]
pub mod mem;
#[cfg(feature = "server")]
pub mod store;
#[cfg(feature = "server")]
pub mod sys;

pub use rpc::{
    Encoding, ErrorKind, GetParams, GetResult, ListResult, PendingInfo, PingResult, Request,
    Response, RpcError,
};

/// Directory of the daemon's runtime sockets (spec section 22): `/run` is a
/// tmpfs on Linux; macOS has no `/run`, its equivalent is `/var/run`.
#[cfg(target_os = "macos")]
pub const DEFAULT_RUN_DIR: &str = "/var/run/secretd";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_RUN_DIR: &str = "/run/secretd";

/// Default client socket path (per OS, see [`DEFAULT_RUN_DIR`]).
#[cfg(target_os = "macos")]
pub const DEFAULT_SOCKET: &str = "/var/run/secretd/secretd.sock";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_SOCKET: &str = "/run/secretd/secretd.sock";

/// Default admin socket path (per OS).
#[cfg(target_os = "macos")]
pub const DEFAULT_ADMIN_SOCKET: &str = "/var/run/secretd/admin.sock";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_ADMIN_SOCKET: &str = "/run/secretd/admin.sock";

/// Maximum length of one protocol line (excluding the newline): 64 KiB.
pub const MAX_LINE_LEN: usize = 64 * 1024;

/// Maximum length in characters of the client supplied `reason`.
pub const MAX_REASON_CHARS: usize = 200;

/// Returns true if `name` is a syntactically valid secret name
/// (`[A-Za-z0-9._/-]+`, at most 256 bytes).
pub fn valid_secret_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(valid_secret_name("db-password"));
        assert!(valid_secret_name("a/b.c_d"));
        assert!(!valid_secret_name(""));
        assert!(!valid_secret_name("a b"));
        assert!(!valid_secret_name("a\n"));
        assert!(!valid_secret_name(&"a".repeat(257)));
    }
}
