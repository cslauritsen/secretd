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

pub use rpc::{
    Encoding, ErrorKind, GetParams, GetResult, ListResult, PendingInfo, PingResult, Request,
    Response, RpcError,
};

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
