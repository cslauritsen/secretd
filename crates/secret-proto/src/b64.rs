//! Standard base64 helpers (thin wrapper so callers need no extra dependency).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

pub fn encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn decode(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s.trim()).ok()
}
