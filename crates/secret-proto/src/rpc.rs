//! JSON-RPC 2.0 message types and the secretd error vocabulary.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const JSONRPC: &str = "2.0";

/// Application error kinds (spec section 3.4) plus the standard JSON-RPC errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    NotFound,
    Denied,
    Timeout,
    RateLimited,
    CallerChanged,
    DecryptFailed,
    Internal,
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
}

impl ErrorKind {
    pub fn code(self) -> i64 {
        match self {
            ErrorKind::NotFound => -32001,
            ErrorKind::Denied => -32002,
            ErrorKind::Timeout => -32003,
            ErrorKind::RateLimited => -32004,
            ErrorKind::CallerChanged => -32005,
            ErrorKind::DecryptFailed => -32006,
            ErrorKind::Internal => -32007,
            ErrorKind::ParseError => -32700,
            ErrorKind::InvalidRequest => -32600,
            ErrorKind::MethodNotFound => -32601,
            ErrorKind::InvalidParams => -32602,
        }
    }

    /// Stable string placed in `error.data.kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::NotFound => "NOT_FOUND",
            ErrorKind::Denied => "DENIED",
            ErrorKind::Timeout => "TIMEOUT",
            ErrorKind::RateLimited => "RATE_LIMITED",
            ErrorKind::CallerChanged => "CALLER_CHANGED",
            ErrorKind::DecryptFailed => "DECRYPT_FAILED",
            ErrorKind::Internal => "INTERNAL",
            ErrorKind::ParseError => "PARSE_ERROR",
            ErrorKind::InvalidRequest => "INVALID_REQUEST",
            ErrorKind::MethodNotFound => "METHOD_NOT_FOUND",
            ErrorKind::InvalidParams => "INVALID_PARAMS",
        }
    }

    pub fn from_code(code: i64) -> Option<Self> {
        Some(match code {
            -32001 => ErrorKind::NotFound,
            -32002 => ErrorKind::Denied,
            -32003 => ErrorKind::Timeout,
            -32004 => ErrorKind::RateLimited,
            -32005 => ErrorKind::CallerChanged,
            -32006 => ErrorKind::DecryptFailed,
            -32007 => ErrorKind::Internal,
            -32700 => ErrorKind::ParseError,
            -32600 => ErrorKind::InvalidRequest,
            -32601 => ErrorKind::MethodNotFound,
            -32602 => ErrorKind::InvalidParams,
            _ => return None,
        })
    }

    /// Short generic message; never carries internal details.
    pub fn default_message(self) -> &'static str {
        match self {
            ErrorKind::NotFound => "no such secret",
            ErrorKind::Denied => "request denied by owner",
            ErrorKind::Timeout => "no owner response in time",
            ErrorKind::RateLimited => "rate limited",
            ErrorKind::CallerChanged => "caller identity changed",
            ErrorKind::DecryptFailed => "decryption failed",
            ErrorKind::Internal => "internal error",
            ErrorKind::ParseError => "parse error",
            ErrorKind::InvalidRequest => "invalid request",
            ErrorKind::MethodNotFound => "method not found",
            ErrorKind::InvalidParams => "invalid params",
        }
    }
}

/// The `error.data` object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorData {
    pub kind: String,
    /// Remaining passphrase attempts (admin socket, `DECRYPT_FAILED` retries).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_attempts: Option<u8>,
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<ErrorData>,
}

impl RpcError {
    pub fn new(kind: ErrorKind) -> Self {
        RpcError {
            code: kind.code(),
            message: kind.default_message().to_string(),
            data: Some(ErrorData {
                kind: kind.as_str().to_string(),
                remaining_attempts: None,
            }),
        }
    }

    pub fn with_message(kind: ErrorKind, message: impl Into<String>) -> Self {
        let mut e = Self::new(kind);
        e.message = message.into();
        e
    }

    pub fn with_remaining(mut self, remaining: u8) -> Self {
        if let Some(d) = self.data.as_mut() {
            d.remaining_attempts = Some(remaining);
        }
        self
    }

    pub fn kind(&self) -> Option<ErrorKind> {
        ErrorKind::from_code(self.code)
    }

    pub fn kind_str(&self) -> Option<&str> {
        self.data.as_ref().map(|d| d.kind.as_str())
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for RpcError {}

/// A JSON-RPC request. `id` is `None` for notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub params: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
}

impl Request {
    pub fn new(method: &str, params: Value, id: u64) -> Self {
        Request {
            jsonrpc: JSONRPC.to_string(),
            method: method.to_string(),
            params,
            id: Some(Value::from(id)),
        }
    }
}

/// A JSON-RPC response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    pub id: Value,
}

impl Response {
    pub fn ok(id: Value, result: Value) -> Self {
        Response {
            jsonrpc: JSONRPC.to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn err(id: Value, error: RpcError) -> Self {
        Response {
            jsonrpc: JSONRPC.to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

/// Parse one protocol line into a request, mapping failures to the right
/// standard JSON-RPC error.  The returned id (if recoverable) lets the caller
/// address the error response.
pub fn parse_request(line: &[u8]) -> Result<Request, (Value, RpcError)> {
    let value: Value = serde_json::from_slice(line)
        .map_err(|_| (Value::Null, RpcError::new(ErrorKind::ParseError)))?;
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let id_ok = matches!(id, Value::Null | Value::String(_) | Value::Number(_));
    if !value.is_object() || !id_ok {
        return Err((Value::Null, RpcError::new(ErrorKind::InvalidRequest)));
    }
    let req: Request = serde_json::from_value(value)
        .map_err(|_| (id.clone(), RpcError::new(ErrorKind::InvalidRequest)))?;
    if req.jsonrpc != JSONRPC {
        return Err((id, RpcError::new(ErrorKind::InvalidRequest)));
    }
    Ok(req)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Utf8,
    Base64,
}

/// `secret.get` params.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GetParams {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

/// `secret.get` result. The value is deliberately not `Debug`-printable.
#[derive(Serialize, Deserialize)]
pub struct GetResult {
    pub name: String,
    pub value: String,
    pub encoding: Encoding,
}

impl std::fmt::Debug for GetResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetResult")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("encoding", &self.encoding)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListResult {
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PingResult {
    pub version: String,
    pub sealed: bool,
}

/// A pending request as shown to the owner (admin socket).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingInfo {
    pub request_id: String,
    pub secret_name: String,
    pub uid: u32,
    pub username: String,
    pub pid: u32,
    pub exe: String,
    pub cmdline: String,
    /// Client supplied, untrusted, sanitised.
    pub reason: Option<String>,
    pub expires_at: String,
}

/// Admin socket params for `admin.approve`.
#[derive(Serialize, Deserialize)]
pub struct AdminApproveParams {
    pub request_id: String,
    pub passphrase: String,
}

impl std::fmt::Debug for AdminApproveParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminApproveParams")
            .field("request_id", &self.request_id)
            .field("passphrase", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminDenyParams {
    pub request_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_ok() {
        let r = parse_request(br#"{"jsonrpc":"2.0","method":"server.ping","id":1}"#).unwrap();
        assert_eq!(r.method, "server.ping");
        assert_eq!(r.id, Some(json!(1)));
        assert!(r.params.is_null());
    }

    #[test]
    fn parse_errors() {
        let (id, e) = parse_request(b"{not json").unwrap_err();
        assert_eq!(id, Value::Null);
        assert_eq!(e.code, -32700);
        let (_, e) = parse_request(b"[1,2]").unwrap_err();
        assert_eq!(e.code, -32600);
        let (id, e) = parse_request(br#"{"jsonrpc":"1.0","method":"x","id":7}"#).unwrap_err();
        assert_eq!(id, json!(7));
        assert_eq!(e.code, -32600);
        let (_, e) = parse_request(br#"{"jsonrpc":"2.0","id":7}"#).unwrap_err();
        assert_eq!(e.code, -32600);
        let (_, e) = parse_request(br#"{"jsonrpc":"2.0","method":"x","id":{"a":1}}"#).unwrap_err();
        assert_eq!(e.code, -32600);
    }

    #[test]
    fn error_codes_round_trip() {
        for k in [
            ErrorKind::NotFound,
            ErrorKind::Denied,
            ErrorKind::Timeout,
            ErrorKind::RateLimited,
            ErrorKind::CallerChanged,
            ErrorKind::DecryptFailed,
            ErrorKind::Internal,
            ErrorKind::ParseError,
            ErrorKind::InvalidRequest,
            ErrorKind::MethodNotFound,
            ErrorKind::InvalidParams,
        ] {
            assert_eq!(ErrorKind::from_code(k.code()), Some(k));
            let e = RpcError::new(k);
            assert_eq!(e.kind(), Some(k));
            assert_eq!(e.kind_str(), Some(k.as_str()));
        }
        assert_eq!(ErrorKind::NotFound.code(), -32001);
        assert_eq!(ErrorKind::Internal.code(), -32007);
        assert_eq!(ErrorKind::DecryptFailed.as_str(), "DECRYPT_FAILED");
    }

    #[test]
    fn response_serialisation() {
        let r = Response::err(json!(3), RpcError::new(ErrorKind::Denied));
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"code\":-32002"));
        assert!(s.contains("\"kind\":\"DENIED\""));
        assert!(!s.contains("\"result\""));
    }

    #[test]
    fn get_result_debug_redacts() {
        let g = GetResult {
            name: "n".into(),
            value: "hunter2".into(),
            encoding: Encoding::Utf8,
        };
        assert!(!format!("{g:?}").contains("hunter2"));
        let a = AdminApproveParams {
            request_id: "x".into(),
            passphrase: "pw-secret".into(),
        };
        assert!(!format!("{a:?}").contains("pw-secret"));
    }
}
