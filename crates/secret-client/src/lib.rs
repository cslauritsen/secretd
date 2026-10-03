//! Synchronous client for the secretd Unix-socket protocol.
//!
//! ```no_run
//! use secret_client::{Client, GetOptions};
//! let mut c = Client::connect("/run/secretd/secretd.sock")?;
//! let v = c.get("db-password", &GetOptions::new().reason("nightly backup"))?;
//! assert!(!v.as_bytes().is_empty());
//! # Ok::<(), secret_client::Error>(())
//! ```

use secret_proto::rpc::{ErrorKind, GetParams, ListResult, PingResult, Request, RpcError};
use secret_proto::{b64, framing, Encoding, MAX_LINE_LEN};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub use secret_proto::rpc::ErrorKind as Kind;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The daemon returned a JSON-RPC error.
    #[error("{0}")]
    Rpc(RpcError),
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl Error {
    /// The application error kind, for `Rpc` errors.
    pub fn kind(&self) -> Option<ErrorKind> {
        match self {
            Error::Rpc(e) => e.kind(),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Options for [`Client::get`].
#[derive(Debug, Clone, Default)]
pub struct GetOptions {
    pub reason: Option<String>,
    pub timeout_secs: Option<u64>,
}

impl GetOptions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn reason(mut self, r: impl Into<String>) -> Self {
        self.reason = Some(r.into());
        self
    }
    pub fn timeout_secs(mut self, t: u64) -> Self {
        self.timeout_secs = Some(t);
        self
    }
}

/// Secret bytes, zeroized on drop. `Debug` never prints the contents.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// The value as text, if it is valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Take the zeroizing buffer.
    pub fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretValue(<{} bytes redacted>)", self.0.len())
    }
}

#[derive(Deserialize)]
struct Envelope<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RawGet {
    value: Zeroizing<String>,
    encoding: Encoding,
}

/// A connection to secretd. Requests are sequential; `get` blocks until the
/// owner approves, denies, or the request times out.
pub struct Client {
    stream: UnixStream,
    /// Bytes read past the end of the last line (zeroized on drop).
    spill: Zeroizing<Vec<u8>>,
    next_id: u64,
}

impl Client {
    pub fn connect(path: impl AsRef<Path>) -> Result<Client> {
        Ok(Client {
            stream: UnixStream::connect(path)?,
            spill: Zeroizing::new(Vec::new()),
            next_id: 1,
        })
    }

    /// Read one line into a zeroizing buffer without an intermediate
    /// (unzeroized) `BufReader` copy of the response.
    fn read_line(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let mut line = Zeroizing::new(Vec::with_capacity(512));
        let mut chunk = Zeroizing::new([0u8; 4096]);
        loop {
            if let Some(pos) = self.spill.iter().position(|&b| b == b'\n') {
                line.extend_from_slice(&self.spill[..pos]);
                let rest: Vec<u8> = self.spill[pos + 1..].to_vec();
                self.spill.zeroize();
                *self.spill = rest;
                return Ok(line);
            }
            if self.spill.len() > MAX_LINE_LEN {
                return Err(Error::Protocol("response line too long".into()));
            }
            let n = self.stream.read(&mut chunk[..])?;
            if n == 0 {
                return Err(Error::Protocol("connection closed by daemon".into()));
            }
            self.spill.extend_from_slice(&chunk[..n]);
            chunk.zeroize();
        }
    }

    fn call<T: for<'de> Deserialize<'de>>(&mut self, method: &str, params: Value) -> Result<T> {
        let id = self.next_id;
        self.next_id += 1;
        let req = framing::encode_line(&Request::new(method, params, id))?;
        self.stream.write_all(&req)?;
        let line = self.read_line()?;
        let env: Envelope<T> = serde_json::from_slice(&line)
            .map_err(|_| Error::Protocol("malformed response".into()))?;
        if let Some(e) = env.error {
            return Err(Error::Rpc(e));
        }
        env.result
            .ok_or_else(|| Error::Protocol("response has neither result nor error".into()))
    }

    /// Request a secret. Blocks until the owner decides.
    pub fn get(&mut self, name: &str, opts: &GetOptions) -> Result<SecretValue> {
        let params = GetParams {
            name: name.to_string(),
            reason: opts.reason.clone(),
            timeout_secs: opts.timeout_secs,
        };
        let raw: RawGet = self.call(
            "secret.get",
            serde_json::to_value(params).map_err(|e| Error::Protocol(e.to_string()))?,
        )?;
        let bytes = match raw.encoding {
            Encoding::Utf8 => Zeroizing::new(raw.value.as_bytes().to_vec()),
            Encoding::Base64 => Zeroizing::new(
                b64::decode(&raw.value)
                    .ok_or_else(|| Error::Protocol("invalid base64 in response".into()))?,
            ),
        };
        Ok(SecretValue(bytes))
    }

    /// Names this caller may request.
    pub fn list(&mut self) -> Result<Vec<String>> {
        let r: ListResult = self.call("secret.list", json!({}))?;
        Ok(r.names)
    }

    /// Liveness check; returns the daemon version.
    pub fn ping(&mut self) -> Result<String> {
        let r: PingResult = self.call("server.ping", json!({}))?;
        Ok(r.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;

    fn serve(
        replies: Vec<String>,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::thread::JoinHandle<Vec<Value>>,
    ) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s");
        let l = UnixListener::bind(&p).unwrap();
        let h = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut rd = BufReader::new(s.try_clone().unwrap());
            let mut wr = s;
            let mut seen = Vec::new();
            for r in replies {
                let mut line = String::new();
                rd.read_line(&mut line).unwrap();
                let req: Value = serde_json::from_str(&line).unwrap();
                let resp = r.replace("\"ID\"", &req["id"].to_string());
                seen.push(req);
                wr.write_all(resp.as_bytes()).unwrap();
            }
            seen
        });
        (d, p, h)
    }

    #[test]
    fn get_decodes_utf8_and_base64() {
        let (_d, p, h) = serve(vec![
            "{\"jsonrpc\":\"2.0\",\"result\":{\"name\":\"a\",\"value\":\"hello\",\"encoding\":\"utf8\"},\"id\":\"ID\"}\n".into(),
            // two responses in one write exercise the spill buffer
            "{\"jsonrpc\":\"2.0\",\"result\":{\"name\":\"b\",\"value\":\"AP8=\",\"encoding\":\"base64\"},\"id\":\"ID\"}\n".into(),
        ]);
        let mut c = Client::connect(&p).unwrap();
        let v = c
            .get("a", &GetOptions::new().reason("why").timeout_secs(5))
            .unwrap();
        assert_eq!(v.as_str(), Some("hello"));
        let v = c.get("b", &GetOptions::new()).unwrap();
        assert_eq!(v.as_bytes(), &[0, 255]);
        let seen = h.join().unwrap();
        assert_eq!(seen[0]["method"], "secret.get");
        assert_eq!(seen[0]["params"]["name"], "a");
        assert_eq!(seen[0]["params"]["reason"], "why");
        assert_eq!(seen[0]["params"]["timeout_secs"], 5);
        assert!(seen[1]["params"].get("reason").is_none());
    }

    #[test]
    fn errors_map_to_kinds() {
        let (_d, p, h) = serve(vec![
            "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32002,\"message\":\"x\",\"data\":{\"kind\":\"DENIED\"}},\"id\":\"ID\"}\n".into(),
            "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32003,\"message\":\"x\",\"data\":{\"kind\":\"TIMEOUT\"}},\"id\":\"ID\"}\n".into(),
        ]);
        let mut c = Client::connect(&p).unwrap();
        assert_eq!(
            c.get("a", &GetOptions::new()).unwrap_err().kind(),
            Some(Kind::Denied)
        );
        assert_eq!(c.list().unwrap_err().kind(), Some(Kind::Timeout));
        h.join().unwrap();
    }

    #[test]
    fn list_ping_and_protocol_errors() {
        let (_d, p, h) = serve(vec![
            "{\"jsonrpc\":\"2.0\",\"result\":{\"names\":[\"a\",\"b\"]},\"id\":\"ID\"}\n".into(),
            "{\"jsonrpc\":\"2.0\",\"result\":{\"version\":\"9.9\",\"sealed\":true},\"id\":\"ID\"}\n".into(),
            "garbage\n".into(),
        ]);
        let mut c = Client::connect(&p).unwrap();
        assert_eq!(c.list().unwrap(), vec!["a", "b"]);
        assert_eq!(c.ping().unwrap(), "9.9");
        assert!(matches!(c.ping(), Err(Error::Protocol(_))));
        h.join().unwrap();
        // The server side is gone now.
        assert!(c.ping().is_err());
    }

    #[test]
    fn debug_does_not_print_contents() {
        let v = SecretValue(Zeroizing::new(b"hunter2".to_vec()));
        let s = format!("{v:?}");
        assert!(!s.contains("hunter2"));
        assert!(s.contains("7 bytes"));
    }

    #[test]
    fn connect_failure_is_io_error() {
        assert!(matches!(
            Client::connect("/nonexistent/sock"),
            Err(Error::Io(_))
        ));
    }
}
