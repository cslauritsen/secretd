//! Unix socket servers: the client socket (`secret.*`, `server.ping`) and the
//! admin socket (`admin.*`).  Newline-delimited JSON-RPC 2.0, async I/O.

use crate::core::{ApproveOutcome, Core, DenyOutcome, Released, Source};
use crate::peer::PeerCredProvider;
use secret_proto::rpc::{
    parse_request, AdminApproveParams, AdminDenyParams, ErrorKind, GetParams, ListResult,
    PingResult, Request, Response, RpcError,
};
use secret_proto::{framing, Encoding, MAX_LINE_LEN};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

/// Cancel-safe line reader with an internal buffer.
pub struct LineReader {
    rd: OwnedReadHalf,
    buf: Vec<u8>,
}

pub enum Line {
    Line(Vec<u8>),
    Eof,
    TooLong,
}

impl LineReader {
    pub fn new(rd: OwnedReadHalf) -> Self {
        LineReader {
            rd,
            buf: Vec::new(),
        }
    }

    fn take_line(&mut self) -> Option<Line> {
        let pos = self.buf.iter().position(|&b| b == b'\n');
        match pos {
            Some(p) if p > MAX_LINE_LEN => Some(Line::TooLong),
            Some(p) => {
                let mut line: Vec<u8> = self.buf.drain(..=p).collect();
                line.pop();
                Some(Line::Line(line))
            }
            None if self.buf.len() > MAX_LINE_LEN => Some(Line::TooLong),
            None => None,
        }
    }

    /// Next complete line. Cancel-safe: partial data stays buffered.
    pub async fn next_line(&mut self) -> std::io::Result<Line> {
        loop {
            if let Some(l) = self.take_line() {
                return Ok(l);
            }
            let mut chunk = [0u8; 4096];
            let n = self.rd.read(&mut chunk).await?;
            if n == 0 {
                return Ok(Line::Eof);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Resolves when the peer closes the connection (or misbehaves by
    /// flooding while a request is in flight). Data read meanwhile stays
    /// buffered for the next request.
    pub async fn wait_disconnect(&mut self) {
        loop {
            if self.buf.len() > MAX_LINE_LEN {
                return;
            }
            let mut chunk = [0u8; 4096];
            match self.rd.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }
}

async fn send(wr: &mut OwnedWriteHalf, resp: &Response) -> std::io::Result<()> {
    let line = framing::encode_line(resp)?;
    wr.write_all(&line).await?;
    wr.flush().await
}

/// Serialise a successful `secret.get` response straight into a zeroizing
/// buffer so the value is never copied into an ordinary `String`/`Value`.
fn release_line(id: &Value, r: &Released) -> Zeroizing<Vec<u8>> {
    #[derive(serde::Serialize)]
    struct Res<'a> {
        name: &'a str,
        value: &'a str,
        encoding: Encoding,
    }
    // JSON escaping can expand a byte up to six-fold; pre-size to avoid
    // reallocation (which would leave unzeroized copies).
    let mut out = Zeroizing::new(Vec::with_capacity(r.value.len() * 6 + 256));
    out.extend_from_slice(br#"{"jsonrpc":"2.0","result":"#);
    let _ = serde_json::to_writer(
        &mut *out,
        &Res {
            name: &r.name,
            value: &r.value,
            encoding: r.encoding,
        },
    );
    out.extend_from_slice(br#","id":"#);
    let _ = serde_json::to_writer(&mut *out, id);
    out.extend_from_slice(b"}\n");
    out
}

/// Accept loop for the client socket.
pub async fn serve_clients(
    core: Arc<Core>,
    listener: UnixListener,
    peer: Arc<dyn PeerCredProvider>,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::error!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let core = core.clone();
        let peer = peer.clone();
        tokio::spawn(async move {
            handle_client(core, stream, peer).await;
        });
    }
}

async fn handle_client(core: Arc<Core>, stream: UnixStream, peer: Arc<dyn PeerCredProvider>) {
    // Credentials come from the kernel, read immediately.
    let cred = match peer.peer_cred(&stream) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("SO_PEERCRED failed: {e}");
            return;
        }
    };
    let (rd, mut wr) = stream.into_split();
    let Some(_guard) = core.acquire_conn(cred.uid) else {
        let _ = send(
            &mut wr,
            &Response::err(Value::Null, RpcError::new(ErrorKind::RateLimited)),
        )
        .await;
        return;
    };
    let caller = core.identify(cred);
    let mut lr = LineReader::new(rd);
    let idle = Duration::from_secs(core.config().limits.idle_timeout_secs.max(1));

    loop {
        let line = match tokio::time::timeout(idle, lr.next_line()).await {
            Ok(Ok(Line::Line(l))) => l,
            Ok(Ok(Line::TooLong)) => {
                let _ = send(
                    &mut wr,
                    &Response::err(Value::Null, RpcError::new(ErrorKind::InvalidRequest)),
                )
                .await;
                return;
            }
            Ok(Ok(Line::Eof)) | Ok(Err(_)) | Err(_) => return,
        };
        let req = match parse_request(&line) {
            Ok(r) => r,
            Err((id, e)) => {
                if send(&mut wr, &Response::err(id, e)).await.is_err() {
                    return;
                }
                continue;
            }
        };
        let Some(id) = req.id.clone() else {
            continue; // notification: no response
        };
        let ok = match req.method.as_str() {
            "secret.get" => {
                let params: Result<GetParams, _> = serde_json::from_value(req.params);
                match params {
                    Err(_) => {
                        send(
                            &mut wr,
                            &Response::err(id, RpcError::new(ErrorKind::InvalidParams)),
                        )
                        .await
                    }
                    Ok(p) => match core.get(&caller, p, lr.wait_disconnect()).await {
                        Ok(rel) => {
                            let line = release_line(&id, &rel);
                            let r = wr.write_all(&line).await;
                            match r {
                                Ok(()) => wr.flush().await,
                                Err(e) => Err(e),
                            }
                        }
                        Err(e) => send(&mut wr, &Response::err(id, e)).await,
                    },
                }
            }
            "secret.list" => {
                let names = core.list_names(&caller);
                send(&mut wr, &Response::ok(id, json!(ListResult { names }))).await
            }
            "server.ping" => {
                let r = PingResult {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    sealed: true,
                };
                send(&mut wr, &Response::ok(id, json!(r))).await
            }
            _ => {
                send(
                    &mut wr,
                    &Response::err(id, RpcError::new(ErrorKind::MethodNotFound)),
                )
                .await
            }
        };
        if ok.is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------- admin

/// Accept loop for the admin socket. Only uid 0 (per `SO_PEERCRED`) is served.
pub async fn serve_admin(core: Arc<Core>, listener: UnixListener, peer: Arc<dyn PeerCredProvider>) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::error!("admin accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let core = core.clone();
        let peer = peer.clone();
        tokio::spawn(async move {
            handle_admin(core, stream, peer).await;
        });
    }
}

async fn handle_admin(core: Arc<Core>, stream: UnixStream, peer: Arc<dyn PeerCredProvider>) {
    match peer.peer_cred(&stream) {
        Ok(c) if c.uid == 0 => {}
        Ok(c) => {
            tracing::warn!("admin socket: rejected uid {}", c.uid);
            return;
        }
        Err(_) => return,
    }
    let (rd, mut wr) = stream.into_split();
    let mut lr = LineReader::new(rd);
    loop {
        let line = match tokio::time::timeout(Duration::from_secs(120), lr.next_line()).await {
            Ok(Ok(Line::Line(l))) => l,
            _ => return,
        };
        let req: Request = match parse_request(&line) {
            Ok(r) => r,
            Err((id, e)) => {
                if send(&mut wr, &Response::err(id, e)).await.is_err() {
                    return;
                }
                continue;
            }
        };
        let Some(id) = req.id.clone() else { continue };
        let resp = admin_dispatch(&core, &req).await;
        let resp = match resp {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, e),
        };
        if send(&mut wr, &resp).await.is_err() {
            return;
        }
    }
}

async fn admin_dispatch(core: &Arc<Core>, req: &Request) -> Result<Value, RpcError> {
    let _ = core.audit(
        &crate::audit::AuditEvent::new("admin_action")
            .outcome(&req.method)
            .detail("admin socket"),
    );
    match req.method.as_str() {
        "admin.pending" => Ok(json!({ "pending": core.pending_list() })),
        "admin.deny" => {
            let p: AdminDenyParams = serde_json::from_value(req.params.clone())
                .map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
            match core.deny(&p.request_id, Source::Admin) {
                DenyOutcome::Denied => Ok(json!({ "ok": true })),
                DenyOutcome::Gone => Err(RpcError::with_message(
                    ErrorKind::NotFound,
                    "no such pending request",
                )),
            }
        }
        "admin.approve" => {
            let p: AdminApproveParams = serde_json::from_value(req.params.clone())
                .map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
            let pass = Zeroizing::new(p.passphrase);
            match core.approve(&p.request_id, pass, Source::Admin).await {
                ApproveOutcome::Released => Ok(json!({ "ok": true })),
                ApproveOutcome::WrongPassphrase { remaining } => Err(RpcError::with_message(
                    ErrorKind::DecryptFailed,
                    "wrong passphrase",
                )
                .with_remaining(remaining)),
                ApproveOutcome::Failed => Err(RpcError::with_message(
                    ErrorKind::DecryptFailed,
                    "wrong passphrase; request denied after too many attempts",
                )
                .with_remaining(0)),
                ApproveOutcome::Gone | ApproveOutcome::Busy => Err(RpcError::with_message(
                    ErrorKind::NotFound,
                    "no such pending request",
                )),
                ApproveOutcome::CallerChanged => Err(RpcError::new(ErrorKind::CallerChanged)),
                ApproveOutcome::NotInStore => Err(RpcError::with_message(
                    ErrorKind::NotFound,
                    "secret is not in the store",
                )),
                ApproveOutcome::Internal => Err(RpcError::new(ErrorKind::Internal)),
            }
        }
        _ => Err(RpcError::new(ErrorKind::MethodNotFound)),
    }
}
