//! Terminal fallback: talk to the daemon's admin socket (peer uid must be 0).

use crate::util::*;
use crate::Cli;
use anyhow::{anyhow, bail, Context, Result};
use secret_proto::framing::{self, Frame};
use secret_proto::rpc::{
    AdminApproveParams, AdminDenyParams, ErrorKind, PendingInfo, Request, Response,
};
use serde_json::{json, Value};
use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

struct AdminConn {
    rd: BufReader<UnixStream>,
    wr: UnixStream,
    next: u64,
}

fn socket_path(cli: &Cli) -> Result<PathBuf> {
    if let Some(p) = &cli.admin_socket {
        return Ok(p.clone());
    }
    Ok(load_config(cli)?.daemon.admin_socket)
}

impl AdminConn {
    fn connect(cli: &Cli) -> Result<Self> {
        let path = socket_path(cli)?;
        let s = UnixStream::connect(&path)
            .with_context(|| format!("connecting to admin socket {}", path.display()))?;
        Ok(AdminConn {
            rd: BufReader::new(s.try_clone()?),
            wr: s,
            next: 1,
        })
    }

    fn call(&mut self, method: &str, params: Value) -> Result<Response> {
        let id = self.next;
        self.next += 1;
        framing::write_line(&mut self.wr, &Request::new(method, params, id))?;
        let mut buf = Vec::new();
        match framing::read_frame(&mut self.rd, &mut buf, secret_proto::MAX_LINE_LEN)? {
            Frame::Line => Ok(serde_json::from_slice(&buf)?),
            _ => bail!("admin socket closed the connection (is your uid 0?)"),
        }
    }
}

pub fn pending(cli: &Cli) -> Result<()> {
    let mut c = AdminConn::connect(cli)?;
    let r = c.call("admin.pending", json!({}))?;
    if let Some(e) = r.error {
        bail!("{e}");
    }
    let list: Vec<PendingInfo> = serde_json::from_value(
        r.result
            .and_then(|v| v.get("pending").cloned())
            .ok_or_else(|| anyhow!("malformed response"))?,
    )?;
    if list.is_empty() {
        println!("no pending requests");
        return Ok(());
    }
    for p in list {
        println!(
            "{}  {}  uid={} ({})  pid={}  expires {}",
            p.request_id, p.secret_name, p.uid, p.username, p.pid, p.expires_at
        );
        println!("    exe:     {}", p.exe);
        println!("    cmdline: {}", p.cmdline);
        if let Some(r) = p.reason {
            println!("    reason (client-supplied, untrusted): {r}");
        }
    }
    Ok(())
}

pub fn approve(cli: &Cli, id: &str) -> Result<()> {
    let mut c = AdminConn::connect(cli)?;
    loop {
        let pass = passphrase(cli, "Store passphrase: ")?;
        let params = AdminApproveParams {
            request_id: id.to_string(),
            passphrase: pass.as_str().to_string(),
        };
        let r = c.call("admin.approve", serde_json::to_value(&params)?)?;
        drop(params);
        match r.error {
            None => {
                eprintln!("approved: secret released to the waiting process");
                return Ok(());
            }
            Some(e) => {
                let retry = e.kind() == Some(ErrorKind::DecryptFailed)
                    && e.data
                        .as_ref()
                        .and_then(|d| d.remaining_attempts)
                        .unwrap_or(0)
                        > 0;
                if retry && cli.passphrase_file.is_none() {
                    eprintln!(
                        "wrong passphrase; {} attempt(s) remaining",
                        e.data.and_then(|d| d.remaining_attempts).unwrap_or(0)
                    );
                    continue;
                }
                bail!("{e}");
            }
        }
    }
}

pub fn deny(cli: &Cli, id: &str) -> Result<()> {
    let mut c = AdminConn::connect(cli)?;
    let r = c.call(
        "admin.deny",
        serde_json::to_value(AdminDenyParams {
            request_id: id.to_string(),
        })?,
    )?;
    if let Some(e) = r.error {
        bail!("{e}");
    }
    eprintln!("denied");
    Ok(())
}
