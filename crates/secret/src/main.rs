//! `secret`: client CLI for secretd.

mod inject;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use secret_client::{Client, Error, GetOptions, Kind};
use std::collections::HashMap;
use std::io::{IsTerminal, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const DEFAULT_SOCKET: &str = secret_proto::DEFAULT_SOCKET;
const MAX_TEMPLATE: usize = 64 * 1024 * 1024;

#[derive(Parser)]
#[command(name = "secret", version, about = "Request secrets from secretd")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(clap::Args, Clone)]
struct Common {
    /// secretd socket path (default: $SECRETD_SOCKET or /run/secretd/secretd.sock,
    /// /var/run/secretd/secretd.sock on macOS).
    #[arg(long, global = true, env = "SECRETD_SOCKET")]
    socket: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print one secret to stdout (no trailing newline unless stdout is a terminal).
    Get {
        name: String,
        /// Free-text reason shown to the owner (max 200 chars).
        #[arg(long)]
        reason: Option<String>,
        /// Maximum seconds to wait for the owner.
        #[arg(long)]
        timeout: Option<u64>,
        #[command(flatten)]
        common: Common,
    },
    /// List the secret names you are allowed to request.
    List {
        #[command(flatten)]
        common: Common,
    },
    /// Substitute `{{ secret:NAME }}` tokens in a template.
    Inject {
        /// Input file (default: stdin).
        #[arg(short = 'i', long = "in")]
        input: Option<PathBuf>,
        /// Output file, created with mode 0600 (default: stdout).
        #[arg(short = 'o', long = "out")]
        output: Option<PathBuf>,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        timeout: Option<u64>,
        /// Overwrite the output file if it exists.
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        common: Common,
    },
}

/// Exit codes: 0 ok; 1 generic; 2 not found/ACL; 3 denied; 4 timeout; 5 rate limited.
fn exit_code(e: &anyhow::Error) -> i32 {
    match e.downcast_ref::<Error>().and_then(Error::kind) {
        Some(Kind::NotFound) => 2,
        Some(Kind::Denied) => 3,
        Some(Kind::Timeout) => 4,
        Some(Kind::RateLimited) => 5,
        _ => 1,
    }
}

fn describe(e: &anyhow::Error) -> String {
    match e.downcast_ref::<Error>() {
        Some(Error::Rpc(r)) => match r.kind() {
            Some(Kind::NotFound) => "no such secret, or access denied".into(),
            Some(Kind::Denied) => "the owner denied the request".into(),
            Some(Kind::Timeout) => "timed out waiting for the owner".into(),
            Some(Kind::RateLimited) => "rate limited; try again later".into(),
            Some(Kind::CallerChanged) => "this process changed identity during the request".into(),
            Some(Kind::DecryptFailed) => "the owner's passphrase was wrong".into(),
            _ => r.message.clone(),
        },
        _ => format!("{e:#}"),
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("secret: {}", describe(&e));
        std::process::exit(exit_code(&e));
    }
}

fn connect(c: &Common) -> Result<Client> {
    let path = c
        .socket
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
    Client::connect(&path).with_context(|| format!("cannot connect to {}", path.display()))
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Cmd::Get {
            name,
            reason,
            timeout,
            common,
        } => cmd_get(&common, &name, reason, timeout),
        Cmd::List { common } => {
            let mut c = connect(&common)?;
            for n in c.list()? {
                println!("{n}");
            }
            Ok(())
        }
        Cmd::Inject {
            input,
            output,
            reason,
            timeout,
            force,
            common,
        } => cmd_inject(
            &common,
            input.as_deref(),
            output.as_deref(),
            reason,
            timeout,
            force,
        ),
    }
}

fn opts(reason: Option<String>, timeout: Option<u64>) -> GetOptions {
    GetOptions {
        reason,
        timeout_secs: timeout,
    }
}

fn cmd_get(
    common: &Common,
    name: &str,
    reason: Option<String>,
    timeout: Option<u64>,
) -> Result<()> {
    let mut c = connect(common)?;
    eprintln!("waiting for owner approval of {name:?}...");
    let v = c.get(name, &opts(reason, timeout))?;
    let mut out = std::io::stdout().lock();
    out.write_all(v.as_bytes())?;
    if std::io::stdout().is_terminal() {
        out.write_all(b"\n")?;
    }
    out.flush()?;
    Ok(())
}

fn cmd_inject(
    common: &Common,
    input: Option<&Path>,
    output: Option<&Path>,
    reason: Option<String>,
    timeout: Option<u64>,
    force: bool,
) -> Result<()> {
    // Fail early (before asking the owner for anything) if the output is unusable.
    if let Some(o) = output {
        if o.exists() && !force {
            bail!("{} exists; use --force to overwrite", o.display());
        }
    }
    let template: Zeroizing<Vec<u8>> = Zeroizing::new(match input {
        Some(p) => {
            let mut f = std::fs::File::open(p).with_context(|| p.display().to_string())?;
            inject::read_all(&mut f, MAX_TEMPLATE)?
        }
        None => inject::read_all(&mut std::io::stdin().lock(), MAX_TEMPLATE)?,
    });
    let segs = inject::parse(&template);
    let wanted = inject::names(&segs);

    // One request per distinct name, sequentially (respects the pending cap).
    let mut values: HashMap<&str, secret_client::SecretValue> = HashMap::new();
    if !wanted.is_empty() {
        let mut c = connect(common)?;
        let reason = reason.unwrap_or_else(|| "secret inject".to_string());
        for name in &wanted {
            eprintln!("waiting for owner approval of {name:?}...");
            let v = c.get(name, &opts(Some(reason.clone()), timeout))?;
            values.insert(name, v);
        }
    }
    let rendered = Zeroizing::new(
        inject::render(&segs, |n| values.get(n).map(|v| v.as_bytes()))
            .ok_or_else(|| anyhow!("internal error: missing secret"))?,
    );

    // Everything succeeded: write the output in one go.
    match output {
        None => {
            let mut out = std::io::stdout().lock();
            out.write_all(&rendered)?;
            out.flush()?;
        }
        Some(path) => write_output(path, &rendered, force)?,
    }
    Ok(())
}

fn write_output(path: &Path, data: &[u8], force: bool) -> Result<()> {
    if force {
        // Atomic replace: temp file (0600) in the same directory, then rename.
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut rnd = [0u8; 8];
        let mut f = std::fs::File::open("/dev/urandom")?;
        f.read_exact(&mut rnd)?;
        let tmp = dir.join(format!(
            ".secret-inject.{}.tmp",
            rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        let res = (|| -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)
        })();
        if res.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        res.with_context(|| format!("writing {}", path.display()))
    } else {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        if let Err(e) = f.write_all(data).and_then(|_| f.sync_all()) {
            let _ = std::fs::remove_file(path);
            return Err(e).with_context(|| format!("writing {}", path.display()));
        }
        Ok(())
    }
}
