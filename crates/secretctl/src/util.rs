use crate::Cli;
use anyhow::{anyhow, bail, Context, Result};
use secret_proto::config::{Config, SystemResolver};
use secret_proto::store::Passphrase;
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Uids allowed to own the config file: root, ourselves, and the daemon user.
pub fn trusted_uids(daemon_user: Option<&str>) -> Vec<u32> {
    let mut v = vec![0, nix_euid()];
    if let Some(u) = daemon_user {
        if let Some(uid) = secret_proto::config::NameResolver::uid(&SystemResolver, u) {
            v.push(uid);
        }
    }
    v
}

fn nix_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Load the config (permission-checked).
pub fn load_config(cli: &Cli) -> Result<Config> {
    let uids = trusted_uids(Some("secretd"));
    Config::load(&cli.config, &uids, &SystemResolver)
        .map_err(|e| anyhow!("{e}"))
        .with_context(|| format!("loading config {}", cli.config.display()))
}

/// Best-effort config load (used to cross-check names).
pub fn try_load_config(cli: &Cli) -> Option<Config> {
    if cli.config.exists() {
        load_config(cli).ok()
    } else {
        None
    }
}

pub fn store_path(cli: &Cli) -> Result<PathBuf> {
    if let Some(p) = &cli.store {
        return Ok(p.clone());
    }
    Ok(load_config(cli)?.daemon.store)
}

fn read_first_line(path: &Path) -> Result<Passphrase> {
    let s = std::fs::read_to_string(path)
        .with_context(|| format!("reading passphrase file {}", path.display()))?;
    let line = s.lines().next().unwrap_or("").to_string();
    drop(Zeroizing::new(s));
    if line.is_empty() {
        bail!("passphrase file is empty");
    }
    Ok(Zeroizing::new(line))
}

/// Obtain the (existing) store passphrase.
pub fn passphrase(cli: &Cli, prompt: &str) -> Result<Passphrase> {
    if let Some(p) = &cli.passphrase_file {
        return read_first_line(p);
    }
    let p = Zeroizing::new(rpassword::prompt_password(prompt).context("reading passphrase")?);
    if p.is_empty() {
        bail!("empty passphrase");
    }
    Ok(p)
}

/// Obtain a new passphrase, confirmed when prompting.
pub fn new_passphrase(file: Option<&PathBuf>, what: &str) -> Result<Passphrase> {
    if let Some(p) = file {
        return read_first_line(p);
    }
    let a = Zeroizing::new(
        rpassword::prompt_password(format!("{what}: ")).context("reading passphrase")?,
    );
    if a.is_empty() {
        bail!("empty passphrase");
    }
    let b = Zeroizing::new(
        rpassword::prompt_password(format!("{what} (again): ")).context("reading passphrase")?,
    );
    if *a != *b {
        bail!("passphrases do not match");
    }
    Ok(a)
}

/// Read a secret value from stdin (no-echo prompt on a terminal).
pub fn read_value_stdin() -> Result<Zeroizing<Vec<u8>>> {
    if std::io::stdin().is_terminal() {
        let v = Zeroizing::new(rpassword::prompt_password("Secret value: ")?);
        return Ok(Zeroizing::new(v.as_bytes().to_vec()));
    }
    let mut buf = Zeroizing::new(Vec::new());
    std::io::stdin().lock().read_to_end(&mut buf)?;
    if buf.ends_with(b"\n") {
        buf.pop();
        if buf.ends_with(b"\r") {
            buf.pop();
        }
    }
    Ok(buf)
}
