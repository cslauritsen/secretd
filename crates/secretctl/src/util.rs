use crate::Cli;
use anyhow::{anyhow, bail, Context, Result};
use secret_proto::config::{Config, SystemResolver};
use secret_proto::store::Passphrase;
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Uids allowed to own the config file: root and ourselves; `Config::load`
/// adds the daemon user named in the file (`daemon.user`).
fn trusted_uids() -> Vec<u32> {
    vec![0, nix_euid()]
}

fn nix_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Load the config (permission-checked).
pub fn load_config(cli: &Cli) -> Result<Config> {
    Config::load(&cli.config, &trusted_uids(), &SystemResolver)
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

/// After `secretctl` wrote the store as root, hand the file to the daemon
/// user: the daemon runs unprivileged and could otherwise not read a
/// root-owned 0600 store. (The supported way is to run `secretctl` as the
/// daemon user, see the README; this keeps a root run from silently breaking
/// the daemon.)
pub fn fix_store_owner(cli: &Cli, path: &Path) {
    if nix_euid() != 0 {
        return;
    }
    let Some(cfg) = try_load_config(cli) else {
        eprintln!(
            "warning: running as root without a readable config: {} is owned by root and the \
             secretd user cannot read it. Run secretctl as the daemon user \
             (`sudo -u secretd secretctl ...`) or chown the file yourself.",
            path.display()
        );
        return;
    };
    let name = &cfg.daemon.user;
    match nix::unistd::User::from_name(name) {
        Ok(Some(u)) if u.uid.is_root() => {}
        Ok(Some(u)) => match nix::unistd::chown(path, Some(u.uid), Some(u.gid)) {
            Ok(()) => eprintln!(
                "note: running as root; store ownership set to {name} so the daemon can read it \
                 (prefer `sudo -u {name} secretctl ...`)"
            ),
            Err(e) => eprintln!(
                "warning: could not give {} to {name}: {e}; the daemon will not be able to read it",
                path.display()
            ),
        },
        _ => eprintln!(
            "warning: running as root and daemon user {name:?} does not exist; {} stays owned by root",
            path.display()
        ),
    }
}
