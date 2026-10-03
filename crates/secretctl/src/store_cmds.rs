use crate::util::*;
use crate::Cli;
use anyhow::{bail, Context, Result};
use secret_proto::store::{self, Entry, StoreError};
use secret_proto::valid_secret_name;
use std::path::Path;
use zeroize::Zeroizing;

pub fn init(cli: &Cli) -> Result<()> {
    let path = store_path(cli)?;
    if path.exists() {
        bail!("{} already exists; refusing to overwrite", path.display());
    }
    let pass = new_passphrase(cli.passphrase_file.as_ref(), "New store passphrase")?;
    store::create(&path, &pass, cli.work_factor).context("creating store")?;
    fix_store_owner(cli, &path);
    eprintln!("created empty store {}", path.display());
    Ok(())
}

pub fn add(cli: &Cli, name: &str, file: Option<&Path>) -> Result<()> {
    if !valid_secret_name(name) {
        bail!("invalid secret name (allowed: [A-Za-z0-9._/-]+, max 256)");
    }
    let path = store_path(cli)?;
    // Read the value first so a typo does not cost a passphrase round trip.
    let value: Zeroizing<Vec<u8>> = match file {
        Some(f) => Zeroizing::new(std::fs::read(f).with_context(|| f.display().to_string())?),
        None => read_value_stdin()?,
    };
    let pass = passphrase(cli, "Store passphrase: ")?;
    let mut secrets = load_store(&path, &pass)?;
    let existed = secrets.get(name).is_some();
    secrets.insert(name, Entry::from_bytes(&value));
    store::save(&path, &pass, &secrets, cli.work_factor).context("writing store")?;
    fix_store_owner(cli, &path);
    eprintln!(
        "{} secret {name:?}",
        if existed { "replaced" } else { "added" }
    );
    if let Some(cfg) = try_load_config(cli) {
        if cfg.secret(name).is_none() {
            eprintln!("warning: {name:?} has no [[secret]] entry in the config and is unreachable");
        }
    }
    Ok(())
}

pub fn remove(cli: &Cli, name: &str) -> Result<()> {
    let path = store_path(cli)?;
    let pass = passphrase(cli, "Store passphrase: ")?;
    let mut secrets = load_store(&path, &pass)?;
    if !secrets.remove(name) {
        bail!("no such secret {name:?} in the store");
    }
    store::save(&path, &pass, &secrets, cli.work_factor).context("writing store")?;
    fix_store_owner(cli, &path);
    eprintln!("removed secret {name:?}");
    Ok(())
}

pub fn list(cli: &Cli, check_store: bool) -> Result<()> {
    let cfg = load_config(cli)?;
    for s in &cfg.secrets {
        let uids: Vec<String> = s.uids.iter().map(|u| u.to_string()).collect();
        let gids: Vec<String> = s.gids.iter().map(|u| u.to_string()).collect();
        let exes = if s.exes.is_empty() {
            "any (allow_any_exe)".to_string()
        } else {
            s.exes.join(",")
        };
        println!(
            "{}\tuids=[{}]\tgids=[{}]\texes=[{}]{}",
            s.name,
            uids.join(","),
            gids.join(","),
            exes,
            s.description
                .as_deref()
                .map(|d| format!("\t# {d}"))
                .unwrap_or_default()
        );
    }
    if check_store {
        let path = store_path(cli)?;
        let pass = passphrase(cli, "Store passphrase: ")?;
        let secrets = load_store(&path, &pass)?;
        let in_store = secrets.names();
        for n in &in_store {
            if cfg.secret(n).is_none() {
                eprintln!("warning: {n:?} is in the store but not in the config (unreachable)");
            }
        }
        for s in &cfg.secrets {
            if !in_store.contains(&s.name) {
                eprintln!(
                    "warning: {:?} is in the config but not in the store",
                    s.name
                );
            }
        }
    }
    Ok(())
}

pub fn rotate(cli: &Cli) -> Result<()> {
    let path = store_path(cli)?;
    let old = passphrase(cli, "Current passphrase: ")?;
    let secrets = load_store(&path, &old)?;
    let new = new_passphrase(cli.new_passphrase_file.as_ref(), "New passphrase")?;
    if *old == *new {
        bail!("new passphrase is identical to the old one");
    }
    store::save(&path, &new, &secrets, cli.work_factor).context("writing store")?;
    fix_store_owner(cli, &path);
    eprintln!(
        "re-encrypted {} secret(s) under the new passphrase",
        secrets.len()
    );
    Ok(())
}

fn load_store(path: &Path, pass: &store::Passphrase) -> Result<store::Secrets> {
    match store::load(path, pass) {
        Ok(s) => Ok(s),
        Err(StoreError::WrongPassphrase) => bail!("wrong passphrase"),
        Err(StoreError::NotFound) => {
            bail!("store {} not found (run `secretctl init`)", path.display())
        }
        Err(e) => Err(e.into()),
    }
}
