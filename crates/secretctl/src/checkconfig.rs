use crate::util::*;
use crate::Cli;
use anyhow::{bail, Result};
use secret_proto::config::Config;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub fn run(cli: &Cli) -> Result<()> {
    let cfg: Config = match load_config(cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: {e:#}");
            bail!("configuration is invalid");
        }
    };
    let mut warnings = cfg.warnings.clone();
    let mut errors: Vec<String> = Vec::new();

    // Files referenced by the configuration.
    let mut secret_files = vec![(
        "approval.oidc.client_secret_file",
        &cfg.approval.oidc.client_secret_file,
    )];
    if let Some(p) = &cfg.notify.auth_token_file {
        secret_files.push(("notify.auth_token_file", p));
    }
    if let Some(p) = &cfg.notify.hmac_secret_file {
        secret_files.push(("notify.hmac_secret_file", p));
    }
    for (label, p) in secret_files {
        match std::fs::metadata(p) {
            Ok(md) => {
                if md.mode() & 0o077 != 0 {
                    warnings.push(format!(
                        "{label} {} is accessible by group/others (mode {:o}); use 0600/0640",
                        p.display(),
                        md.mode() & 0o7777
                    ));
                }
                if md.len() == 0 {
                    errors.push(format!("{label} {} is empty", p.display()));
                }
            }
            Err(e) => errors.push(format!("{label} {}: {e}", p.display())),
        }
    }

    // Store.
    match std::fs::metadata(&cfg.daemon.store) {
        Ok(md) => {
            if md.mode() & 0o077 != 0 {
                warnings.push(format!(
                    "store {} is accessible by group/others (mode {:o}); expected 0600",
                    cfg.daemon.store.display(),
                    md.mode() & 0o7777
                ));
            }
        }
        Err(_) => warnings.push(format!(
            "store {} does not exist (run `secretctl init`)",
            cfg.daemon.store.display()
        )),
    }

    // Parent directories of sockets and log.
    for (label, p) in [
        ("daemon.socket", &cfg.daemon.socket),
        ("daemon.admin_socket", &cfg.daemon.admin_socket),
        ("daemon.audit_log", &cfg.daemon.audit_log),
    ] {
        if let Some(parent) = p.parent() {
            if !Path::new(parent).is_dir() {
                warnings.push(format!(
                    "{label}: directory {} does not exist (created by systemd units/tmpfiles)",
                    parent.display()
                ));
            }
        }
    }

    // OIDC / approval summary.
    if cfg.approval.oidc.issuer != "https://accounts.google.com" {
        warnings.push(format!(
            "approval.oidc.issuer is {:?}, not Google",
            cfg.approval.oidc.issuer
        ));
    }
    if cfg.secrets.is_empty() {
        warnings.push("no [[secret]] entries configured".into());
    }

    for w in &warnings {
        println!("WARNING: {w}");
    }
    for e in &errors {
        println!("ERROR: {e}");
    }
    if errors.is_empty() {
        println!(
            "OK: {} secret(s), approval on {} (external {}), {} owner email(s)",
            cfg.secrets.len(),
            cfg.approval.listen,
            cfg.approval.external_url,
            cfg.approval.oidc.owner_emails.len()
        );
        Ok(())
    } else {
        bail!("{} error(s) found", errors.len())
    }
}
