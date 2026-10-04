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
    let mut secret_files = Vec::new();
    if let Some(a) = &cfg.approval {
        secret_files.push((
            "approval.oidc.client_secret_file",
            &a.oidc.client_secret_file,
        ));
    }
    if let Some(n) = &cfg.notify {
        if let Some(p) = &n.auth_token_file {
            secret_files.push(("notify.auth_token_file", p));
        }
        if let Some(p) = &n.hmac_secret_file {
            secret_files.push(("notify.hmac_secret_file", p));
        }
    }
    let socket_gid = cfg.daemon.socket_group.as_deref().and_then(|g| {
        secret_proto::config::NameResolver::gid(&secret_proto::config::SystemResolver, g)
    });
    for (label, p) in secret_files {
        match std::fs::metadata(p) {
            Ok(md) => {
                if socket_gid == Some(md.gid()) && md.mode() & 0o040 != 0 {
                    warnings.push(format!(
                        "{label} {} is readable by the client socket group (gid {}): every member \
                         allowed to connect could read it; make it owner-only (0400)",
                        p.display(),
                        md.gid()
                    ));
                }
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
    if let Some(a) = &cfg.approval {
        if a.oidc.issuer != "https://accounts.google.com" {
            warnings.push(format!(
                "approval.oidc.issuer is {:?}, not Google",
                a.oidc.issuer
            ));
        }
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
        let channels: Vec<&str> = cfg.channels.enabled.iter().map(|c| c.as_str()).collect();
        println!(
            "OK: {} secret(s), channels: {}",
            cfg.secrets.len(),
            channels.join(", ")
        );
        if let Some(a) = &cfg.approval {
            println!(
                "OK: web approval on {} (external {}), {} owner email(s)",
                a.listen,
                a.external_url,
                a.oidc.owner_emails.len()
            );
        }
        Ok(())
    } else {
        bail!("{} error(s) found", errors.len())
    }
}
