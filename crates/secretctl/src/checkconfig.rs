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
    if let Some(h) = &cfg.homeassistant {
        secret_files.push(("homeassistant.token_file", &h.token_file));
        if let Some(ca) = &h.ca_file {
            if !ca.is_file() {
                errors.push(format!(
                    "homeassistant.ca_file {} is not a file",
                    ca.display()
                ));
            }
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

    check_fifos(&cfg, &mut warnings, &mut errors);

    // OIDC / approval summary.
    if let Some(a) = &cfg.approval {
        if a.oidc.issuer != "https://accounts.google.com" {
            warnings.push(format!(
                "approval.oidc.issuer is {:?}, not Google",
                a.oidc.issuer
            ));
        }
    }
    if let Some(h) = &cfg.homeassistant {
        // Documented limit of the channel: the passphrase is typed into an
        // `input_text` helper, whose maximum length is 255.
        println!(
            "NOTE: homeassistant: {} must be an input_text helper (mode: password, max: 255) \
             excluded from recorder/history/logbook; store passphrases longer than 255 \
             characters cannot be entered through Home Assistant",
            h.passphrase_entity
        );
        println!(
            "NOTE: homeassistant: the passphrase transits Home Assistant (entity state, event bus, \
             WebSocket); anyone with HA admin access can read it while it is set. See the README"
        );
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
        if !cfg.fifos.is_empty() {
            println!("OK: {} named pipe(s)", cfg.fifos.len());
        }
        if let Some(h) = &cfg.homeassistant {
            println!(
                "OK: Home Assistant at {} (notify {}, entity {}, {} owner user id(s))",
                h.url,
                h.notify_service,
                h.passphrase_entity,
                h.owner_user_ids.len()
            );
        }
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

/// Static checks of `[[fifo]]` entries against the file system and the daemon
/// user, mirroring what `secretd` verifies when it creates the pipes (spec 20.1).
fn check_fifos(cfg: &Config, warnings: &mut Vec<String>, errors: &mut Vec<String>) {
    if cfg.fifos.is_empty() {
        return;
    }
    let user = nix::unistd::User::from_name(&cfg.daemon.user)
        .ok()
        .flatten();
    if user.is_none() {
        warnings.push(format!(
            "daemon.user {:?} does not exist here: pipe ownership checks skipped",
            cfg.daemon.user
        ));
    }
    for f in &cfg.fifos {
        let label = format!("fifo {}", f.path.display());
        // Directory.
        if let Some(parent) = f.path.parent() {
            match std::fs::symlink_metadata(parent) {
                Err(_) => warnings.push(format!(
                    "{label}: directory {} does not exist (secretd creates it with mode 0755; \
                     better: systemd-tmpfiles, see packaging/tmpfiles.d)",
                    parent.display()
                )),
                Ok(md) => {
                    if md.file_type().is_symlink() || !md.is_dir() {
                        errors.push(format!(
                            "{label}: {} is not a directory (or is a symlink)",
                            parent.display()
                        ));
                    }
                    if let Some(u) = &user {
                        if !u.uid.is_root() && md.uid() != u.uid.as_raw() {
                            errors.push(format!(
                                "{label}: directory {} is owned by uid {}, not by the daemon user {:?}",
                                parent.display(),
                                md.uid(),
                                cfg.daemon.user
                            ));
                        }
                    }
                    if md.mode() & 0o022 != 0 {
                        errors.push(format!(
                            "{label}: directory {} is writable by group or others (mode {:o})",
                            parent.display(),
                            md.mode() & 0o7777
                        ));
                    }
                }
            }
        }
        // Something already there.
        if let Ok(md) = std::fs::symlink_metadata(&f.path) {
            use std::os::unix::fs::FileTypeExt;
            if md.file_type().is_symlink() || !md.file_type().is_fifo() {
                errors.push(format!(
                    "{label}: the path exists and is not a FIFO (symlink or other file); secretd \
                     refuses to start"
                ));
            }
        }
        // Can the daemon user open it for writing? (It must, to answer a reader.)
        let Some(u) = &user else { continue };
        if u.uid.is_root() {
            continue;
        }
        let uid = u.uid.as_raw();
        let owner = f.owner.unwrap_or(uid);
        if owner != uid {
            errors.push(format!(
                "{label}: owner uid {owner} is not the daemon user: an unprivileged daemon cannot \
                 chown to another user; use the daemon user as owner (readers get access through \
                 the group) or create the pipe with systemd-tmpfiles"
            ));
        }
        let name = std::ffi::CString::new(cfg.daemon.user.clone()).ok();
        let in_group = f.gid == u.gid.as_raw()
            || name
                .and_then(|n| nix::unistd::getgrouplist(&n, u.gid).ok())
                .is_some_and(|g| g.iter().any(|x| x.as_raw() == f.gid));
        let can_write = (owner == uid && f.mode & 0o200 != 0) || (in_group && f.mode & 0o020 != 0);
        if !can_write {
            errors.push(format!(
                "{label}: owner {owner}, group {}, mode {:04o}: the daemon user cannot open it for \
                 writing (needs the owner write bit as owner, or the group write bit as a member \
                 of the group), so it could never answer a reader",
                f.gid, f.mode
            ));
        }
        if !in_group {
            errors.push(format!(
                "{label}: the daemon user is not a member of group {}: an unprivileged daemon can \
                 only set the group of a pipe to a group it belongs to",
                f.gid
            ));
        }
    }
}
