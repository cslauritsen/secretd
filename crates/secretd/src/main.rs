use anyhow::{anyhow, Context, Result};
use clap::Parser;
use secret_proto::config::{Config, SystemResolver};
use secretd::audit::Audit;
use secretd::core::Core;
use secretd::notify_http::HttpNotifier;
use secretd::oidc::OidcClient;
use secretd::peer::RealPeerCred;
use secretd::procinfo::RealProcReader;
use secretd::{runtime, server};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "secretd", version, about = "Local secrets-release daemon")]
struct Args {
    /// Configuration file.
    #[arg(long, short, default_value = "/etc/secretd/config.toml")]
    config: PathBuf,
    /// Validate the configuration and exit.
    #[arg(long)]
    check: bool,
}

fn trusted_uids(cfg_user: &str) -> Vec<u32> {
    let mut v = vec![0, nix::unistd::geteuid().as_raw()];
    if let Ok(Some(u)) = nix::unistd::User::from_name(cfg_user) {
        v.push(u.uid.as_raw());
    }
    v
}

fn load_config(path: &std::path::Path) -> Result<Config> {
    // The daemon user is not known before parsing; accept root, the daemon's
    // default user and ourselves as owners.
    let uids = trusted_uids("secretd");
    Config::load(path, &uids, &SystemResolver).map_err(|e| anyhow!("{e}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    if !secret_proto::mem::disable_core_dumps() {
        tracing::warn!("could not disable core dumps");
    }
    let cfg =
        load_config(&args.config).with_context(|| format!("loading {}", args.config.display()))?;
    for w in &cfg.warnings {
        tracing::warn!("config: {w}");
    }
    if args.check {
        println!("configuration OK");
        return Ok(());
    }

    // Bind (or inherit) sockets while still privileged, then drop root.
    let activated = runtime::systemd_sockets().context("socket activation")?;
    let client_l = match activated.client {
        Some(l) => l,
        None => {
            let l = runtime::bind_unix(&cfg.daemon.socket, cfg.daemon.socket_mode)?;
            if nix::unistd::geteuid().is_root() {
                runtime::chown_to_user(&cfg.daemon.socket, &cfg.daemon.user)?;
            }
            l
        }
    };
    let admin_l = match activated.admin {
        Some(l) => l,
        None => runtime::bind_unix(&cfg.daemon.admin_socket, 0o600)?,
    };
    runtime::drop_privileges(&cfg.daemon.user).context("dropping privileges")?;

    let audit = Audit::open(&cfg.daemon.audit_log)
        .with_context(|| format!("opening audit log {}", cfg.daemon.audit_log.display()))?;
    let notifier = HttpNotifier::new(&cfg.notify).context("setting up notifier")?;
    let client_secret =
        secret_proto::config::read_secret_file(&cfg.approval.oidc.client_secret_file)
            .map_err(|e| anyhow!("{e}"))?;
    let oidc = Arc::new(OidcClient::new(cfg.approval.oidc.clone(), client_secret)?);
    let approval_cfg = cfg.approval.clone();
    let core = Core::new(cfg, audit, Arc::new(notifier), Arc::new(RealProcReader));
    let http_listener = tokio::net::TcpListener::bind(approval_cfg.listen)
        .await
        .with_context(|| format!("binding approval endpoint {}", approval_cfg.listen))?;
    tracing::info!(
        "approval endpoint on {} (plain HTTP; terminate TLS in a reverse proxy)",
        approval_cfg.listen
    );
    tokio::spawn(secretd::approval::serve(
        http_listener,
        secretd::approval::router(core.clone(), approval_cfg, oidc),
    ));
    let peer: Arc<dyn secretd::peer::PeerCredProvider> = Arc::new(RealPeerCred);
    tokio::spawn(server::serve_clients(core.clone(), client_l, peer.clone()));
    tokio::spawn(server::serve_admin(core.clone(), admin_l, peer));

    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    loop {
        tokio::select! {
            _ = hup.recv() => match load_config(&args.config) {
                Ok(c) => { core.set_config(c); tracing::info!("configuration reloaded"); }
                Err(e) => tracing::error!("reload failed, keeping old config: {e}"),
            },
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
    }
    tracing::info!("shutting down");
    Ok(())
}
