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

fn load_config(path: &std::path::Path) -> Result<Config> {
    // Owners accepted: root, the invoking user, and the daemon user named in
    // the file itself (`daemon.user`).
    let uids = [0, nix::unistd::geteuid().as_raw()];
    Config::load(path, &uids, &SystemResolver).map_err(|e| anyhow!("{e}"))
}

fn main() -> Result<()> {
    // Few threads on purpose: the unit sets TasksMax, and the only blocking
    // work is one scrypt unseal at a time plus the odd name lookup.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .max_blocking_threads(8)
        .enable_all()
        .build()
        .context("starting the async runtime")?
        .block_on(run())
}

/// File descriptors the daemon may need at the configured limits: a socket
/// and a pidfd per client connection, the approval connections, plus headroom
/// for listeners, the audit log, the store and outbound notification calls.
fn nofile_needed(cfg: &Config) -> u64 {
    2 * cfg.limits.max_conns_total as u64 + cfg.approval.max_connections as u64 + 64
}

fn warn_if_nofile_low(cfg: &Config) {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `rl` is a valid out-pointer for getrlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 {
        let need = nofile_needed(cfg);
        #[allow(clippy::unnecessary_cast)] // rlim_t is u32 on 32-bit targets
        let cur = rl.rlim_cur as u64;
        if cur < need {
            tracing::warn!(
                "RLIMIT_NOFILE is {} but the configured limits can need {need} descriptors; \
                 raise LimitNOFILE= in the unit or lower limits.max_conns_total / \
                 approval.max_connections",
                rl.rlim_cur
            );
        }
    }
}

async fn run() -> Result<()> {
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
    warn_if_nofile_low(&cfg);
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
                runtime::chown_to_user(
                    &cfg.daemon.socket,
                    &cfg.daemon.user,
                    cfg.daemon.socket_group.as_deref(),
                )?;
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
    let serve_opts = secretd::approval::ServeOpts::from_cfg(&approval_cfg);
    tokio::spawn(secretd::approval::serve_with(
        http_listener,
        secretd::approval::router(core.clone(), approval_cfg, oidc),
        serve_opts,
    ));
    let peer: Arc<dyn secretd::peer::PeerCredProvider> = Arc::new(RealPeerCred);
    tokio::spawn(server::serve_clients(core.clone(), client_l, peer.clone()));
    tokio::spawn(server::serve_admin(core.clone(), admin_l, peer));

    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut summaries = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = hup.recv() => {
                match load_config(&args.config) {
                    Ok(c) => { core.set_config(c); tracing::info!("configuration reloaded"); }
                    Err(e) => tracing::error!("reload failed, keeping old config: {e}"),
                }
                // Log rotation: reopen the audit file on the same signal.
                match core.reopen_audit() {
                    Ok(()) => tracing::info!("audit log reopened"),
                    Err(e) => tracing::error!("audit log reopen failed, keeping old handle: {e}"),
                }
            },
            _ = summaries.tick() => core.flush_audit_summaries(false),
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
    }
    core.flush_audit_summaries(true);
    tracing::info!("shutting down");
    Ok(())
}
