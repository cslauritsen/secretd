use anyhow::{anyhow, Context, Result};
use clap::Parser;
use secret_proto::config::{ChannelKind, Config, SystemResolver};
use secretd::audit::Audit;
use secretd::channel::{AdminChannel, Channel, WebChannel};
use secretd::core::Core;
use secretd::homeassistant::HaChannel;
use secretd::notify_http::HttpNotifier;
use secretd::oidc::OidcClient;
use secretd::peer::RealPeerCred;
use secretd::procinfo::{ProcInfoReader, RealProcReader};
use secretd::{platform, runtime, server};
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
    let web = cfg
        .approval
        .as_ref()
        .map_or(0, |a| a.max_connections as u64);
    2 * cfg.limits.max_conns_total as u64 + web + 64
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
                 raise LimitNOFILE= in the unit (SoftResourceLimits/NumberOfFiles in the \
                 launchd plist) or lower limits.max_conns_total / approval.max_connections",
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
    let activated = runtime::activated_sockets().context("socket activation")?;
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
    let want_admin = cfg.channels.has(ChannelKind::Admin);
    let admin_l = match (activated.admin, want_admin) {
        (Some(l), true) => Some(l),
        (Some(_), false) => None, // channel disabled: drop the inherited socket
        (None, true) => Some(runtime::bind_unix(&cfg.daemon.admin_socket, 0o600)?),
        (None, false) => None,
    };
    runtime::drop_privileges(&cfg.daemon.user).context("dropping privileges")?;

    // macOS: identifying callers of other users needs root (spec section 22).
    // Refuse a configuration that pins executables for such callers instead of
    // starting a daemon that would deny all of them. Linux keeps its documented
    // per-request fail-closed behaviour (CAP_SYS_PTRACE is granted by the unit).
    if cfg!(target_os = "macos") {
        let probe = RealProcReader.read(1).map(|_| ());
        let rep = platform::check_process_inspection(&cfg, nix::unistd::geteuid().as_raw(), &probe);
        for w in &rep.warnings {
            tracing::warn!("process inspection: {w}");
        }
        if !rep.errors.is_empty() {
            return Err(anyhow!(
                "cannot identify callers of other users: {}",
                rep.errors.join("; ")
            ));
        }
    }

    let audit = Audit::open(&cfg.daemon.audit_log)
        .with_context(|| format!("opening audit log {}", cfg.daemon.audit_log.display()))?;

    let mut channels: Vec<Arc<dyn Channel>> = Vec::new();
    let mut web_parts = None;
    if let (true, Some(notify_cfg), Some(approval_cfg)) = (
        cfg.channels.has(ChannelKind::Web),
        &cfg.notify,
        &cfg.approval,
    ) {
        let notifier = HttpNotifier::new(notify_cfg).context("setting up notifier")?;
        let client_secret =
            secret_proto::config::read_secret_file(&approval_cfg.oidc.client_secret_file)
                .map_err(|e| anyhow!("{e}"))?;
        let oidc = Arc::new(OidcClient::new(approval_cfg.oidc.clone(), client_secret)?);
        channels.push(Arc::new(WebChannel::new(Arc::new(notifier))));
        web_parts = Some((approval_cfg.clone(), oidc));
    }
    let mut ha_channel = None;
    if let (true, Some(ha_cfg)) = (
        cfg.channels.has(ChannelKind::HomeAssistant),
        &cfg.homeassistant,
    ) {
        let token = secret_proto::config::read_secret_file(&ha_cfg.token_file)
            .map_err(|e| anyhow!("{e}"))?;
        let ha = HaChannel::new(ha_cfg, token).context("setting up the Home Assistant channel")?;
        channels.push(ha.clone());
        ha_channel = Some(ha);
    }
    if want_admin {
        channels.push(Arc::new(AdminChannel));
    }
    let core = Core::with_channels(cfg, audit, channels, Arc::new(RealProcReader));
    if let Some(ha) = ha_channel {
        // Connects (and reconnects with backoff); until it is up, the channel
        // counts as failed for new requests.
        tokio::spawn(ha.run(core.clone()));
    }

    if let Some((approval_cfg, oidc)) = web_parts {
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
    }
    let peer: Arc<dyn secretd::peer::PeerCredProvider> = Arc::new(RealPeerCred);
    tokio::spawn(server::serve_clients(core.clone(), client_l, peer.clone()));
    if let Some(admin_l) = admin_l {
        tokio::spawn(server::serve_admin(core.clone(), admin_l, peer));
    }

    // Named pipes (section 20): created now, as the daemon user.
    let daemon_uid = nix::unistd::geteuid().as_raw();
    let scanner: Arc<dyn secretd::fifo::ReaderScanner> =
        Arc::new(secretd::fifo::ProcScanner::new(Arc::new(RealProcReader)));
    let mut fifo_cfgs = core.config().fifos.clone();
    let mut fifos = if fifo_cfgs.is_empty() {
        None
    } else {
        Some(
            secretd::fifo::start(core.clone(), scanner.clone(), &fifo_cfgs, daemon_uid)
                .context("setting up the named pipes")?,
        )
    };

    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut summaries = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = hup.recv() => {
                match load_config(&args.config) {
                    Ok(c) => {
                        let new_fifos = c.fifos.clone();
                        core.set_config(c);
                        tracing::info!("configuration reloaded");
                        // Pipes are re-armed only if their configuration changed
                        // (every wait is cancelled first).
                        if new_fifos != fifo_cfgs {
                            if let Some(f) = fifos.take() {
                                f.shutdown().await;
                            }
                            fifo_cfgs = new_fifos;
                            if !fifo_cfgs.is_empty() {
                                match secretd::fifo::start(
                                    core.clone(),
                                    scanner.clone(),
                                    &fifo_cfgs,
                                    daemon_uid,
                                ) {
                                    Ok(f) => fifos = Some(f),
                                    Err(e) => tracing::error!(
                                        "named pipes not re-armed after reload: {e}"
                                    ),
                                }
                            }
                        }
                    }
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
    if let Some(f) = fifos.take() {
        f.shutdown().await; // cancels the waits and removes the pipes
    }
    core.flush_audit_summaries(true);
    tracing::info!("shutting down");
    Ok(())
}
