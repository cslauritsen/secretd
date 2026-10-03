//! `secretctl`: admin CLI for secretd.

mod admin;
mod checkconfig;
mod store_cmds;
mod util;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "secretctl", version, about = "Administer secretd")]
pub struct Cli {
    /// Path to the secretd configuration file.
    #[arg(
        long,
        short = 'c',
        global = true,
        default_value = "/etc/secretd/config.toml"
    )]
    pub config: PathBuf,
    /// Store file (overrides `daemon.store` from the config).
    #[arg(long, global = true)]
    pub store: Option<PathBuf>,
    /// Admin socket (overrides `daemon.admin_socket` from the config).
    #[arg(long, global = true)]
    pub admin_socket: Option<PathBuf>,
    /// Read the store passphrase from the first line of this file instead of prompting.
    #[arg(long, global = true)]
    pub passphrase_file: Option<PathBuf>,
    /// For `rotate-passphrase`: read the new passphrase from this file.
    #[arg(long, global = true)]
    pub new_passphrase_file: Option<PathBuf>,
    /// scrypt work factor (log2 N) for newly written stores; default is age's (~1s).
    #[arg(long, global = true)]
    pub work_factor: Option<u8>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create an empty store and set its passphrase.
    Init,
    /// Add or replace a secret (value from stdin or a no-echo prompt).
    Add {
        name: String,
        /// Read the value from this file (binary safe) instead of stdin.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Remove a secret from the store.
    Remove { name: String },
    /// List configured secret names and their ACL summary (never values).
    List {
        /// Also prompt for the passphrase and compare names with the store.
        #[arg(long)]
        check_store: bool,
    },
    /// Re-encrypt every secret under a new passphrase.
    RotatePassphrase,
    /// List pending requests (via the admin socket).
    Pending,
    /// Approve a pending request, entering the store passphrase.
    Approve { request_id: String },
    /// Deny a pending request.
    Deny { request_id: String },
    /// Validate the configuration, ACLs, OIDC settings and file permissions.
    CheckConfig,
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("secretctl: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Command::Init => store_cmds::init(&cli),
        Command::Add { name, file } => store_cmds::add(&cli, name, file.as_deref()),
        Command::Remove { name } => store_cmds::remove(&cli, name),
        Command::List { check_store } => store_cmds::list(&cli, *check_store),
        Command::RotatePassphrase => store_cmds::rotate(&cli),
        Command::Pending => admin::pending(&cli),
        Command::Approve { request_id } => admin::approve(&cli, request_id),
        Command::Deny { request_id } => admin::deny(&cli, request_id),
        Command::CheckConfig => checkconfig::run(&cli),
    }
}
