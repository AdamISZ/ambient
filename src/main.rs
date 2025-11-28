mod manager;
mod snicker;
mod cli;
mod wallet_node;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use tracing_subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use std::fs::OpenOptions;

/// CLI arguments
#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Network to use (regtest, signet, or mainnet)
    #[arg(short, long, value_enum)]
    network: Net,

    /// Recovery start height
    #[arg(long, default_value_t = 200_000)]
    recovery_height: u32,

    /// Bitcoin Core RPC URL (required for proposer mode)
    #[arg(long)]
    rpc_url: Option<String>,

    /// Bitcoin Core RPC username
    #[arg(long)]
    rpc_user: Option<String>,

    /// Bitcoin Core RPC password
    #[arg(long)]
    rpc_password: Option<String>,
}

#[derive(ValueEnum, Clone)]
enum Net {
    Regtest,
    Signet,
    Mainnet,
}

impl Net {
    fn as_str(&self) -> &'static str {
        match self {
            Net::Regtest => "regtest",
            Net::Signet  => "signet",
            Net::Mainnet => "mainnet",
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let project_dirs = directories::ProjectDirs
    ::from("org", "code", "ambient").unwrap();
    let log_path = project_dirs.data_local_dir()
    .join(args.network.as_str()).join( "logs")
    .join("ambient.log");
    std::fs::create_dir_all(log_path.parent().unwrap())?;
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    // Write logs to file only (not stderr)
    // Include bdk_wallet logs to see debug output from patched BDK
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(log_file))
        .with(tracing_subscriber::filter::LevelFilter::INFO)
        .init();

    // Print log location to stderr so user knows where to find it
    eprintln!("📝 Logging to: {}", log_path.display());

    // Prepare RPC configuration (if provided)
    let rpc_config = match (args.rpc_url, args.rpc_user, args.rpc_password) {
        (Some(url), Some(user), Some(password)) => Some((url, user, password)),
        (None, None, None) => None,
        _ => {
            eprintln!("⚠️  Warning: RPC configuration incomplete. All of --rpc-url, --rpc-user, and --rpc-password must be provided together.");
            eprintln!("           Proceeding in receiver-only mode (proposer scanning disabled).");
            None
        }
    };

    // delegate all user interactions to the CLI layer
    cli::repl(args.network.as_str(), args.recovery_height, rpc_config).await?;

    Ok(())
}
