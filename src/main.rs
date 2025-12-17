mod manager;
mod snicker;
mod cli;
mod wallet_node;
mod config;
mod automation;
mod encryption;
mod fee;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use tracing_subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use std::fs::OpenOptions;
use config::Config;

/// CLI arguments
#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Network to use (regtest, signet, or mainnet). Defaults to config file value.
    #[arg(short, long, value_enum)]
    network: Option<Net>,

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

    fn from_config_network(network: config::Network) -> Self {
        match network {
            config::Network::Regtest => Net::Regtest,
            config::Network::Signet => Net::Signet,
            config::Network::Mainnet => Net::Mainnet,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load configuration
    let config = Config::load()?;
    config.validate()?;

    // Use network from CLI args if provided, otherwise from config
    let network = args.network
        .unwrap_or_else(|| Net::from_config_network(config.network));

    let project_dirs = directories::ProjectDirs
    ::from("org", "code", "ambient").unwrap();
    let log_path = project_dirs.data_local_dir()
    .join(network.as_str()).join( "logs")
    .join("ambient.log");
    std::fs::create_dir_all(log_path.parent().unwrap())?;
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    // Write logs to file only (not stderr)
    // Set our own logs to INFO, but suppress verbose logs from bdk_kyoto
    // Respects RUST_LOG environment variable
    use tracing_subscriber::filter::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"))
        .add_directive("bdk_kyoto=warn".parse().unwrap());

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer()
            .with_writer(log_file)
            .with_ansi(false))  // Disable color codes in log file
        .with(filter)
        .init();

    // Print log and config location to stderr so user knows where to find them
    eprintln!("📝 Logging to: {}", log_path.display());
    if let Ok(config_path) = config::get_config_path() {
        eprintln!("⚙️  Config: {}", config_path.display());
    }

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
    cli::repl(network.as_str(), args.recovery_height, rpc_config).await?;

    Ok(())
}
