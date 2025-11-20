mod ui;
mod wallet_node;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use tracing_subscriber;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
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
    ::from("org", "code", "rustsnicker").unwrap();
    let log_path = project_dirs.data_local_dir()
    .join(args.network.as_str()).join( "logs")
    .join("rustsnicker.log");
    std::fs::create_dir_all(log_path.parent().unwrap())?;
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    let subscriber = tracing_subscriber::FmtSubscriber::builder()
    .with_writer(BoxMakeWriter::new(log_file))
    .with_ansi(false)
    .finish();
    //let subscriber =
    //tracing_subscriber::FmtSubscriber::builder()
    //.with_writer(std::io::stderr).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    
    // delegate all user interactions to the UI layer
    ui::repl(args.network.as_str(), args.recovery_height).await?;
    //ui::run_cli(&mut wallet_node).await?;

    Ok(())
}
