// GUI binary entry point for Ambient Wallet

#[cfg(feature = "gui")]
use ambient::gui;

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!("Error: GUI feature not enabled");
    eprintln!("Build with: cargo build --features gui");
    std::process::exit(1);
}

#[cfg(feature = "gui")]
#[tokio::main]
async fn main() -> iced::Result {
    use ambient::config::Config;
    use std::fs::OpenOptions;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::filter::EnvFilter;

    // Load configuration to get network
    let config = Config::load().expect("Failed to load config");
    let network = config.network.as_str();

    // Set up log file path
    let project_dirs = directories::ProjectDirs::from("org", "code", "ambient")
        .expect("Failed to get project directories");
    let log_path = project_dirs.data_local_dir()
        .join(network)
        .join("logs")
        .join("ambient.log");

    std::fs::create_dir_all(log_path.parent().unwrap())
        .expect("Failed to create log directory");

    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .expect("Failed to open log file");

    // Initialize the status layer for GUI status bar updates
    let status_layer = gui::init_status_layer();

    // Initialize tracing with file output and status layer
    // Respects RUST_LOG environment variable, defaults to INFO level
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"))
        .add_directive("bdk_kyoto=warn".parse().unwrap());

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer()
            .with_writer(log_file)
            .with_ansi(false))
        .with(status_layer)
        .with(filter)
        .init();

    // Print log location to stderr
    eprintln!("📝 Logging to: {}", log_path.display());
    if let Ok(config_path) = ambient::config::get_config_path() {
        eprintln!("⚙️  Config: {}", config_path.display());
    }

    // Run the GUI application
    gui::run()
}
