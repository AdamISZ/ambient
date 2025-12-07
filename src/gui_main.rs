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
    // Initialize tracing with reduced verbosity
    // Set to WARN level to reduce noise from dependencies
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    // Run the GUI application
    gui::run()
}
