//! Graphical user interface for Ambient Wallet
//!
//! Built with Iced framework for a native-feeling Linux desktop application.

pub mod app;
pub mod message;
pub mod modal;
pub mod state;
pub mod status_layer;
pub mod theme;
pub mod views;
pub mod widgets;

pub use app::AmbientApp;
pub use status_layer::{init_status_layer, take_status_receiver};

/// Run the GUI application
pub fn run() -> iced::Result {
    iced::application(
        AmbientApp::title,
        AmbientApp::update,
        AmbientApp::view,
    )
    .theme(AmbientApp::theme)
    .subscription(AmbientApp::subscription)
    .run()
}
