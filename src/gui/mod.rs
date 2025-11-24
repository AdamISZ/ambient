//! Graphical user interface for Ambient Wallet
//!
//! Built with Iced framework for a native-feeling Linux desktop application.

pub mod app;
pub mod state;
pub mod message;
pub mod theme;
pub mod views;
pub mod widgets;

pub use app::AmbientApp;

use iced::{Application, Settings};

/// Run the GUI application
pub fn run() -> iced::Result {
    AmbientApp::run(Settings::default())
}
