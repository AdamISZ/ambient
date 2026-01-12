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

/// Load the application icon from embedded PNG
fn load_icon() -> Option<iced::window::Icon> {
    // Icon is embedded at compile time
    let icon_bytes = include_bytes!("../../assets/icon.png");

    // Decode PNG to RGBA
    let img = image::load_from_memory(icon_bytes).ok()?;
    let rgba = img.to_rgba8();
    let (width, height) = rgba.dimensions();

    iced::window::icon::from_rgba(rgba.into_raw(), width, height).ok()
}

/// Run the GUI application
pub fn run() -> iced::Result {
    let window_settings = iced::window::Settings {
        icon: load_icon(),
        platform_specific: iced::window::settings::PlatformSpecific {
            application_id: String::from("ambient-gui"),
            ..Default::default()
        },
        ..Default::default()
    };

    iced::application(
        AmbientApp::title,
        AmbientApp::update,
        AmbientApp::view,
    )
    .window(window_settings)
    .theme(AmbientApp::theme)
    .subscription(AmbientApp::subscription)
    .run()
}
