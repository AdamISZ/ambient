//! Theme and styling for the application

use iced::Color;

/// Application color palette
pub struct AppTheme {
    pub primary: Color,
    pub secondary: Color,
    pub success: Color,
    pub warning: Color,
    pub danger: Color,
    pub background: Color,
    pub surface: Color,
    pub text: Color,
    pub text_muted: Color,
}

impl Default for AppTheme {
    fn default() -> Self {
        Self {
            // Bitcoin orange as primary
            primary: Color::from_rgb(0.95, 0.58, 0.20),
            secondary: Color::from_rgb(0.30, 0.47, 0.80),
            success: Color::from_rgb(0.20, 0.73, 0.45),
            warning: Color::from_rgb(0.95, 0.77, 0.20),
            danger: Color::from_rgb(0.86, 0.20, 0.27),
            background: Color::from_rgb(0.11, 0.11, 0.13),
            surface: Color::from_rgb(0.15, 0.15, 0.18),
            text: Color::from_rgb(0.95, 0.95, 0.97),
            text_muted: Color::from_rgb(0.60, 0.60, 0.65),
        }
    }
}

/// Spacing constants
pub mod spacing {
    pub const SMALL: u16 = 8;
    pub const MEDIUM: u16 = 16;
    pub const LARGE: u16 = 24;
    pub const XLARGE: u16 = 32;
}

/// Font sizes
pub mod font_size {
    pub const SMALL: u16 = 12;
    pub const NORMAL: u16 = 14;
    pub const MEDIUM: u16 = 16;
    pub const LARGE: u16 = 20;
    pub const XLARGE: u16 = 24;
    pub const TITLE: u16 = 32;
}
