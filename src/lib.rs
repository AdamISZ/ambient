// Library interface for ambient wallet
// Exposes public modules for testing

extern crate hex;

pub mod manager;
pub mod snicker;
pub mod wallet_node;
pub mod cli;

// GUI module - only include if iced feature is enabled
#[cfg(feature = "gui")]
pub mod gui;
