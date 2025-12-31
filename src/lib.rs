// Library interface for ambient wallet
// Exposes public modules for testing

extern crate hex;

pub mod blockchain_data;
pub mod encryption;
pub mod fee;
pub mod network;
pub mod signer;
pub mod snicker;
pub mod utils;
pub mod wallet_node;
pub mod manager;
pub mod cli;
pub mod config;
pub mod automation;
pub mod partial_utxo_set;

// GUI module - only include if iced feature is enabled
#[cfg(feature = "gui")]
pub mod gui;
