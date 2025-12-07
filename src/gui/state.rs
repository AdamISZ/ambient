//! Application state management

use crate::manager::Manager;
use bdk_wallet::bitcoin::Amount;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Root application state - simplified to persistent states only
/// Transient operations (like wallet creation) are handled by modals
pub enum AppState {
    /// No wallet loaded - showing landing page
    NoWallet {
        available_wallets: Vec<String>,
    },

    /// Wallet loaded and active
    WalletLoaded {
        manager: Arc<Mutex<Manager>>,
        wallet_data: WalletData,
    },

    /// Error state
    Error {
        message: String,
    },
}

/// Tab selection within the wallet view
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletTab {
    Overview,
    Send,
    Receive,
    Transactions,
    Snicker,
}

/// Data associated with a loaded wallet
pub struct WalletData {
    pub current_tab: WalletTab,
    pub balance: Amount,
    pub last_address: Option<String>,
    pub is_syncing: bool,

    // Send form state
    pub send_address: String,
    pub send_amount: String,
    pub send_fee_rate: String,

    // SNICKER state
    pub snicker_candidates: usize,
    pub snicker_opportunities: usize,
}

impl Default for WalletData {
    fn default() -> Self {
        Self {
            current_tab: WalletTab::Overview,
            balance: Amount::ZERO,
            last_address: None,
            is_syncing: false,
            send_address: String::new(),
            send_amount: String::new(),
            send_fee_rate: String::from("1.0"),
            snicker_candidates: 0,
            snicker_opportunities: 0,
        }
    }
}

impl AppState {
    /// Create initial state
    pub fn new() -> Self {
        AppState::NoWallet {
            available_wallets: Vec::new(), // TODO: Load from disk
        }
    }
}
