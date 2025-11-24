//! Application state management

use crate::manager::Manager;
use crate::gui::message::View;
use bdk_wallet::bitcoin::Amount;

/// Root application state
pub enum AppState {
    /// Selecting or creating a wallet
    WalletSelection {
        available_wallets: Vec<String>,
    },

    /// Creating a new wallet
    CreatingWallet {
        wallet_name: String,
        mnemonic: Option<String>,
    },

    /// Main wallet view with loaded wallet
    WalletLoaded {
        manager: Manager,
        current_view: View,
        wallet_data: WalletData,
    },

    /// Error state
    Error {
        message: String,
    },
}

/// Data associated with a loaded wallet
pub struct WalletData {
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
        AppState::WalletSelection {
            available_wallets: Vec::new(), // TODO: Load from disk
        }
    }
}
