//! Application state management

use crate::manager::Manager;
use crate::snicker::ProposalOpportunity;
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
    pub snicker_opportunities_list: Vec<(usize, String)>, // (index, display_string)
    pub snicker_opportunities_data: Vec<ProposalOpportunity>, // Actual opportunities for creating proposals
    pub snicker_last_proposal: Option<String>, // Last created proposal tag (hex)
    pub snicker_proposal_tag_input: String, // Tag input for loading proposal file
    pub snicker_incoming_proposals: Vec<String>, // Incoming proposal tags
    pub snicker_proposal_delta_input: String, // Delta input for creating proposals
    pub snicker_scan_min_delta_input: String, // Min delta for scanning incoming
    pub snicker_scan_max_delta_input: String, // Max delta for scanning incoming
    pub snicker_scan_blocks_input: String, // Number of blocks to scan
    pub snicker_scan_min_utxo_input: String, // Min UTXO size in sats
    pub snicker_scan_max_utxo_input: String, // Max UTXO size in sats
    pub snicker_find_min_utxo_input: String, // Min UTXO size for finding opportunities

    // Display cache (updated periodically from wallet)
    pub utxos: Vec<String>,
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
            snicker_opportunities_list: Vec::new(),
            snicker_opportunities_data: Vec::new(),
            snicker_last_proposal: None,
            snicker_proposal_tag_input: String::new(),
            snicker_incoming_proposals: Vec::new(),
            snicker_proposal_delta_input: String::from("0"),
            snicker_scan_min_delta_input: String::from("-1000"),
            snicker_scan_max_delta_input: String::from("5000"),
            snicker_scan_blocks_input: String::from("100"),
            snicker_scan_min_utxo_input: String::from("10000"),
            snicker_scan_max_utxo_input: String::from("100000000"),
            snicker_find_min_utxo_input: String::from("10000"),
            utxos: Vec::new(),
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
