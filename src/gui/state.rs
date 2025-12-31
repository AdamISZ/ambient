//! Application state management

use crate::manager::{Manager, ProposalScanResult};
use crate::snicker::ProposalOpportunity;
use crate::automation::AutomationTask;
use crate::config::AutomationMode;
use bdk_wallet::bitcoin::Amount;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Root application state - simplified to persistent states only
/// Transient operations (like wallet creation) are handled by modals
pub enum AppState {
    /// No wallet loaded - showing landing page
    NoWallet {
        available_wallets: Vec<String>,
    },

    /// Loading a wallet (shows loading indicator)
    LoadingWallet {
        wallet_name: String,
    },

    /// Wallet loaded and active
    WalletLoaded {
        manager: Arc<RwLock<Manager>>,
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
    pub status_message: Option<String>,

    // Send form state
    pub send_address: String,
    pub send_amount: String,
    pub send_fee_rate: String,
    pub send_all_mode: bool, // True when "Send All" was clicked - recalculate on fee rate change

    // SNICKER state
    pub snicker_candidates: usize,
    pub snicker_opportunities: usize,
    pub snicker_opportunities_list: Vec<(usize, String)>, // (index, display_string)
    pub snicker_opportunities_data: Vec<ProposalOpportunity>, // Actual opportunities for creating proposals
    pub snicker_last_proposal: Option<String>, // Last created proposal tag (hex)
    pub snicker_scanned_proposals: Vec<ProposalScanResult>, // Results from directory scan
    pub snicker_selected_proposal: Option<usize>, // Index into scanned_proposals
    pub snicker_proposal_delta_input: String, // Delta input for creating proposals
    pub snicker_scan_min_delta_input: String, // Min delta for scanning incoming
    pub snicker_scan_max_delta_input: String, // Max delta for scanning incoming
    pub snicker_scan_min_utxo_input: String, // Min candidate UTXO size in sats
    pub snicker_scan_max_utxo_input: String, // Max candidate UTXO size in sats
    pub snicker_scan_block_age_input: String, // Max block age for candidates (0 = all)

    // Automation state
    pub automation_running: bool,
    pub automation_mode: AutomationMode,
    pub automation_max_delta: String,    // Input field for max delta
    pub automation_max_per_day: String,  // Input field for max proposals per day
    pub automation_interval_secs: String, // Input field for interval
    pub automation_task: Option<Arc<tokio::sync::Mutex<AutomationTask>>>, // The actual task runner (shared)

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
            status_message: None,
            send_address: String::new(),
            send_amount: String::new(),
            send_fee_rate: String::from("1.0"),
            send_all_mode: false,
            snicker_candidates: 0,
            snicker_opportunities: 0,
            snicker_opportunities_list: Vec::new(),
            snicker_opportunities_data: Vec::new(),
            snicker_last_proposal: None,
            snicker_scanned_proposals: Vec::new(),
            snicker_selected_proposal: None,
            snicker_proposal_delta_input: String::from("0"),
            snicker_scan_min_delta_input: String::from("-1000"),
            snicker_scan_max_delta_input: String::from("5000"),
            snicker_scan_min_utxo_input: String::from("10000"),
            snicker_scan_max_utxo_input: String::from("100000000"),
            snicker_scan_block_age_input: String::from("0"),
            automation_running: false,
            automation_mode: AutomationMode::Disabled,
            automation_max_delta: String::from("10000"),
            automation_max_per_day: String::from("10"),
            automation_interval_secs: String::from("10"),
            automation_task: None,
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
