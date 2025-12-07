//! Messages (events) that drive the application state machine

use bdk_wallet::bitcoin::{Address, Amount, Txid};
use std::sync::Arc;

/// Wrapper for Manager that allows it to be used in messages
/// We use Arc so it can be Clone and Send but we never actually clone the inner Manager
#[derive(Clone)]
pub struct ManagerWrapper(pub Arc<Option<crate::manager::Manager>>);

impl std::fmt::Debug for ManagerWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ManagerWrapper(...)")
    }
}

/// All possible messages/events in the application
#[derive(Debug, Clone)]
pub enum Message {
    // Modal control
    OpenModal(crate::gui::modal::Modal),
    CloseModal,

    // Wallet management
    WalletSelected(String),
    CreateWalletRequested,
    WalletNameChanged(String),
    GenerateWalletRequested,
    WalletGenerated(Result<(String, String), String>), // (wallet_name, mnemonic) or error
    WalletGenerationConfirmed,
    LoadWalletRequested(String), // wallet name to load
    WalletCreated(String), // wallet name
    WalletLoadComplete(Result<(String, ManagerWrapper), String>), // (wallet_name, manager) or error

    // Wizard navigation
    WizardNextStep,
    WizardPreviousStep,
    WizardStepChanged(crate::gui::modal::GenerateWalletStep),

    // Wallet tab navigation
    TabChanged(crate::gui::state::WalletTab),

    // Clipboard operations
    CopyToClipboard(String),

    // Balance and sync
    SyncRequested,
    SyncCompleted,
    BalanceUpdated(Amount),
    WalletDataUpdated {
        balance: Option<Amount>,
        utxos: Vec<String>,
    },

    // Send transaction
    SendAddressChanged(String),
    SendAmountChanged(String),
    SendFeeRateChanged(String),
    SendRequested,
    TransactionSent(Result<Txid, String>),

    // Receive
    NewAddressRequested,
    AddressGenerated(Address),

    // Transaction history
    TransactionsRequested,
    TransactionsLoaded(Vec<String>), // Placeholder for now

    // SNICKER
    SnickerScanRequested,
    SnickerScanCompleted(Result<usize, String>),
    SnickerFindOpportunities,
    SnickerOpportunitiesFound(usize),

    // Navigation
    ViewChanged(View),

    // Menu actions
    MenuOpenWallet,
    MenuCloseWallet,
    MenuSettings,
    MenuExit,

    // Settings
    SettingsNetworkChanged(String),
    SettingsPeerChanged(String),
    SettingsWalletDirChanged(String),
    SettingsRecoveryHeightChanged(String),
    SettingsSave,
    SettingsSaved(Result<(), String>),

    // Placeholder for unimplemented actions
    Placeholder,
}

/// Different views/screens in the application
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    WalletList,
    CreateWallet,
    Dashboard,
    Send,
    Receive,
    Transactions,
    Snicker,
    Settings,
}
