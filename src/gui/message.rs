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
    WalletFolderPicked(Option<std::path::PathBuf>),
    WalletSelected(String),
    CreateWalletRequested,
    WalletNameChanged(String),
    WalletPasswordChanged(String),
    WalletPasswordConfirmChanged(String),
    OpenWalletPasswordChanged(String),
    GenerateWalletRequested,
    WalletGenerated(Result<(String, String, ManagerWrapper), String>), // (wallet_name, mnemonic, manager) or error
    WalletGenerationConfirmed,
    LoadWalletRequested(String, String), // (wallet name, password)
    WalletCreated(String), // wallet name
    WalletLoadComplete(Result<(String, ManagerWrapper), String>), // (wallet_name, manager) or error

    // Wizard navigation
    WizardNextStep,
    WizardPreviousStep,
    WizardStepChanged(crate::gui::modal::GenerateWalletStep),
    FocusPasswordConfirmField,

    // Keyboard events for tab navigation
    TabPressed,
    ShiftTabPressed,

    // Wallet tab navigation
    TabChanged(crate::gui::state::WalletTab),

    // Clipboard operations
    CopyToClipboard(String),

    // Balance and sync
    SyncRequested,
    SyncCompleted,
    /// Event-driven blockchain update from Kyoto (new block, transaction, etc.)
    BlockchainUpdate(crate::wallet_node::WalletUpdate),
    BalanceUpdated(Amount),
    WalletDataUpdated {
        balance: Option<Amount>,
        pending_outgoing: u64,
        pending_incoming: u64,
        utxos: Vec<String>,
    },

    // Send transaction
    SendAddressChanged(String),
    SendAmountChanged(String),
    SendFeeRateChanged(String),
    SendAllRequested,
    SendAllAmountCalculated(String), // Internal: updates amount without clearing send_all_mode
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
    SnickerScanMinUtxoInputChanged(String),
    SnickerScanMaxUtxoInputChanged(String),
    SnickerScanBlockAgeInputChanged(String),
    SnickerClearCandidates,
    SnickerCandidatesCleared(Result<usize, String>),
    SnickerFindOpportunities,
    SnickerOpportunitiesFound(usize, Vec<(usize, String)>, Vec<crate::snicker::ProposalOpportunity>), // (count, list, data)
    SnickerCreateProposal(usize, u64), // (opportunity_index, delta_sats)
    SnickerProposalCreated(Result<String, String>), // proposal hex or error
    SnickerScanIncomingProposals(i64, i64), // (min_delta, max_delta)
    SnickerProposalsScanned(Vec<crate::manager::ProposalScanResult>), // scanned proposals from directory
    SnickerProposalDeltaInputChanged(String), // delta input for creating proposals
    SnickerScanMinDeltaInputChanged(String), // min delta input for scanning
    SnickerScanMaxDeltaInputChanged(String), // max delta input for scanning
    SnickerProposalSelected(usize), // user selected proposal from list
    SnickerShowAcceptDialog(usize), // show confirmation dialog for proposal
    SnickerConfirmAccept(usize), // user confirmed accepting proposal
    SnickerCancelAccept, // user cancelled accepting proposal
    SnickerProposalAccepted(Result<String, String>), // txid or error

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
    BrowseWalletDirectory,
    SettingsRecoveryHeightChanged(String),
    SettingsProposalsDirChanged(String),
    BrowseProposalsDirectory,
    SettingsProposalNetworkBackendChanged(String), // "FileBased" or "Nostr"
    SettingsNostrRelaysChanged(String), // Comma-separated relay URLs
    SettingsNostrPowDifficultyChanged(String), // PoW difficulty (optional)
    SettingsMaxPerCoinjoinChanged(String), // Spending limit: per coinjoin
    SettingsMaxPerDayChanged(String),      // Spending limit: per day
    SettingsMaxPerWeekChanged(String),     // Spending limit: per week
    SettingsScanWindowChanged(String),     // Partial UTXO set scan window
    SettingsSave,
    SettingsSaved(Result<(), String>),
    SettingsClose,                         // Close settings view (cancel)
    SettingsToggleAdvanced,                // Toggle advanced section visibility

    // Automation
    AutomationToggleEnabled,  // Toggle enable/disable
    AutomationStart,
    AutomationStop,
    AutomationStarted(Result<(), String>),
    AutomationStopped,
    AutomationRoleUpdated(String),  // Role changed (Proposer/Receiver)
    AutomationModeChanged(String),  // Legacy, kept for compatibility
    AutomationMaxSatsPerCoinjoinChanged(String),
    AutomationMaxSatsPerDayChanged(String),
    AutomationMaxSatsPerWeekChanged(String),
    AutomationIntervalChanged(String),
    AutomationStatusUpdate,

    // Status bar updates (from tracing INFO messages)
    StatusUpdate(String),

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
