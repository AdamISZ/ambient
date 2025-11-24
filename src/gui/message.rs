//! Messages (events) that drive the application state machine

use bdk_wallet::bitcoin::{Address, Amount, Txid};
use crate::manager::Manager;

/// All possible messages/events in the application
#[derive(Debug, Clone)]
pub enum Message {
    // Wallet management
    WalletSelected(String),
    CreateWalletRequested,
    LoadWalletRequested,
    WalletCreated(String), // wallet name
    WalletLoaded(String),  // wallet name

    // Balance and sync
    SyncRequested,
    SyncCompleted,
    BalanceUpdated(Amount),

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
}
