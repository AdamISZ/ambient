//! WalletLoaded main view with tabs

use iced::{Element, Length};
use iced::widget::{column, container, text, button, row, text_input};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::gui::message::Message;
use crate::gui::state::{WalletTab, WalletData};
use crate::manager::Manager;

/// Render the wallet loaded view
pub fn view(manager: &Arc<Mutex<Manager>>, data: &WalletData) -> Element<'static, Message> {
    let wallet_name = manager.try_lock()
        .map(|m| m.wallet_node.name().to_string())
        .unwrap_or_else(|_| "Wallet (locked)".to_string());
    let current_tab = data.current_tab;

    // Tab bar
    let tab_bar = row![
        tab_button("Overview", WalletTab::Overview, current_tab),
        tab_button("Send", WalletTab::Send, current_tab),
        tab_button("Receive", WalletTab::Receive, current_tab),
        tab_button("Transactions", WalletTab::Transactions, current_tab),
        tab_button("SNICKER", WalletTab::Snicker, current_tab),
    ]
    .spacing(10)
    .padding(10);

    // Tab content
    let tab_content = match current_tab {
        WalletTab::Overview => view_overview(&wallet_name, data),
        WalletTab::Send => view_send(data),
        WalletTab::Receive => view_receive(data),
        WalletTab::Transactions => view_transactions(),
        WalletTab::Snicker => view_snicker(data),
    };

    column![
        // Header with wallet name and menu
        container(
            row![
                row![
                    text("Ambient Wallet").size(24),
                    text(format!("• {}", wallet_name)).size(20),
                ].spacing(10),

                // Spacer
                container(text(""))
                    .width(Length::Fill),

                // Menu buttons
                row![
                    button("Close Wallet")
                        .on_press(Message::MenuCloseWallet)
                        .padding(8),
                    button("Settings")
                        .on_press(Message::MenuSettings)
                        .padding(8),
                    button("Exit")
                        .on_press(Message::MenuExit)
                        .padding(8),
                ]
                .spacing(10),
            ]
        )
        .padding(15),

        tab_bar,

        container(tab_content)
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(20),
    ]
    .into()
}

/// Create a tab button
fn tab_button(label: &str, tab: WalletTab, current: WalletTab) -> Element<'static, Message> {
    let label = label.to_string();
    let is_active = tab == current;

    let btn = button(text(label).size(16))
        .on_press(Message::TabChanged(tab))
        .padding(10);

    // TODO: Add styling to highlight active tab
    btn.into()
}

/// Overview tab - balance and status
fn view_overview(wallet_name: &str, data: &WalletData) -> Element<'static, Message> {
    let wallet_name = wallet_name.to_string();
    let balance = data.balance;
    let sync_status = if data.is_syncing {
        "Syncing..."
    } else {
        "Synced"
    };
    let utxos = data.utxos.clone();

    column![
        text("Wallet Overview").size(32),

        container(
            column![
                row![
                    text("Wallet:").size(18),
                    text(wallet_name).size(18),
                ].spacing(10),

                row![
                    text("Balance:").size(24),
                    text(format!("{}", balance)).size(24),
                ].spacing(10),

                row![
                    text("Status:").size(16),
                    text(sync_status).size(16),
                ].spacing(10),
            ].spacing(20)
        )
        .padding(20),

        row![
            button("Sync Wallet")
                .on_press(Message::SyncRequested)
                .padding(15),
            button("New Address")
                .on_press(Message::NewAddressRequested)
                .padding(15),
        ]
        .spacing(15),

        {
            if let Some(ref addr) = data.last_address {
                let addr_copy = addr.clone();
                container(
                    column![
                        text("Last Generated Address:").size(16),
                        row![
                            text(addr.clone()).size(14),
                            button("📋 Copy")
                                .on_press(Message::CopyToClipboard(addr_copy))
                                .padding(5),
                        ].spacing(10),
                    ].spacing(5)
                )
                .padding(15)
            } else {
                container(text(""))
                    .padding(15)
            }
        },

        // UTXOs section
        {
            if utxos.is_empty() {
                container(
                    text("No unspent outputs").size(14)
                )
                .padding(15)
            } else {
                let mut utxo_list = column![
                    text(format!("Unspent Outputs ({})", utxos.len())).size(18),
                ].spacing(5);

                for utxo in utxos {
                    utxo_list = utxo_list.push(
                        text(utxo).size(12)
                    );
                }

                container(utxo_list)
                    .padding(15)
            }
        },
    ]
    .spacing(30)
    .into()
}

/// Send tab - create transactions
fn view_send(data: &WalletData) -> Element<'static, Message> {
    let send_address = data.send_address.clone();
    let send_amount = data.send_amount.clone();
    let send_fee_rate = data.send_fee_rate.clone();

    column![
        text("Send Bitcoin").size(32),

        column![
            text("Recipient Address").size(16),
            text_input("bc1q...", &send_address)
                .on_input(Message::SendAddressChanged)
                .width(Length::Fixed(600.0)),
        ].spacing(5),

        column![
            text("Amount (BTC)").size(16),
            text_input("0.001", &send_amount)
                .on_input(Message::SendAmountChanged)
                .width(Length::Fixed(300.0)),
        ].spacing(5),

        column![
            text("Fee Rate (sat/vB)").size(16),
            text_input("1.0", &send_fee_rate)
                .on_input(Message::SendFeeRateChanged)
                .width(Length::Fixed(200.0)),
        ].spacing(5),

        button("Send Transaction")
            .on_press(Message::SendRequested)
            .padding(15),
    ]
    .spacing(20)
    .into()
}

/// Receive tab - show addresses
fn view_receive(data: &WalletData) -> Element<'static, Message> {
    column![
        text("Receive Bitcoin").size(32),

        text("Generate a new address to receive Bitcoin").size(16),

        button("Generate New Address")
            .on_press(Message::NewAddressRequested)
            .padding(15),

        {
            if let Some(ref addr) = data.last_address {
                let addr_copy = addr.clone();
                container(
                    column![
                        text("Your Receive Address:").size(18),
                        container(
                            row![
                                text(addr.clone()).size(16),
                                button("📋 Copy Address")
                                    .on_press(Message::CopyToClipboard(addr_copy))
                                    .padding(10),
                            ].spacing(15)
                        )
                        .padding(15),
                        text("Share this address to receive Bitcoin").size(14),
                    ].spacing(10)
                )
                .padding(20)
            } else {
                container(
                    text("No address generated yet").size(16)
                )
                .padding(20)
            }
        },
    ]
    .spacing(30)
    .into()
}

/// Transactions tab - transaction history
fn view_transactions() -> Element<'static, Message> {
    column![
        text("Transaction History").size(32),
        text("Transaction list coming soon...").size(16),
        button("Refresh")
            .on_press(Message::TransactionsRequested)
            .padding(10),
    ]
    .spacing(20)
    .into()
}

/// SNICKER tab - privacy features
fn view_snicker(data: &WalletData) -> Element<'static, Message> {
    column![
        text("SNICKER Privacy").size(32),

        container(
            column![
                text("SNICKER allows you to participate in collaborative transactions").size(16),
                text("This improves your privacy by breaking on-chain links").size(14),
            ].spacing(10)
        )
        .padding(15),

        row![
            text("Candidates:").size(16),
            text(format!("{}", data.snicker_candidates)).size(16),
        ].spacing(10),

        row![
            text("Opportunities:").size(16),
            text(format!("{}", data.snicker_opportunities)).size(16),
        ].spacing(10),

        row![
            button("Scan for Candidates")
                .on_press(Message::SnickerScanRequested)
                .padding(15),
            button("Find Opportunities")
                .on_press(Message::SnickerFindOpportunities)
                .padding(15),
        ]
        .spacing(15),
    ]
    .spacing(20)
    .into()
}
