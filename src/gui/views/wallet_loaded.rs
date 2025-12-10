//! WalletLoaded main view with tabs

use iced::{Element, Length, Border, Color, Theme};
use iced::widget::{column, container, text, button, row, text_input, scrollable, Scrollable};
use iced::widget::scrollable::{Direction, Scrollbar};
use iced::widget::button::Style;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::gui::message::Message;
use crate::gui::state::{WalletTab, WalletData};
use crate::manager::Manager;

/// Render the wallet loaded view
pub fn view(manager: &Arc<Mutex<Manager>>, data: &WalletData) -> Element<'static, Message> {
    let wallet_name_owned = manager.try_lock()
        .map(|m| m.wallet_node.name().to_string())
        .unwrap_or_else(|_| "Wallet (locked)".to_string());
    let current_tab = data.current_tab;

    // Left sidebar navigation
    let sidebar = column![
        sidebar_button("Overview", WalletTab::Overview, current_tab),
        sidebar_button("Send", WalletTab::Send, current_tab),
        sidebar_button("Receive", WalletTab::Receive, current_tab),
        sidebar_button("Transactions", WalletTab::Transactions, current_tab),
        sidebar_button("SNICKER", WalletTab::Snicker, current_tab),
    ]
    .spacing(5)
    .padding(10);

    // Tab content
    let tab_content = match current_tab {
        WalletTab::Overview => view_overview(&wallet_name_owned, data),
        WalletTab::Send => view_send(data),
        WalletTab::Receive => view_receive(data),
        WalletTab::Transactions => view_transactions(),
        WalletTab::Snicker => view_snicker(data),
    };

    column![
        // Header with wallet name and menu
        container(
            row![
                text("Ambient Wallet").size(22),
                text(" • ").size(22),
                text(wallet_name_owned).size(22),

                // Spacer
                container(text(""))
                    .width(Length::Fill),

                // Menu buttons
                row![
                    menu_button("Close Wallet", Message::MenuCloseWallet),
                    menu_button("Settings", Message::MenuSettings),
                    menu_button("Exit", Message::MenuExit),
                ]
                .spacing(10),
            ]
        )
        .padding(15),

        // Main content area with sidebar + content
        row![
            // Left sidebar
            container(sidebar)
                .width(Length::Fixed(150.0)),

            // Content area (scrollable without visible scrollbar)
            scrollable(
                container(tab_content)
                    .width(Length::Fill)
                    .padding(20)
            )
            .direction(Direction::Vertical(
                Scrollbar::new()
                    .width(0)
                    .scroller_width(0)
            ))
            .width(Length::Fill)
            .height(Length::Fill),
        ]
        .spacing(0),
    ]
    .into()
}

/// Create a sidebar navigation button
fn sidebar_button(label: &str, tab: WalletTab, current: WalletTab) -> Element<'static, Message> {
    let is_active = tab == current;
    let label = label.to_string();

    let btn = if is_active {
        // Active button: prominent styling with colored background
        button(
            container(text(label.clone()).size(15))
                .width(Length::Fill)
                .padding(12)
        )
        .on_press(Message::TabChanged(tab))
        .width(Length::Fill)
        .style(|_theme: &Theme, _status| {
            Style {
                background: Some(iced::Background::Color(Color::from_rgb(0.2, 0.4, 0.8))),
                text_color: Color::WHITE,
                border: Border {
                    color: Color::from_rgb(0.3, 0.5, 0.9),
                    width: 2.0,
                    radius: 4.0.into(),
                },
                shadow: iced::Shadow::default(),
            }
        })
    } else {
        // Inactive button: subtle styling
        button(
            container(text(label.clone()).size(14))
                .width(Length::Fill)
                .padding(12)
        )
        .on_press(Message::TabChanged(tab))
        .width(Length::Fill)
        .style(|_theme: &Theme, status| {
            match status {
                button::Status::Hovered => Style {
                    background: Some(iced::Background::Color(Color::from_rgb(0.15, 0.15, 0.20))),
                    text_color: Color::WHITE,
                    border: Border {
                        color: Color::from_rgb(0.3, 0.3, 0.4),
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    shadow: iced::Shadow::default(),
                },
                _ => Style {
                    background: Some(iced::Background::Color(Color::from_rgb(0.1, 0.1, 0.15))),
                    text_color: Color::from_rgb(0.8, 0.8, 0.8),
                    border: Border {
                        color: Color::from_rgb(0.2, 0.2, 0.25),
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    shadow: iced::Shadow::default(),
                },
            }
        })
    };

    btn.into()
}

/// Create a styled menu button with rounded corners
fn menu_button(label: &str, message: Message) -> Element<'static, Message> {
    let label = label.to_string();

    button(text(label).size(14))
        .on_press(message)
        .padding(10)
        .style(|_theme: &Theme, status| {
            match status {
                button::Status::Hovered => Style {
                    background: Some(iced::Background::Color(Color::from_rgb(0.3, 0.3, 0.35))),
                    text_color: Color::WHITE,
                    border: Border {
                        color: Color::from_rgb(0.4, 0.4, 0.45),
                        width: 1.0,
                        radius: 6.0.into(),
                    },
                    shadow: iced::Shadow::default(),
                },
                button::Status::Pressed => Style {
                    background: Some(iced::Background::Color(Color::from_rgb(0.2, 0.2, 0.25))),
                    text_color: Color::WHITE,
                    border: Border {
                        color: Color::from_rgb(0.3, 0.3, 0.35),
                        width: 1.0,
                        radius: 6.0.into(),
                    },
                    shadow: iced::Shadow::default(),
                },
                _ => Style {
                    background: Some(iced::Background::Color(Color::from_rgb(0.15, 0.15, 0.2))),
                    text_color: Color::from_rgb(0.9, 0.9, 0.9),
                    border: Border {
                        color: Color::from_rgb(0.25, 0.25, 0.3),
                        width: 1.0,
                        radius: 6.0.into(),
                    },
                    shadow: iced::Shadow::default(),
                },
            }
        })
        .into()
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
    let mut content = column![
        container(
            column![
                text("SNICKER allows you to participate in collaborative transactions.").size(16),
                text("This improves your privacy by breaking on-chain links.").size(14),
            ].spacing(5)
        )
        .padding(10),
    ].spacing(20);

    // ========== PROPOSER SECTION ==========
    content = content.push(
        container(
            column![
                text("Proposer: Create Proposals").size(24),
                text("First scan the blockchain for potential candidates, then find matching opportunities with your UTXOs.").size(12),
            ].spacing(5)
        )
        .padding(10)
    );

    // Scan for candidates section
    let scan_blocks = data.snicker_scan_blocks_input.clone();
    let scan_min_utxo = data.snicker_scan_min_utxo_input.clone();
    let scan_max_utxo = data.snicker_scan_max_utxo_input.clone();

    content = content.push(
        container(
            column![
                text("Scan for Candidates (stored in database):").size(14),
                row![
                    text("Blocks:").size(12),
                    text_input("100", &scan_blocks)
                        .on_input(Message::SnickerScanBlocksInputChanged)
                        .width(Length::Fixed(80.0)),
                    text("Min:").size(12),
                    text_input("10000", &scan_min_utxo)
                        .on_input(Message::SnickerScanMinUtxoInputChanged)
                        .width(Length::Fixed(100.0)),
                    text("Max:").size(12),
                    text_input("100000000", &scan_max_utxo)
                        .on_input(Message::SnickerScanMaxUtxoInputChanged)
                        .width(Length::Fixed(120.0)),
                    button("Scan")
                        .on_press(Message::SnickerScanRequested)
                        .padding(8),
                    button("Clear All")
                        .on_press(Message::SnickerClearCandidates)
                        .padding(8),
                ].spacing(10),
                text(format!("Found {} candidates (includes all stored)", data.snicker_candidates)).size(12),
            ].spacing(5)
        )
        .padding(10)
    );

    // Find opportunities section
    let find_min_utxo = data.snicker_find_min_utxo_input.clone();

    content = content.push(
        container(
            column![
                text("Find Opportunities:").size(14),
                row![
                    text("Min UTXO:").size(12),
                    text_input("10000", &find_min_utxo)
                        .on_input(Message::SnickerFindMinUtxoInputChanged)
                        .width(Length::Fixed(100.0)),
                    button("Find")
                        .on_press(Message::SnickerFindOpportunities)
                        .padding(8),
                ].spacing(10),
                text(format!("Found {} opportunities", data.snicker_opportunities)).size(12),
            ].spacing(5)
        )
        .padding(10)
    );

    // Show opportunities list with create proposal section
    if !data.snicker_opportunities_list.is_empty() {
        let delta_input = data.snicker_proposal_delta_input.clone();

        let mut opp_list = column![].spacing(10);

        for (index, display) in &data.snicker_opportunities_list {
            let delta_for_button = delta_input.parse::<i64>().unwrap_or(0) as u64;
            opp_list = opp_list.push(
                container(
                    column![
                        text(display.clone()).size(12),
                        row![
                            text("Delta (sats):").size(12),
                            text_input("0", &delta_input)
                                .on_input(Message::SnickerProposalDeltaInputChanged)
                                .width(Length::Fixed(100.0)),
                            button(text("Create Proposal"))
                                .on_press(Message::SnickerCreateProposal(*index, delta_for_button))
                                .padding(5),
                        ].spacing(5),
                    ].spacing(5)
                )
                .padding(10)
            );
        }

        content = content.push(
            container(
                column![
                    text("Available Opportunities:").size(16),
                    scrollable(opp_list)
                        .direction(Direction::Vertical(
                            Scrollbar::new()
                                .width(0)
                                .scroller_width(0)
                        ))
                        .height(Length::Fixed(300.0)),
                ].spacing(10)
            )
            .padding(10)
        );
    }

    // Show last created proposal
    if let Some(ref tag) = data.snicker_last_proposal {
        content = content.push(
            container(
                column![
                    text("✅ Last Created Proposal:").size(14),
                    text(format!("Tag: {}", tag)).size(12),
                    text("File: Saved to proposals directory (see Settings)").size(11),
                ].spacing(3)
            )
            .padding(10)
        );
    }

    content = content.push(text("─".repeat(80)).size(12));

    // ========== RECEIVER SECTION ==========
    content = content.push(
        container(
            column![
                text("Receiver: Accept Proposals").size(24),
                text("Scan for incoming proposals or load a specific proposal file by tag.").size(12),
            ].spacing(5)
        )
        .padding(10)
    );

    // Scan for incoming proposals with delta range inputs
    let min_delta = data.snicker_scan_min_delta_input.clone();
    let max_delta = data.snicker_scan_max_delta_input.clone();
    let min_val = min_delta.parse::<i64>().unwrap_or(-1000);
    let max_val = max_delta.parse::<i64>().unwrap_or(5000);

    content = content.push(
        container(
            column![
                text("Scan for Incoming Proposals:").size(14),
                row![
                    text("Min Δ:").size(12),
                    text_input("-1000", &min_delta)
                        .on_input(Message::SnickerScanMinDeltaInputChanged)
                        .width(Length::Fixed(80.0)),
                    text("Max Δ:").size(12),
                    text_input("5000", &max_delta)
                        .on_input(Message::SnickerScanMaxDeltaInputChanged)
                        .width(Length::Fixed(80.0)),
                    button("Scan")
                        .on_press(Message::SnickerScanIncomingProposals(min_val, max_val))
                        .padding(8),
                ].spacing(10),
            ].spacing(5)
        )
        .padding(10)
    );

    // Show scanned proposals list
    if !data.snicker_scanned_proposals.is_empty() {
        let mut proposals_list = column![
            text(format!("Found {} matching proposal(s):", data.snicker_scanned_proposals.len())).size(16),
        ].spacing(10);

        for (idx, result) in data.snicker_scanned_proposals.iter().enumerate() {
            // Truncate tag for display
            let display_tag = if result.tag_hex.len() > 16 {
                format!("{}...{}", &result.tag_hex[..8], &result.tag_hex[result.tag_hex.len()-8..])
            } else {
                result.tag_hex.clone()
            };

            // Color code delta
            // Positive delta = receiver loses (contributes), negative = receiver gains
            let (delta_text, delta_color) = if result.delta > 0 {
                (format!("+{}", result.delta), Color::from_rgb(0.9, 0.2, 0.2)) // RED = loss
            } else if result.delta < 0 {
                (format!("{}", result.delta), Color::from_rgb(0.2, 0.8, 0.2)) // GREEN = gain
            } else {
                (format!("{}", result.delta), Color::from_rgb(0.7, 0.7, 0.7)) // GRAY = neutral
            };

            proposals_list = proposals_list.push(
                button(
                    container(
                        column![
                            text(format!("Tag: {}", display_tag)).size(12),
                            text(format!("Proposer: {} ({} sats)", result.proposer_input, result.proposer_value)).size(11),
                            text(format!("Your output: {} sats", result.receiver_output_value)).size(11),
                            text(format!("Δ: {} sats", delta_text)).size(11).color(delta_color),
                        ].spacing(3)
                    )
                    .padding(8)
                )
                .on_press(Message::SnickerShowAcceptDialog(idx))
                .width(Length::Fixed(500.0))
                .style(|_theme: &Theme, status| {
                    match status {
                        button::Status::Hovered => Style {
                            background: Some(iced::Background::Color(Color::from_rgb(0.25, 0.35, 0.65))),
                            text_color: Color::WHITE,
                            border: Border {
                                color: Color::from_rgb(0.35, 0.45, 0.75),
                                width: 1.5,
                                radius: 6.0.into(),
                            },
                            shadow: iced::Shadow::default(),
                        },
                        _ => Style {
                            background: Some(iced::Background::Color(Color::from_rgb(0.18, 0.28, 0.55))),
                            text_color: Color::WHITE,
                            border: Border {
                                color: Color::from_rgb(0.28, 0.38, 0.65),
                                width: 1.5,
                                radius: 6.0.into(),
                            },
                            shadow: iced::Shadow::default(),
                        },
                    }
                })
            );
        }

        content = content.push(
            container(
                scrollable(proposals_list)
                    .direction(Direction::Vertical(
                        Scrollbar::new()
                            .width(0)
                            .scroller_width(0)
                    ))
                    .height(Length::Fixed(300.0))
            )
            .padding(10)
        );
    }

    content.into()
}
