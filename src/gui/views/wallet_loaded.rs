//! WalletLoaded main view with tabs

use iced::{Element, Length, Border, Color, Theme};
use iced::widget::{column, container, text, button, row, text_input, scrollable};
use iced::widget::scrollable::{Direction, Scrollbar};
use iced::widget::button::Style;
use std::sync::Arc;

use crate::gui::message::Message;
use crate::gui::state::{WalletTab, WalletData};
use crate::manager::Manager;

/// Render the wallet loaded view
pub fn view(manager: &Arc<Manager>, data: &WalletData) -> Element<'static, Message> {
    let wallet_name_owned = manager.wallet_node.name().to_string();
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

        // Status bar at bottom
        status_bar(data)
    ]
    .spacing(0)
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
/// Create permanent status bar at bottom showing status messages
fn status_bar(data: &WalletData) -> Element<'static, Message> {
    let status_text = data.status_message
        .as_ref()
        .cloned()
        .unwrap_or_else(|| "Ready".to_string());

    container(
        text(status_text).size(14)
    )
    .padding(8)
    .width(Length::Fill)
    .style(|_theme: &Theme| {
        container::Style {
            background: Some(iced::Background::Color(Color::from_rgb(0.2, 0.3, 0.4))),
            text_color: Some(Color::WHITE),
            ..Default::default()
        }
    })
    .into()
}

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
    let pending_out = data.pending_outgoing;
    let pending_in = data.pending_incoming;
    let sync_status = if data.is_syncing {
        "Syncing..."
    } else {
        "Synced"
    };
    let utxos = data.utxos.clone();

    // Build pending info string
    let pending_info = if pending_out > 0 || pending_in > 0 {
        let mut parts = Vec::new();
        if pending_out > 0 {
            parts.push(format!("-{} sats", pending_out));
        }
        if pending_in > 0 {
            parts.push(format!("+{} sats", pending_in));
        }
        format!("Pending: {}", parts.join(" | "))
    } else {
        String::new()
    };

    column![
        container(
            column![
                row![
                    text("Wallet:").size(18),
                    text(wallet_name).size(18),
                ].spacing(10),

                row![
                    text("Confirmed:").size(24),
                    text(format!("{}", balance)).size(24),
                ].spacing(10),

                // Show pending info if any
                if !pending_info.is_empty() {
                    text(pending_info).size(16)
                } else {
                    text("").size(1)
                },

                row![
                    text("Status:").size(16),
                    text(sync_status).size(16),
                ].spacing(10),
            ].spacing(15)
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
            row![
                text_input("0.001", &send_amount)
                    .on_input(Message::SendAmountChanged)
                    .width(Length::Fixed(300.0)),
                button(text("Send All").size(14))
                    .on_press(Message::SendAllRequested)
                    .padding(8)
            ].spacing(10)
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

/// Automation section for SNICKER tab
fn view_automation_section(data: &WalletData) -> Element<'static, Message> {
    // Removed: AutomationMode and pick_list - replaced with simple toggle

    // Status indicator
    let status_text = if data.automation_running {
        text("● Running").size(14).color(Color::from_rgb(0.0, 0.8, 0.0)) // Green
    } else {
        text("○ Stopped").size(14).color(Color::from_rgb(0.5, 0.5, 0.5)) // Gray
    };

    // Enable/Disable toggle button
    let toggle_label = if data.automation_enabled {
        "Disable Automation"
    } else {
        "Enable Automation"
    };

    // Role display
    let role_text = text(format!("Role: {}", data.automation_role)).size(14);

    // Build the control row based on state
    let controls = if data.automation_enabled {
        let start_label = "Start";
        let stop_label = "Stop";

        if data.automation_running {
            row![
                button(toggle_label).on_press(Message::AutomationToggleEnabled).padding(8),
                button(start_label).padding(8),
                button(stop_label).on_press(Message::AutomationStop).padding(8),
            ].spacing(10)
        } else {
            row![
                button(toggle_label).on_press(Message::AutomationToggleEnabled).padding(8),
                button(start_label).on_press(Message::AutomationStart).padding(8),
                button(stop_label).padding(8),
            ].spacing(10)
        }
    } else {
        row![
            button(toggle_label).on_press(Message::AutomationToggleEnabled).padding(8),
        ].spacing(10)
    };

    container(
        column![
            text("AUTOMATION").size(24),
            text("Automatically participate in SNICKER coinjoins").size(12),
            controls,
            row![
                text("Status:").size(14),
                status_text,
                role_text,
            ].spacing(10),
            row![
                text("Max sats/coinjoin:").size(14),
                text_input("1000", &data.automation_max_sats_per_coinjoin)
                    .on_input(Message::AutomationMaxSatsPerCoinjoinChanged)
                    .width(Length::Fixed(80.0)),
            ].spacing(10),
            row![
                text("Max sats/day:").size(14),
                text_input("2500", &data.automation_max_sats_per_day)
                    .on_input(Message::AutomationMaxSatsPerDayChanged)
                    .width(Length::Fixed(80.0)),
                text("Max sats/week:").size(14),
                text_input("10000", &data.automation_max_sats_per_week)
                    .on_input(Message::AutomationMaxSatsPerWeekChanged)
                    .width(Length::Fixed(80.0)),
            ].spacing(10),
        ].spacing(10)
    )
    .padding(15)
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

    // ========== AUTOMATION SECTION ==========
    content = content.push(view_automation_section(data));

    // ========== PROPOSER SECTION ==========
    content = content.push(
        container(
            column![
                text("Proposer: Create Proposals").size(24),
                text("Find candidate UTXOs from the blockchain and match them with your UTXOs to create coinjoin proposals.").size(12),
            ].spacing(5)
        )
        .padding(10)
    );

    // Find opportunities section with candidate filters
    let scan_min_utxo = data.snicker_scan_min_utxo_input.clone();
    let scan_max_utxo = data.snicker_scan_max_utxo_input.clone();
    let scan_block_age = data.snicker_scan_block_age_input.clone();

    content = content.push(
        container(
            column![
                text("Find Opportunities:").size(14),
                text("Candidate UTXO filters:").size(12),
                row![
                    text("Min size:").size(12),
                    text_input("10000", &scan_min_utxo)
                        .on_input(Message::SnickerScanMinUtxoInputChanged)
                        .width(Length::Fixed(100.0)),
                    text("sats").size(12),
                    text("Max size:").size(12),
                    text_input("100000000", &scan_max_utxo)
                        .on_input(Message::SnickerScanMaxUtxoInputChanged)
                        .width(Length::Fixed(120.0)),
                    text("sats").size(12),
                ].spacing(10),
                row![
                    text("Max block age:").size(12),
                    text_input("0", &scan_block_age)
                        .on_input(Message::SnickerScanBlockAgeInputChanged)
                        .width(Length::Fixed(100.0)),
                    text("blocks (0 = all)").size(12),
                ].spacing(10),
                row![
                    button("Find Opportunities")
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
                    text("Last Created Proposal:").size(14),
                    text(format!("Tag: {}", tag)).size(12),
                    text("File: Saved to proposals directory (see Settings)").size(11),
                ].spacing(3)
            )
            .padding(10)
        );
    }

    content.into()
}
