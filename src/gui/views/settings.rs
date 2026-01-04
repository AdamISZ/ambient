//! Full-page Settings view with organized sections

use iced::{Element, Length};
use iced::widget::{column, container, text, button, text_input, pick_list, row, scrollable};

use crate::gui::message::Message;
use crate::config::Config;

/// Bitcoin network options for the dropdown
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkOption {
    Mainnet,
    Signet,
    Regtest,
}

/// Proposal network backend options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalBackendOption {
    Nostr,
    FileBased,
}

impl std::fmt::Display for NetworkOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkOption::Mainnet => write!(f, "Mainnet"),
            NetworkOption::Signet => write!(f, "Signet"),
            NetworkOption::Regtest => write!(f, "Regtest"),
        }
    }
}

impl std::fmt::Display for ProposalBackendOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalBackendOption::Nostr => write!(f, "Nostr"),
            ProposalBackendOption::FileBased => write!(f, "File-Based"),
        }
    }
}

impl From<&crate::config::Network> for NetworkOption {
    fn from(network: &crate::config::Network) -> Self {
        match network {
            crate::config::Network::Mainnet => NetworkOption::Mainnet,
            crate::config::Network::Signet => NetworkOption::Signet,
            crate::config::Network::Regtest => NetworkOption::Regtest,
        }
    }
}

impl NetworkOption {
    fn as_str(&self) -> &str {
        match self {
            NetworkOption::Mainnet => "mainnet",
            NetworkOption::Signet => "signet",
            NetworkOption::Regtest => "regtest",
        }
    }

    const ALL: [NetworkOption; 3] = [
        NetworkOption::Mainnet,
        NetworkOption::Signet,
        NetworkOption::Regtest,
    ];
}

impl From<&crate::config::ProposalNetworkBackend> for ProposalBackendOption {
    fn from(backend: &crate::config::ProposalNetworkBackend) -> Self {
        match backend {
            crate::config::ProposalNetworkBackend::Nostr => ProposalBackendOption::Nostr,
            crate::config::ProposalNetworkBackend::FileBased => ProposalBackendOption::FileBased,
        }
    }
}

impl ProposalBackendOption {
    fn as_str(&self) -> &str {
        match self {
            ProposalBackendOption::Nostr => "Nostr",
            ProposalBackendOption::FileBased => "FileBased",
        }
    }

    const ALL: [ProposalBackendOption; 2] = [
        ProposalBackendOption::Nostr,
        ProposalBackendOption::FileBased,
    ];
}

/// Render the full-page settings view
pub fn view(edited_config: &Config, wallet_loaded: bool, advanced_expanded: bool) -> Element<'static, Message> {
    // Extract values for display
    let network = NetworkOption::from(&edited_config.network);
    let wallet_dir = edited_config.wallet_dir.to_string_lossy().to_string();
    let proposal_backend = ProposalBackendOption::from(&edited_config.proposal_network.backend);
    let nostr_relays = edited_config.proposal_network.nostr_relays.join(", ");
    let proposals_dir = edited_config.proposal_network.file_directory.to_string_lossy().to_string();

    // Spending limits
    let max_per_coinjoin = edited_config.snicker_automation.max_sats_per_coinjoin.to_string();
    let max_per_day = edited_config.snicker_automation.max_sats_per_day.to_string();
    let max_per_week = edited_config.snicker_automation.max_sats_per_week.to_string();

    // Advanced settings
    let peer_value = edited_config.peer.clone().unwrap_or_default();
    let recovery_height = edited_config.recovery_height.to_string();
    let nostr_pow = edited_config.proposal_network.nostr_pow_difficulty
        .map(|d| d.to_string())
        .unwrap_or_default();
    let scan_window = edited_config.partial_utxo_set.scan_window_blocks.to_string();

    // Build the settings content
    let content = column![
        // Header
        row![
            button("Back")
                .on_press(Message::SettingsClose)
                .padding(10),
            text("Settings").size(28),
        ]
        .spacing(20),

        // Scrollable settings content
        scrollable(
            column![
                // === GENERAL SECTION ===
                section_header("General"),

                setting_row(
                    "Network",
                    "Bitcoin network to connect to",
                    if wallet_loaded {
                        container(
                            column![
                                text(format!("{}", network)).size(14),
                                text("(Cannot change while wallet is loaded)").size(12)
                            ].spacing(2)
                        ).into()
                    } else {
                        pick_list(
                            &NetworkOption::ALL[..],
                            Some(network),
                            |selected| Message::SettingsNetworkChanged(selected.as_str().to_string())
                        ).into()
                    }
                ),

                setting_row(
                    "Wallet Directory",
                    "Where wallet files are stored",
                    row![
                        text_input("Wallet directory path", &wallet_dir)
                            .on_input(Message::SettingsWalletDirChanged)
                            .width(Length::Fixed(350.0)),
                        button("Browse")
                            .on_press(Message::BrowseWalletDirectory)
                            .padding(8)
                    ].spacing(10).into()
                ),

                // === PROPOSAL NETWORK SECTION ===
                section_header("Proposal Network"),

                setting_row(
                    "Backend",
                    "How SNICKER proposals are exchanged",
                    pick_list(
                        &ProposalBackendOption::ALL[..],
                        Some(proposal_backend),
                        |selected| Message::SettingsProposalNetworkBackendChanged(selected.as_str().to_string())
                    ).into()
                ),

                // Conditional fields based on backend
                if matches!(proposal_backend, ProposalBackendOption::Nostr) {
                    setting_row(
                        "Nostr Relays",
                        "Comma-separated relay URLs",
                        text_input("wss://relay.damus.io", &nostr_relays)
                            .on_input(Message::SettingsNostrRelaysChanged)
                            .width(Length::Fixed(400.0))
                            .into()
                    )
                } else {
                    setting_row(
                        "Proposals Directory",
                        "Directory for proposal files",
                        row![
                            text_input("Proposals directory", &proposals_dir)
                                .on_input(Message::SettingsProposalsDirChanged)
                                .width(Length::Fixed(350.0)),
                            button("Browse")
                                .on_press(Message::BrowseProposalsDirectory)
                                .padding(8)
                        ].spacing(10).into()
                    )
                },

                // === SPENDING LIMITS SECTION ===
                section_header("Spending Limits"),
                text("Maximum sats you're willing to spend on coinjoin fees").size(12),

                setting_row(
                    "Per Coinjoin",
                    "Maximum fee contribution per coinjoin",
                    row![
                        text_input("1000", &max_per_coinjoin)
                            .on_input(Message::SettingsMaxPerCoinjoinChanged)
                            .width(Length::Fixed(100.0)),
                        text("sats").size(14),
                    ].spacing(8).into()
                ),

                setting_row(
                    "Per Day",
                    "Maximum total fees per day",
                    row![
                        text_input("2500", &max_per_day)
                            .on_input(Message::SettingsMaxPerDayChanged)
                            .width(Length::Fixed(100.0)),
                        text("sats").size(14),
                    ].spacing(8).into()
                ),

                setting_row(
                    "Per Week",
                    "Maximum total fees per week",
                    row![
                        text_input("10000", &max_per_week)
                            .on_input(Message::SettingsMaxPerWeekChanged)
                            .width(Length::Fixed(100.0)),
                        text("sats").size(14),
                    ].spacing(8).into()
                ),

                // === ADVANCED SECTION (Collapsible) ===
                collapsible_section_header("Advanced", advanced_expanded),

                advanced_section(
                    advanced_expanded,
                    &peer_value,
                    &recovery_height,
                    &nostr_pow,
                    &scan_window,
                    proposal_backend,
                ),

            ]
            .spacing(12)
            .padding(20)
        )
        .height(Length::Fill),

        // Save/Cancel buttons at bottom
        container(
            row![
                button("Save Changes")
                    .on_press(Message::SettingsSave)
                    .padding(12),
                button("Cancel")
                    .on_press(Message::SettingsClose)
                    .padding(12),
            ]
            .spacing(15)
        )
        .padding(15),
    ]
    .spacing(10)
    .padding(20);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// Create a section header
fn section_header(title: &str) -> Element<'static, Message> {
    let title = title.to_string();
    container(
        container(
            text(title).size(20)
        )
        .padding([15, 5])  // [top_bottom, left_right]
    )
    .into()
}

/// Create the advanced section content (conditionally shown)
fn advanced_section(
    expanded: bool,
    peer_value: &str,
    recovery_height: &str,
    nostr_pow: &str,
    scan_window: &str,
    proposal_backend: ProposalBackendOption,
) -> Element<'static, Message> {
    if !expanded {
        return container(text("")).height(Length::Shrink).into();
    }

    let peer_value = peer_value.to_string();
    let recovery_height = recovery_height.to_string();
    let nostr_pow = nostr_pow.to_string();
    let scan_window = scan_window.to_string();

    let mut content = column![
        setting_row(
            "Peer",
            "Connect to specific node (leave empty for auto)",
            text_input("host:port", &peer_value)
                .on_input(Message::SettingsPeerChanged)
                .width(Length::Fixed(250.0))
                .into()
        ),

        setting_row(
            "Recovery Height",
            "Blockchain height to start scanning from",
            text_input("0", &recovery_height)
                .on_input(Message::SettingsRecoveryHeightChanged)
                .width(Length::Fixed(120.0))
                .into()
        ),
    ].spacing(12);

    // Add Nostr PoW difficulty if using Nostr backend
    if matches!(proposal_backend, ProposalBackendOption::Nostr) {
        content = content.push(
            setting_row(
                "Nostr PoW Difficulty",
                "Spam protection (10-20 recommended, empty=none)",
                text_input("", &nostr_pow)
                    .on_input(Message::SettingsNostrPowDifficultyChanged)
                    .width(Length::Fixed(80.0))
                    .into()
            )
        );
    }

    content = content.push(
        setting_row(
            "Scan Window",
            "Track UTXOs created in recent blocks (~1000 = 1 week)",
            row![
                text_input("1000", &scan_window)
                    .on_input(Message::SettingsScanWindowChanged)
                    .width(Length::Fixed(100.0)),
                text("blocks").size(14),
            ].spacing(8).into()
        )
    );

    content.into()
}

/// Create a collapsible section header with expand/collapse toggle
fn collapsible_section_header(title: &str, expanded: bool) -> Element<'static, Message> {
    let title = title.to_string();
    let indicator = if expanded { "[-]" } else { "[+]" };

    button(
        row![
            text(format!("{} {}", indicator, title)).size(20),
        ]
        .spacing(8)
    )
    .on_press(Message::SettingsToggleAdvanced)
    .padding([15, 5])
    .style(|_theme: &iced::Theme, status| {
        use iced::widget::button::Style;
        use iced::Border;
        match status {
            iced::widget::button::Status::Hovered => Style {
                background: Some(iced::Background::Color(iced::Color::from_rgb(0.15, 0.15, 0.2))),
                text_color: iced::Color::WHITE,
                border: Border::default(),
                shadow: iced::Shadow::default(),
            },
            _ => Style {
                background: None,
                text_color: iced::Color::from_rgb(0.9, 0.9, 0.9),
                border: Border::default(),
                shadow: iced::Shadow::default(),
            },
        }
    })
    .into()
}

/// Create a setting row with label, description, and control
fn setting_row(
    label: &str,
    description: &str,
    control: Element<'static, Message>,
) -> Element<'static, Message> {
    let label = label.to_string();
    let description = description.to_string();

    row![
        column![
            text(label).size(14),
            text(description).size(11),
        ]
        .width(Length::Fixed(220.0))
        .spacing(2),

        control,
    ]
    .spacing(20)
    .padding([5, 0])
    .into()
}
