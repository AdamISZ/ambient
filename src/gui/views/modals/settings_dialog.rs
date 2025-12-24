//! Settings dialog modal

use iced::{Element, Length};
use iced::widget::{column, container, text, button, text_input, pick_list, row, scrollable};

use crate::gui::message::Message;
use crate::config::Config;

/// Bitcoin network options for the dropdown
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkOption {
    Regtest,
    Signet,
    Mainnet,
}

/// Proposal network backend options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProposalNetworkBackend {
    FileBased,
    Nostr,
}

impl std::fmt::Display for NetworkOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkOption::Regtest => write!(f, "Regtest"),
            NetworkOption::Signet => write!(f, "Signet"),
            NetworkOption::Mainnet => write!(f, "Mainnet"),
        }
    }
}

impl std::fmt::Display for ProposalNetworkBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalNetworkBackend::FileBased => write!(f, "File-Based"),
            ProposalNetworkBackend::Nostr => write!(f, "Nostr"),
        }
    }
}

impl From<&crate::config::Network> for NetworkOption {
    fn from(network: &crate::config::Network) -> Self {
        match network {
            crate::config::Network::Regtest => NetworkOption::Regtest,
            crate::config::Network::Signet => NetworkOption::Signet,
            crate::config::Network::Mainnet => NetworkOption::Mainnet,
        }
    }
}

impl NetworkOption {
    fn as_str(&self) -> &str {
        match self {
            NetworkOption::Regtest => "regtest",
            NetworkOption::Signet => "signet",
            NetworkOption::Mainnet => "mainnet",
        }
    }

    const ALL: [NetworkOption; 3] = [
        NetworkOption::Regtest,
        NetworkOption::Signet,
        NetworkOption::Mainnet,
    ];
}

impl From<&crate::config::ProposalNetworkBackend> for ProposalNetworkBackend {
    fn from(backend: &crate::config::ProposalNetworkBackend) -> Self {
        match backend {
            crate::config::ProposalNetworkBackend::FileBased => ProposalNetworkBackend::FileBased,
            crate::config::ProposalNetworkBackend::Nostr => ProposalNetworkBackend::Nostr,
        }
    }
}

impl ProposalNetworkBackend {
    fn as_str(&self) -> &str {
        match self {
            ProposalNetworkBackend::FileBased => "FileBased",
            ProposalNetworkBackend::Nostr => "Nostr",
        }
    }

    const ALL: [ProposalNetworkBackend; 2] = [
        ProposalNetworkBackend::FileBased,
        ProposalNetworkBackend::Nostr,
    ];
}

/// Render the settings dialog
pub fn view(edited_config: &Config, wallet_loaded: bool) -> Element<'static, Message> {
    // Clone data for 'static lifetime
    let network = NetworkOption::from(&edited_config.network);
    let peer_value = edited_config.peer.clone().unwrap_or_default();
    let wallet_dir = edited_config.wallet_dir.to_string_lossy().to_string();
    let recovery_height_value = edited_config.recovery_height.to_string();
    let proposals_dir = edited_config.proposal_network.file_directory.to_string_lossy().to_string();
    let proposal_backend = ProposalNetworkBackend::from(&edited_config.proposal_network.backend);
    let nostr_relays = edited_config.proposal_network.nostr_relays.join(", ");
    let nostr_pow = edited_config.proposal_network.nostr_pow_difficulty
        .map(|d| d.to_string())
        .unwrap_or_default();
    let min_change_output_size_value = edited_config.snicker_automation.min_change_output_size.to_string();

    // Build scrollable content section
    let scrollable_content = column![
        // Network selection
        column![
            text("Network").size(16),
            if wallet_loaded {
                // Show current network as disabled text when wallet is loaded
                column![
                    text(format!("{}", network)).size(14),
                    text("(Cannot change network while wallet is loaded)").size(12)
                ].spacing(2)
            } else {
                // Show editable picker when no wallet is loaded
                column![
                    pick_list(
                        &NetworkOption::ALL[..],
                        Some(network),
                        |selected| Message::SettingsNetworkChanged(selected.as_str().to_string())
                    )
                ].spacing(0)
            }
        ].spacing(5),

        // Peer input
        column![
            text("Peer (optional)").size(16),
            text("Format: host:port (e.g., localhost:38333)").size(12),
            text_input("localhost:38333", &peer_value)
                .on_input(Message::SettingsPeerChanged)
                .width(Length::Fixed(400.0))
        ].spacing(5),

        // Recovery height input
        column![
            text("Recovery Height").size(16),
            text("Blockchain height to start scanning from (use 0 for regtest)").size(12),
            text_input("0", &recovery_height_value)
                .on_input(Message::SettingsRecoveryHeightChanged)
                .width(Length::Fixed(200.0))
        ].spacing(5),

        // Wallet directory input
        column![
            text("Wallet Directory").size(16),
            text_input("Wallet directory path", &wallet_dir)
                .on_input(Message::SettingsWalletDirChanged)
                .width(Length::Fixed(400.0))
        ].spacing(5),

        // Proposal Network Backend selection
        column![
            text("Proposal Network Backend").size(16),
            pick_list(
                &ProposalNetworkBackend::ALL[..],
                Some(proposal_backend),
                |selected| Message::SettingsProposalNetworkBackendChanged(selected.as_str().to_string())
            )
        ].spacing(5),

        // Show different fields based on backend selection
        if matches!(proposal_backend, ProposalNetworkBackend::FileBased) {
            column![
                text("Proposals Directory").size(16),
                text("Directory where SNICKER proposal files are stored").size(12),
                text_input("Proposals directory path", &proposals_dir)
                    .on_input(Message::SettingsProposalsDirChanged)
                    .width(Length::Fixed(400.0))
            ].spacing(5)
        } else {
            column![
                text("Nostr Relay URLs").size(16),
                text("Comma-separated relay URLs (e.g., ws://127.0.0.1:7780, wss://relay.damus.io)").size(12),
                text_input("ws://127.0.0.1:7780", &nostr_relays)
                    .on_input(Message::SettingsNostrRelaysChanged)
                    .width(Length::Fixed(500.0)),

                text("Proof-of-Work Difficulty (optional)").size(16),
                text("PoW difficulty for spam protection (10-20 recommended, leave empty for none)").size(12),
                text_input("10", &nostr_pow)
                    .on_input(Message::SettingsNostrPowDifficultyChanged)
                    .width(Length::Fixed(100.0))
            ].spacing(5)
        },

        // Minimum change output size input
        column![
            text("Minimum Change Output Size (sats)").size(16),
            text("Minimum size for change outputs in SNICKER proposals (default: 2730 = 5× dust limit)").size(12),
            text("Change below this will be dropped and added to miner fee instead").size(12),
            text_input("2730", &min_change_output_size_value)
                .on_input(Message::SettingsMinChangeOutputSizeChanged)
                .width(Length::Fixed(200.0))
        ].spacing(5),
    ]
    .spacing(20);

    // Fixed button bar at bottom
    let buttons = row![
        button("Save")
            .on_press(Message::SettingsSave)
            .padding(10),
        button("Cancel")
            .on_press(Message::CloseModal)
            .padding(10),
    ]
    .spacing(10);

    // Main layout: header + scrollable content + fixed buttons
    let layout = column![
        // Header
        text("Settings").size(32),

        // Scrollable content area - takes available space
        scrollable(scrollable_content)
            .height(Length::Fill),

        // Fixed button bar
        buttons,
    ]
    .spacing(20)
    .padding(30);

    // Container with fixed width and max height
    container(layout)
        .width(Length::Fixed(600.0))
        .max_height(700.0)
        .into()
}
