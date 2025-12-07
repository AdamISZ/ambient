//! Settings dialog modal

use iced::{Element, Length};
use iced::widget::{column, container, text, button, text_input, pick_list, row};

use crate::gui::message::Message;
use crate::config::Config;

/// Network options for the dropdown
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkOption {
    Regtest,
    Signet,
    Mainnet,
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

/// Render the settings dialog
pub fn view(edited_config: &Config) -> Element<'static, Message> {
    // Clone data for 'static lifetime
    let network = NetworkOption::from(&edited_config.network);
    let peer_value = edited_config.peer.clone().unwrap_or_default();
    let wallet_dir = edited_config.wallet_dir.to_string_lossy().to_string();
    let recovery_height_value = edited_config.recovery_height.to_string();

    let content = column![
        text("Settings").size(32),

        // Network selection
        column![
            text("Network").size(16),
            pick_list(
                &NetworkOption::ALL[..],
                Some(network),
                |selected| Message::SettingsNetworkChanged(selected.as_str().to_string())
            )
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

        // Buttons
        row![
            button("Save")
                .on_press(Message::SettingsSave)
                .padding(10),
            button("Cancel")
                .on_press(Message::CloseModal)
                .padding(10),
        ]
        .spacing(10)
    ]
    .spacing(20)
    .padding(30);

    container(content)
        .width(Length::Fixed(600.0))
        .into()
}
