//! Settings view for configuring the wallet

use iced::{Element, Length};
use iced::widget::{column, container, text, text_input, button, row, pick_list};

use crate::gui::message::Message;
use crate::config::{Config, Network};

/// Render the settings view
pub fn view(config: &Config) -> Element<'static, Message> {
    let network_options = vec![
        Network::Regtest,
        Network::Signet,
        Network::Mainnet,
    ];

    // Network selection
    let network_row = row![
        text("Network:").width(Length::Fixed(150.0)),
        pick_list(
            network_options,
            Some(config.network),
            |network| Message::SettingsNetworkChanged(network.as_str().to_string())
        )
        .width(Length::Fixed(200.0)),
    ]
    .spacing(10)
    .padding(10);

    // Peer input
    let peer_value = config.peer.clone().unwrap_or_default();
    let peer_row = row![
        text("Peer (optional):").width(Length::Fixed(150.0)),
        text_input("localhost:18444", &peer_value)
            .on_input(Message::SettingsPeerChanged)
            .width(Length::Fixed(300.0)),
    ]
    .spacing(10)
    .padding(10);

    // Wallet directory input
    let wallet_dir_value = config.wallet_dir.to_string_lossy().to_string();
    let wallet_dir_row = row![
        text("Wallet Directory:").width(Length::Fixed(150.0)),
        text_input("/path/to/wallets", &wallet_dir_value)
            .on_input(Message::SettingsWalletDirChanged)
            .width(Length::Fixed(400.0)),
    ]
    .spacing(10)
    .padding(10);

    // Save button
    let save_button = button("Save Settings")
        .on_press(Message::SettingsSave)
        .padding(10);

    // Help text
    let help_text = text(
        "Network: Choose the Bitcoin network (regtest for local testing, signet for testing, mainnet for production)\n\
         Peer: Optional single peer to connect to (format: host:port). Leave empty to discover peers automatically.\n\
         Wallet Directory: Location where wallet data will be stored."
    )
    .size(12);

    let content = column![
        text("Settings").size(32),
        text("Configure wallet settings").size(16),
        network_row,
        peer_row,
        wallet_dir_row,
        save_button,
        container(help_text)
            .padding(20)
            .width(Length::Fill),
    ]
    .spacing(20)
    .padding(20);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}
