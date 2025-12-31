//! Generate wallet view

use iced::{Element, Length};
use iced::widget::{column, container, text, text_input, button};

use crate::gui::message::Message;

/// Render the wallet name input view
pub fn view_name_input(wallet_name: &str) -> Element<'static, Message> {
    let name_input = text_input("Enter wallet name", wallet_name)
        .on_input(Message::WalletNameChanged)
        .width(Length::Fixed(300.0))
        .padding(10);

    let generate_button = button("Generate Wallet")
        .on_press(Message::GenerateWalletRequested)
        .padding(10);

    let content = column![
        text("Create New Wallet").size(32),
        text("Enter a name for your wallet").size(16),
        name_input,
        generate_button,
        text("\nThe wallet will be created with a new random mnemonic (seed phrase).\nYou will need to save this mnemonic safely.").size(12),
    ]
    .spacing(20)
    .padding(20);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
}

/// Render the mnemonic display view
pub fn view_mnemonic(wallet_name: &str, mnemonic: &str) -> Element<'static, Message> {
    let wallet_name = wallet_name.to_string();
    let mnemonic = mnemonic.to_string();

    let mnemonic_display = container(
        text(mnemonic.clone())
            .size(16)
    )
    .padding(20)
    .width(Length::Fill)
    .style(|_theme| {
        container::Style {
            background: Some(iced::Background::Color(iced::Color::from_rgb(0.2, 0.2, 0.2))),
            border: iced::Border {
                color: iced::Color::from_rgb(0.4, 0.4, 0.4),
                width: 1.0,
                radius: 5.0.into(),
            },
            ..Default::default()
        }
    });

    let confirm_button = button("I have saved my mnemonic")
        .on_press(Message::WalletGenerationConfirmed)
        .padding(10);

    let content = column![
        text(format!("Wallet '{}' Created!", wallet_name.clone())).size(32),
        text("SAVE YOUR MNEMONIC SEED PHRASE").size(20),
        text("Write down these words in order. You will need them to recover your wallet.").size(14),
        mnemonic_display,
        text("Store this in a safe place. Anyone with this mnemonic can access your funds.").size(12),
        confirm_button,
    ]
    .spacing(20)
    .padding(20);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .into()
}
