//! NoWallet landing page view

use iced::{Element, Length};
use iced::widget::{column, container, text, button, row};

use crate::gui::message::Message;

/// Render the NoWallet landing page
pub fn view(available_wallets: &[String]) -> Element<'static, Message> {
    let available_wallets = available_wallets.to_vec();

    let wallet_list = if available_wallets.is_empty() {
        column![
            text("No wallets found").size(16),
            text("Create your first wallet to get started").size(14),
        ].spacing(10)
    } else {
        let mut wallet_buttons = column![
            text(format!("Found {} wallet(s)", available_wallets.len())).size(16),
        ].spacing(10);

        for wallet_name in available_wallets {
            let name_clone = wallet_name.clone();
            wallet_buttons = wallet_buttons.push(
                button(text(wallet_name).size(14))
                    .on_press(Message::LoadWalletRequested(name_clone))
                    .padding(10)
                    .width(Length::Fixed(300.0))
            );
        }

        wallet_buttons
    };

    // Menu bar at top
    let menu_bar = container(
        row![
            container(text(""))
                .width(Length::Fill),

            row![
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
    .padding(10)
    .width(Length::Fill);

    // Main content (centered)
    let main_content = container(
        column![
            text("Ambient Wallet").size(48),
            text("A privacy-focused Bitcoin wallet with SNICKER support").size(16),

            container(wallet_list)
                .padding(20),

            row![
                button("Create New Wallet")
                    .on_press(Message::CreateWalletRequested)
                    .padding(15),
                button("Open Wallet...")
                    .on_press(Message::MenuOpenWallet)
                    .padding(15),
            ]
            .spacing(15),
        ]
        .spacing(30)
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .center_x(Length::Fill)
    .center_y(Length::Fill);

    // Combine menu and content
    column![
        menu_bar,
        main_content,
    ]
    .into()
}
