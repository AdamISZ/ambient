//! Open Wallet dialog modal

use iced::{Element, Length};
use iced::widget::{column, container, text, button, row, scrollable};

use crate::gui::message::Message;

/// Render the open wallet dialog
pub fn view(available_wallets: &[String], selected: &Option<String>) -> Element<'static, Message> {
    let available_wallets = available_wallets.to_vec();
    let selected = selected.clone();

    let mut content = column![
        text("Open Wallet").size(32),
    ].spacing(20);

    if available_wallets.is_empty() {
        content = content.push(
            text("No wallets found in this directory").size(16)
        );
    } else {
        content = content.push(
            text(format!("Found {} wallet(s)", available_wallets.len())).size(16)
        );

        // List of wallets as buttons (scrollable)
        let mut wallet_list = column![].spacing(10);
        for wallet_name in &available_wallets {
            let name = wallet_name.clone();
            let is_selected = selected.as_ref() == Some(wallet_name);

            let btn_text = if is_selected {
                format!("▶ {}", wallet_name)
            } else {
                wallet_name.clone()
            };

            wallet_list = wallet_list.push(
                button(text(btn_text).size(14))
                    .on_press(Message::WalletSelected(name))
                    .padding(10)
                    .width(Length::Fixed(400.0))
            );
        }

        // Wrap in scrollable with max height to prevent overflow
        content = content.push(
            scrollable(wallet_list)
                .height(Length::Fixed(300.0))
        );
    }

    // Buttons
    let mut buttons = row![
        button("Cancel")
            .on_press(Message::CloseModal)
            .padding(10),
    ].spacing(10);

    if selected.is_some() {
        buttons = buttons.push(
            button("Load Wallet")
                .on_press(Message::LoadWalletRequested(selected.unwrap()))
                .padding(10)
        );
    }

    content = content.push(buttons);

    container(content.padding(30))
        .width(Length::Fixed(500.0))
        .height(Length::Fixed(550.0))
        .into()
}
