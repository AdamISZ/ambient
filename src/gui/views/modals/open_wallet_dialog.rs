//! Open Wallet dialog modal

use iced::{Element, Length, Border, Color, Theme};
use iced::widget::{button, column, container, row, text, text_input};
use iced::widget::button::Style;

use crate::gui::message::Message;

/// Render the open wallet dialog
pub fn view(
    _available_wallets: &[String],
    selected: &Option<String>,
    password: &str,
    error_message: &Option<String>,
) -> Element<'static, Message> {
    let selected = selected.clone();
    let password_owned = password.to_string();
    let error = error_message.clone();

    let mut content = column![].spacing(20);

    // Show wallet name if selected
    if let Some(ref wallet_name) = selected {
        content = content.push(
            text(format!("Wallet: {}", wallet_name)).size(18)
        );

        // Password input
        let password_input = if !password_owned.is_empty() {
            text_input("Enter wallet password", &password_owned)
                .on_input(Message::OpenWalletPasswordChanged)
                .on_submit(Message::LoadWalletRequested(wallet_name.clone(), password_owned.clone()))
                .secure(true)
                .width(Length::Fixed(400.0))
        } else {
            text_input("Enter wallet password", &password_owned)
                .on_input(Message::OpenWalletPasswordChanged)
                .secure(true)
                .width(Length::Fixed(400.0))
        };

        content = content.push(
            column![
                text("Password").size(16),
                password_input,
            ].spacing(5)
        );
    } else {
        // No wallet selected (error case or cancelled)
        content = content.push(
            text("No wallet selected").size(16)
        );
    }

    // Show error message if present
    if let Some(err) = error {
        content = content.push(
            text(format!("Error: {}", err))
                .size(14)
                .color(Color::from_rgb(1.0, 0.3, 0.3))
        );
    }

    // Button bar
    let mut buttons = row![
        dialog_button("Cancel", Message::CloseModal),
    ].spacing(10);

    if selected.is_some() && !password_owned.is_empty() {
        buttons = buttons.push(
            dialog_button("Load Wallet", Message::LoadWalletRequested(selected.unwrap(), password_owned))
        );
    }

    // Main layout
    let layout = column![
        text("Open Wallet").size(32),
        content,
        buttons,
    ]
    .spacing(20)
    .padding(30);

    container(layout)
        .width(Length::Fixed(500.0))
        .into()
}

/// Create a styled dialog button
fn dialog_button(label: &str, message: Message) -> Element<'static, Message> {
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
