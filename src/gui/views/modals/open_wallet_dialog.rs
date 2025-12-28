//! Open Wallet dialog modal

use iced::{Element, Length, Border, Color, Theme};
use iced::widget::{column, container, text, button, row, scrollable, Scrollable, text_input};
use iced::widget::scrollable::{Direction, Scrollbar};
use iced::widget::button::Style;

use crate::gui::message::Message;

/// Render the open wallet dialog
pub fn view(
    available_wallets: &[String],
    selected: &Option<String>,
    password: &str,
    error_message: &Option<String>,
) -> Element<'static, Message> {
    let available_wallets = available_wallets.to_vec();
    let selected = selected.clone();
    let password_owned = password.to_string();
    let error = error_message.clone();

    // Build scrollable content section
    let mut scrollable_content = column![].spacing(20);

    if available_wallets.is_empty() {
        scrollable_content = scrollable_content.push(
            text("No wallets found in this directory").size(16)
        );
    } else {
        scrollable_content = scrollable_content.push(
            text(format!("Found {} wallet(s)", available_wallets.len())).size(16)
        );

        // List of wallets as buttons (nested scrollable for long lists)
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
                wallet_button(&btn_text, Message::WalletSelected(name), is_selected)
            );
        }

        // Wrap wallet list in its own scrollable with reasonable max height
        scrollable_content = scrollable_content.push(
            scrollable(wallet_list)
                .direction(Direction::Vertical(
                    Scrollbar::new()
                        .width(0)
                        .scroller_width(0)
                ))
                .width(Length::Fill)
                .height(Length::Fixed(300.0))
        );
    }

    // Password input (only show if wallet is selected)
    if selected.is_some() {
        let password_input = if !password_owned.is_empty() {
            // Enable submit on Enter key when password is not empty
            text_input("Enter wallet password", &password_owned)
                .on_input(Message::OpenWalletPasswordChanged)
                .on_submit(Message::LoadWalletRequested(selected.clone().unwrap(), password_owned.clone()))
                .secure(true)
                .width(Length::Fixed(400.0))
        } else {
            // No submit action when password is empty
            text_input("Enter wallet password", &password_owned)
                .on_input(Message::OpenWalletPasswordChanged)
                .secure(true)
                .width(Length::Fixed(400.0))
        };

        scrollable_content = scrollable_content.push(
            column![
                text("Password").size(16),
                password_input,
            ].spacing(5)
        );

        // Show error message if present
        if let Some(err) = error {
            scrollable_content = scrollable_content.push(
                text(format!("❌ {}", err))
                    .size(14)
                    .color(Color::from_rgb(1.0, 0.3, 0.3))
            );
        }
    }

    // Fixed button bar at bottom
    let mut buttons = row![
        dialog_button("Cancel", Message::CloseModal),
    ].spacing(10);

    if selected.is_some() && !password_owned.is_empty() {
        buttons = buttons.push(
            dialog_button("Load Wallet", Message::LoadWalletRequested(selected.unwrap(), password_owned))
        );
    }

    // Main layout: header + scrollable content + fixed buttons
    let layout = column![
        // Header
        text("Open Wallet").size(32),

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
        .width(Length::Fixed(500.0))
        .max_height(700.0)
        .into()
}

/// Create a styled wallet button
fn wallet_button(label: &str, message: Message, is_selected: bool) -> Element<'static, Message> {
    let label = label.to_string();

    let btn = if is_selected {
        button(text(label).size(14))
            .on_press(message)
            .padding(10)
            .width(Length::Fixed(400.0))
            .style(|_theme: &Theme, _status| {
                Style {
                    background: Some(iced::Background::Color(Color::from_rgb(0.2, 0.4, 0.8))),
                    text_color: Color::WHITE,
                    border: Border {
                        color: Color::from_rgb(0.3, 0.5, 0.9),
                        width: 2.0,
                        radius: 6.0.into(),
                    },
                    shadow: iced::Shadow::default(),
                }
            })
    } else {
        button(text(label).size(14))
            .on_press(message)
            .padding(10)
            .width(Length::Fixed(400.0))
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
    };

    btn.into()
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
