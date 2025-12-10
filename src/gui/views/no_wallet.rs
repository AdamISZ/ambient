//! NoWallet landing page view

use iced::{Element, Length, Border, Color, Theme};
use iced::widget::{column, container, text, button, row};
use iced::widget::button::Style;

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
                wallet_button(&wallet_name, Message::LoadWalletRequested(name_clone))
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
                menu_button("Settings", Message::MenuSettings),
                menu_button("Exit", Message::MenuExit),
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
                primary_button("Create New Wallet", Message::CreateWalletRequested),
                primary_button("Open Wallet...", Message::MenuOpenWallet),
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

/// Create a styled menu button with rounded corners
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

/// Create a styled wallet button
fn wallet_button(label: &str, message: Message) -> Element<'static, Message> {
    let label = label.to_string();

    button(text(label).size(14))
        .on_press(message)
        .padding(10)
        .width(Length::Fixed(300.0))
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
                button::Status::Pressed => Style {
                    background: Some(iced::Background::Color(Color::from_rgb(0.15, 0.25, 0.55))),
                    text_color: Color::WHITE,
                    border: Border {
                        color: Color::from_rgb(0.25, 0.35, 0.65),
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
        .into()
}

/// Create a styled primary action button
fn primary_button(label: &str, message: Message) -> Element<'static, Message> {
    let label = label.to_string();

    button(text(label).size(16))
        .on_press(message)
        .padding(15)
        .style(|_theme: &Theme, status| {
            match status {
                button::Status::Hovered => Style {
                    background: Some(iced::Background::Color(Color::from_rgb(0.25, 0.5, 0.9))),
                    text_color: Color::WHITE,
                    border: Border {
                        color: Color::from_rgb(0.35, 0.6, 1.0),
                        width: 2.0,
                        radius: 8.0.into(),
                    },
                    shadow: iced::Shadow::default(),
                },
                button::Status::Pressed => Style {
                    background: Some(iced::Background::Color(Color::from_rgb(0.15, 0.4, 0.8))),
                    text_color: Color::WHITE,
                    border: Border {
                        color: Color::from_rgb(0.25, 0.5, 0.9),
                        width: 2.0,
                        radius: 8.0.into(),
                    },
                    shadow: iced::Shadow::default(),
                },
                _ => Style {
                    background: Some(iced::Background::Color(Color::from_rgb(0.2, 0.45, 0.85))),
                    text_color: Color::WHITE,
                    border: Border {
                        color: Color::from_rgb(0.3, 0.55, 0.95),
                        width: 2.0,
                        radius: 8.0.into(),
                    },
                    shadow: iced::Shadow::default(),
                },
            }
        })
        .into()
}
