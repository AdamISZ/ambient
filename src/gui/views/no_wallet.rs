//! NoWallet landing page view

use iced::{Element, Length, Border, Color, Theme};
use iced::widget::{column, container, text, button, row};
use iced::widget::button::Style;

use crate::gui::message::Message;

/// Render the NoWallet landing page
pub fn view(available_wallets: &[String]) -> Element<'static, Message> {
    let _available_wallets = available_wallets.to_vec(); // Keep parameter for API compatibility

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
