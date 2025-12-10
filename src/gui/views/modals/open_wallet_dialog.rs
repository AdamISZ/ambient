//! Open Wallet dialog modal

use iced::{Element, Length, Border, Color, Theme};
use iced::widget::{column, container, text, button, row, scrollable, Scrollable};
use iced::widget::scrollable::{Direction, Scrollbar};
use iced::widget::button::Style;

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
                wallet_button(&btn_text, Message::WalletSelected(name), is_selected)
            );
        }

        // Wrap in scrollable with max height to prevent overflow
        content = content.push(
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

    // Buttons
    let mut buttons = row![
        dialog_button("Cancel", Message::CloseModal),
    ].spacing(10);

    if selected.is_some() {
        buttons = buttons.push(
            dialog_button("Load Wallet", Message::LoadWalletRequested(selected.unwrap()))
        );
    }

    content = content.push(buttons);

    container(content.padding(30))
        .width(Length::Fixed(500.0))
        .height(Length::Fixed(550.0))
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
