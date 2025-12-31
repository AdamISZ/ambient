//! Accept SNICKER Proposal confirmation dialog

use iced::{Element, Length, Border, Color, Theme};
use iced::widget::{column, container, text, button, row};
use iced::widget::button::Style;

use crate::gui::message::Message;

/// Render the accept proposal confirmation dialog
pub fn view(
    proposal_index: usize,
    tag_hex: &str,
    proposer_input: &str,
    proposer_value: u64,
    receiver_output_value: u64,
    delta: i64,
) -> Element<'static, Message> {
    let tag_hex = tag_hex.to_string();
    let proposer_input = proposer_input.to_string();

    let mut content = column![
        text("Accept SNICKER Proposal?").size(32),
    ].spacing(20);

    // Proposal details
    let details = column![
        text("Proposal Details:").size(18),

        // Tag
        row![
            text("Tag:").size(14),
            text(tag_hex.clone()).size(14),
        ].spacing(10),

        // Proposer Input
        row![
            text("Proposer Input:").size(14),
            text(format!("{} ({} sats)", proposer_input, proposer_value)).size(14),
        ].spacing(10),

        // Your Output
        row![
            text("Your Output:").size(14),
            text(format!("{} sats", receiver_output_value)).size(14),
        ].spacing(10),

        // Delta with color coding
        // Positive delta = receiver loses (contributes), negative = receiver gains
        {
            let (delta_text, delta_color) = if delta > 0 {
                (format!("Δ: +{} sats (loss)", delta), Color::from_rgb(0.9, 0.2, 0.2))
            } else if delta < 0 {
                (format!("Δ: {} sats (gain)", delta), Color::from_rgb(0.2, 0.8, 0.2))
            } else {
                (format!("Δ: {} sats (neutral)", delta), Color::from_rgb(0.7, 0.7, 0.7))
            };

            row![
                text(delta_text).size(14).color(delta_color),
            ]
        },
    ].spacing(10);

    content = content.push(details);

    // Warning for large positive delta (receiver loses money)
    if delta > 10000 {
        content = content.push(
            container(
                text(format!("Warning: You will lose {} sats in this transaction!", delta))
                    .size(14)
                    .color(Color::from_rgb(0.9, 0.5, 0.0))
            )
            .padding(10)
        );
    }

    // Buttons
    let buttons = row![
        dialog_button("Cancel", Message::SnickerCancelAccept, false),
        dialog_button("Accept & Broadcast", Message::SnickerConfirmAccept(proposal_index), true),
    ].spacing(10);

    content = content.push(buttons);

    container(content.padding(30))
        .width(Length::Fixed(550.0))
        .height(Length::Fixed(400.0))
        .into()
}

/// Create a styled dialog button
fn dialog_button(label: &str, message: Message, is_primary: bool) -> Element<'static, Message> {
    let label = label.to_string();

    if is_primary {
        button(text(label).size(14))
            .on_press(message)
            .padding(12)
            .style(|_theme: &Theme, status| {
                match status {
                    button::Status::Hovered => Style {
                        background: Some(iced::Background::Color(Color::from_rgb(0.25, 0.5, 0.9))),
                        text_color: Color::WHITE,
                        border: Border {
                            color: Color::from_rgb(0.35, 0.6, 1.0),
                            width: 2.0,
                            radius: 6.0.into(),
                        },
                        shadow: iced::Shadow::default(),
                    },
                    button::Status::Pressed => Style {
                        background: Some(iced::Background::Color(Color::from_rgb(0.15, 0.4, 0.8))),
                        text_color: Color::WHITE,
                        border: Border {
                            color: Color::from_rgb(0.25, 0.5, 0.9),
                            width: 2.0,
                            radius: 6.0.into(),
                        },
                        shadow: iced::Shadow::default(),
                    },
                    _ => Style {
                        background: Some(iced::Background::Color(Color::from_rgb(0.2, 0.45, 0.85))),
                        text_color: Color::WHITE,
                        border: Border {
                            color: Color::from_rgb(0.3, 0.55, 0.95),
                            width: 2.0,
                            radius: 6.0.into(),
                        },
                        shadow: iced::Shadow::default(),
                    },
                }
            })
            .into()
    } else {
        button(text(label).size(14))
            .on_press(message)
            .padding(12)
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
}
