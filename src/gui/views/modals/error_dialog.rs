//! Error dialog modal

use iced::{Element, Length, Border, Color, Theme};
use iced::widget::{button, column, container, text};
use iced::widget::button::Style;

use crate::gui::message::Message;

/// Render the error dialog
pub fn view(title: &str, message: &str) -> Element<'static, Message> {
    let title = title.to_string();
    let message = message.to_string();

    let content = column![
        text(title).size(24).color(Color::from_rgb(1.0, 0.4, 0.4)),
        text(message).size(16),
        dialog_button("OK", Message::CloseModal),
    ]
    .spacing(20)
    .padding(30);

    container(content)
        .width(Length::Fixed(450.0))
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
