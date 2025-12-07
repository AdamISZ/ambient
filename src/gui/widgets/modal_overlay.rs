//! Modal overlay widget for displaying dialogs on top of main content

use iced::{Element, Background, Color, Length, Border};
use iced::widget::{container, stack};

/// Create a modal overlay with backdrop
///
/// This renders the base content with a semi-transparent backdrop
/// and the modal content centered on top
pub fn modal_overlay<'a, Message: 'a>(
    base: Element<'a, Message>,
    modal_content: Element<'a, Message>,
) -> Element<'a, Message> {
    stack![
        base,
        // Backdrop with centered modal content
        container(
            container(modal_content)
                .style(modal_container_style)
                .padding(20)
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .style(backdrop_style)
    ]
    .into()
}

/// Style for the modal container (the dialog box itself)
fn modal_container_style(_theme: &iced::Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgb(0.15, 0.15, 0.15))),
        border: Border {
            color: Color::from_rgb(0.4, 0.4, 0.4),
            width: 2.0,
            radius: 12.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
            offset: iced::Vector::new(0.0, 4.0),
            blur_radius: 20.0,
        },
        ..Default::default()
    }
}

/// Style for the backdrop (semi-transparent overlay)
fn backdrop_style(_theme: &iced::Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.6))),
        ..Default::default()
    }
}
