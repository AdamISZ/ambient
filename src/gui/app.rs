//! Main Iced application

use iced::{Application, Command, Element, Settings, Theme, executor};

use crate::gui::message::{Message, View};
use crate::gui::state::AppState;

/// Main application struct
pub struct AmbientApp {
    state: AppState,
}

impl Application for AmbientApp {
    type Message = Message;
    type Executor = executor::Default;
    type Flags = ();
    type Theme = Theme;

    fn new(_flags: Self::Flags) -> (Self, Command<Self::Message>) {
        (
            Self {
                state: AppState::new(),
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        String::from("Ambient Wallet")
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            Message::WalletSelected(name) => {
                // TODO: Load wallet
                println!("Loading wallet: {}", name);
                Command::none()
            }

            Message::CreateWalletRequested => {
                // TODO: Show create wallet screen
                println!("Create wallet requested");
                Command::none()
            }

            Message::ViewChanged(view) => {
                // TODO: Change view
                println!("View changed to: {:?}", view);
                Command::none()
            }

            Message::Placeholder => {
                // No-op for now
                Command::none()
            }

            _ => {
                // TODO: Implement other message handlers
                println!("Unhandled message: {:?}", message);
                Command::none()
            }
        }
    }

    fn view(&self) -> Element<Self::Message> {
        use iced::widget::{column, container, text};

        let content = match &self.state {
            AppState::WalletSelection { available_wallets } => {
                column![
                    text("Ambient Wallet").size(32),
                    text("Select or create a wallet").size(16),
                    text(format!("Found {} wallets", available_wallets.len())),
                ]
                .spacing(20)
            }

            AppState::CreatingWallet { wallet_name, .. } => {
                column![
                    text("Create New Wallet").size(32),
                    text(format!("Wallet name: {}", wallet_name)),
                ]
                .spacing(20)
            }

            AppState::WalletLoaded { wallet_data, .. } => {
                column![
                    text("Wallet Loaded").size(32),
                    text(format!("Balance: {}", wallet_data.balance)),
                ]
                .spacing(20)
            }

            AppState::Error { message } => {
                column![
                    text("Error").size(32),
                    text(message),
                ]
                .spacing(20)
            }
        };

        container(content)
            .width(iced::Length::Fill)
            .height(iced::Length::Fill)
            .center_x()
            .center_y()
            .into()
    }

    fn theme(&self) -> Self::Theme {
        Theme::Dark
    }
}
