//! Modal dialog system for overlay UI elements

use iced::Element;
use crate::gui::message::Message;
use crate::config::Config;

/// Different types of modal dialogs that can be displayed
#[derive(Debug, Clone)]
pub enum Modal {
    /// Multi-step wallet generation wizard
    GenerateWallet {
        step: GenerateWalletStep,
        data: GenerateWalletData,
    },

    /// Settings dialog
    Settings {
        edited_config: Config,
    },

    /// Open existing wallet dialog (future)
    OpenWallet {
        available_wallets: Vec<String>,
        selected: Option<String>,
    },
}

/// Steps in the wallet generation wizard
#[derive(Debug, Clone, PartialEq)]
pub enum GenerateWalletStep {
    EnterName,
    ReviewAndGenerate,
    DisplayMnemonic,
    VerifyMnemonic,
    Complete,
}

/// Data carried through the wallet generation wizard
#[derive(Debug, Clone)]
pub struct GenerateWalletData {
    pub wallet_name: String,
    pub network: String,
    pub mnemonic: Option<String>,
    pub confirmed_saved: bool,
}

impl GenerateWalletData {
    pub fn new(network: String) -> Self {
        Self {
            wallet_name: String::new(),
            network,
            mnemonic: None,
            confirmed_saved: false,
        }
    }
}

impl Modal {
    /// Render the modal content
    pub fn render(&self) -> Element<'static, Message> {
        match self {
            Modal::GenerateWallet { step, data } => {
                crate::gui::views::modals::generate_wallet_wizard::view(step, data)
            }
            Modal::Settings { edited_config } => {
                crate::gui::views::modals::settings_dialog::view(edited_config)
            }
            Modal::OpenWallet { available_wallets, selected } => {
                // TODO: Implement open wallet dialog
                use iced::widget::{text, container};
                use iced::Length;

                container(text("Open Wallet Dialog (TODO)"))
                    .width(Length::Fixed(400.0))
                    .height(Length::Fixed(300.0))
                    .into()
            }
        }
    }
}
