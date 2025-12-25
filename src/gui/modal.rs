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
        wallet_loaded: bool,
    },

    /// Open existing wallet dialog
    OpenWallet {
        available_wallets: Vec<String>,
        selected: Option<String>,
        password: String,
        error_message: Option<String>,
    },

    /// Accept SNICKER proposal confirmation dialog
    AcceptProposalConfirmation {
        proposal_index: usize,
        tag_hex: String,
        proposer_input: String,
        proposer_value: u64,
        receiver_output_value: u64,
        delta: i64,
    },
}

/// Steps in the wallet generation wizard
#[derive(Debug, Clone, PartialEq)]
pub enum GenerateWalletStep {
    EnterName,
    EnterPassword,
    ReviewAndGenerate,
    Generating,
    DisplayMnemonic,
    VerifyMnemonic,
    Complete,
}

/// Data carried through the wallet generation wizard
pub struct GenerateWalletData {
    pub wallet_name: String,
    pub network: String,
    pub password: String,
    pub password_confirm: String,
    pub mnemonic: Option<String>,
    pub confirmed_saved: bool,
    pub generated_manager: Option<crate::manager::Manager>,
}

impl std::fmt::Debug for GenerateWalletData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerateWalletData")
            .field("wallet_name", &self.wallet_name)
            .field("network", &self.network)
            .field("password", &"<redacted>")
            .field("password_confirm", &"<redacted>")
            .field("mnemonic", &self.mnemonic.as_ref().map(|_| "<redacted>"))
            .field("confirmed_saved", &self.confirmed_saved)
            .field("generated_manager", &self.generated_manager.as_ref().map(|_| "<manager>"))
            .finish()
    }
}

impl Clone for GenerateWalletData {
    fn clone(&self) -> Self {
        Self {
            wallet_name: self.wallet_name.clone(),
            network: self.network.clone(),
            password: self.password.clone(),
            password_confirm: self.password_confirm.clone(),
            mnemonic: self.mnemonic.clone(),
            confirmed_saved: self.confirmed_saved,
            generated_manager: None, // Manager can't be cloned - leave as None
        }
    }
}

impl GenerateWalletData {
    pub fn new(network: String) -> Self {
        Self {
            wallet_name: String::new(),
            network,
            password: String::new(),
            password_confirm: String::new(),
            mnemonic: None,
            confirmed_saved: false,
            generated_manager: None,
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
            Modal::Settings { edited_config, wallet_loaded } => {
                crate::gui::views::modals::settings_dialog::view(edited_config, *wallet_loaded)
            }
            Modal::OpenWallet { available_wallets, selected, password, error_message } => {
                crate::gui::views::modals::open_wallet_dialog::view(available_wallets, selected, password, error_message)
            }
            Modal::AcceptProposalConfirmation {
                proposal_index,
                tag_hex,
                proposer_input,
                proposer_value,
                receiver_output_value,
                delta,
            } => {
                crate::gui::views::modals::accept_proposal_dialog::view(
                    *proposal_index,
                    tag_hex,
                    proposer_input,
                    *proposer_value,
                    *receiver_output_value,
                    *delta,
                )
            }
        }
    }
}
