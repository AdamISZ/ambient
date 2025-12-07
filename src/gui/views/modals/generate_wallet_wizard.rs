//! Generate wallet wizard modal

use iced::{Element, Length};
use iced::widget::{column, container, text, button, text_input, row, scrollable};

use crate::gui::message::Message;
use crate::gui::modal::{GenerateWalletStep, GenerateWalletData};

/// Render the wallet generation wizard
pub fn view(step: &GenerateWalletStep, data: &GenerateWalletData) -> Element<'static, Message> {
    // Clone data for 'static lifetime
    let wallet_name = data.wallet_name.clone();
    let network = data.network.clone();
    let mnemonic = data.mnemonic.clone();

    let content = match step {
        GenerateWalletStep::EnterName => view_enter_name(&wallet_name, &network),
        GenerateWalletStep::ReviewAndGenerate => view_review_and_generate(&wallet_name, &network),
        GenerateWalletStep::DisplayMnemonic => view_display_mnemonic(&wallet_name, mnemonic.as_deref()),
        GenerateWalletStep::VerifyMnemonic => view_verify_mnemonic(),
        GenerateWalletStep::Complete => view_complete(),
    };

    container(content)
        .width(Length::Fixed(700.0))
        .into()
}

/// Step 1: Enter wallet name
fn view_enter_name(wallet_name: &str, network: &str) -> Element<'static, Message> {
    let wallet_name_owned = wallet_name.to_string();
    let network_owned = network.to_string();

    column![
        text("Create New Wallet").size(32),
        text("Step 1: Enter Wallet Name").size(20),

        column![
            text("Wallet Name").size(16),
            text("Choose a unique name for your wallet").size(12),
            text_input("Enter wallet name", wallet_name)
                .on_input(Message::WalletNameChanged)
                .width(Length::Fixed(500.0))
        ].spacing(5),

        column![
            text("Network").size(16),
            text(network_owned).size(14),
        ].spacing(5),

        row![
            button("Cancel")
                .on_press(Message::CloseModal)
                .padding(10),
            button("Next")
                .on_press(Message::WizardStepChanged(GenerateWalletStep::ReviewAndGenerate))
                .padding(10),
        ]
        .spacing(10)
    ]
    .spacing(20)
    .padding(30)
    .into()
}

/// Step 2: Review and generate
fn view_review_and_generate(wallet_name: &str, network: &str) -> Element<'static, Message> {
    let wallet_name = wallet_name.to_string();
    let network = network.to_string();

    column![
        text("Create New Wallet").size(32),
        text("Step 2: Review and Generate").size(20),

        column![
            text("Review your wallet settings:").size(16),
            text(format!("Wallet Name: {}", wallet_name)).size(14),
            text(format!("Network: {}", network)).size(14),
        ].spacing(5),

        container(
            column![
                text("⚠️ Important Information").size(18),
                text("• A recovery seed (mnemonic) will be generated").size(14),
                text("• You MUST save this seed in a secure location").size(14),
                text("• This seed is the ONLY way to recover your wallet").size(14),
                text("• Never share your seed with anyone").size(14),
            ].spacing(5)
        )
        .padding(15),

        row![
            button("Back")
                .on_press(Message::WizardStepChanged(GenerateWalletStep::EnterName))
                .padding(10),
            button("Generate Wallet")
                .on_press(Message::GenerateWalletRequested)
                .padding(10),
        ]
        .spacing(10)
    ]
    .spacing(20)
    .padding(30)
    .into()
}

/// Step 3: Display mnemonic
fn view_display_mnemonic(wallet_name: &str, mnemonic: Option<&str>) -> Element<'static, Message> {
    let wallet_name = wallet_name.to_string();

    let mnemonic_display = if let Some(mnemonic_str) = mnemonic {
        let mnemonic_str = mnemonic_str.to_string();
        let words: Vec<String> = mnemonic_str.split_whitespace()
            .map(|s| s.to_string())
            .collect();

        // Display words in a grid
        let mut word_grid = column![].spacing(10);
        for (chunk_idx, chunk) in words.chunks(4).enumerate() {
            let row_content: Vec<Element<'static, Message>> = chunk.iter().enumerate()
                .map(|(i, word)| {
                    let index = (chunk_idx * 4) + i + 1;
                    let word_owned = word.clone();
                    container(
                        column![
                            text(format!("{}.", index)).size(12),
                            text(word_owned).size(16),
                        ].spacing(2)
                    )
                    .padding(10)
                    .width(Length::Fixed(120.0))
                    .into()
                })
                .collect();

            word_grid = word_grid.push(row(row_content).spacing(10));
        }

        column![
            text("✅ Wallet Generated Successfully!").size(20),
            text(format!("Wallet: {}", wallet_name)).size(14),

            container(
                column![
                    text("🔑 Your Recovery Seed").size(18),
                    text("Write down these words in order and store them safely").size(12),
                    word_grid,
                ].spacing(10)
            )
            .padding(20),

            container(
                column![
                    text("⚠️ CRITICAL WARNING").size(18),
                    text("• Write this seed on paper and store it securely").size(14),
                    text("• Do NOT store it digitally (no screenshots, no files)").size(14),
                    text("• Anyone with this seed can access your funds").size(14),
                    text("• If you lose this seed, your funds are GONE FOREVER").size(14),
                ].spacing(5)
            )
            .padding(15),

            button("I have saved my recovery seed")
                .on_press(Message::WalletGenerationConfirmed)
                .padding(10),
        ].spacing(20)
    } else {
        column![
            text("Generating wallet...").size(20),
            text("Please wait...").size(14),
        ].spacing(10)
    };

    container(
        scrollable(
            mnemonic_display.padding(30)
        )
    )
    .into()
}

/// Step 4: Verify mnemonic (optional - not currently used)
fn view_verify_mnemonic() -> Element<'static, Message> {
    column![
        text("Verify Your Seed").size(32),
        text("Step 4: Verification (Optional)").size(20),
        text("Verification step coming soon...").size(14),
        button("Skip")
            .on_press(Message::WizardStepChanged(GenerateWalletStep::Complete))
            .padding(10),
    ]
    .spacing(20)
    .padding(30)
    .into()
}

/// Step 5: Complete (not currently used - we load wallet directly)
fn view_complete() -> Element<'static, Message> {
    column![
        text("Wallet Created!").size(32),
        text("Your wallet has been created successfully").size(16),
        button("Open Wallet")
            .on_press(Message::CloseModal)
            .padding(10),
    ]
    .spacing(20)
    .padding(30)
    .into()
}
