//! Main Iced application

use iced::{Element, Task, Theme};
use iced::widget;

use crate::gui::message::{Message, ManagerWrapper};
use crate::gui::state::AppState;
use crate::gui::modal::Modal;
use crate::config::Config;
use std::sync::Arc;
use std::mem::ManuallyDrop;
use tokio::sync::RwLock;

/// Main application struct
pub struct AmbientApp {
    state: AppState,
    config: Config,
    // Active modal dialog (if any)
    active_modal: Option<crate::gui::modal::Modal>,
    // Long-lived Tokio runtime for wallet operations
    // Wrapped in ManuallyDrop to prevent panic on shutdown when dropped from async context
    tokio_runtime: ManuallyDrop<tokio::runtime::Runtime>,
}

impl AmbientApp {
    pub fn new() -> (Self, Task<Message>) {
        // Load configuration (use default if fails)
        let config = Config::load().unwrap_or_else(|e| {
            eprintln!("⚠️  Failed to load config: {}", e);
            eprintln!("    Using default configuration");
            Config::default()
        });

        // Create long-lived Tokio runtime for wallet operations
        let tokio_runtime = ManuallyDrop::new(
            tokio::runtime::Runtime::new()
                .expect("Failed to create Tokio runtime")
        );

        (
            Self {
                state: AppState::new(),
                config,
                active_modal: None,
                tokio_runtime,
            },
            Task::none(),
        )
    }

    pub fn title(&self) -> String {
        String::from("Ambient Wallet")
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        self.handle_message(message)
    }

    pub fn view(&self) -> Element<Message> {
        self.render_view()
    }

    pub fn theme(&self) -> Theme {
        Theme::Dark
    }

    pub fn subscription(&self) -> iced::Subscription<Message> {
        use std::time::{Duration, Instant};
        use iced::futures::StreamExt;

        // Only subscribe to events when wallet is loaded
        match &self.state {
            AppState::WalletLoaded { manager, wallet_data, .. } => {
                // Event-driven blockchain update subscription
                // Subscribes to Kyoto's blockchain events (new blocks, transactions)
                let manager_clone = manager.clone();
                let balance_sub = iced::Subscription::run_with_id(
                    "blockchain_updates",
                    iced::futures::stream::unfold(None, move |mut receiver_opt| {
                        let manager = manager_clone.clone();
                        async move {
                            // Create receiver on first run
                            if receiver_opt.is_none() {
                                let mgr = manager.read().await;
                                let receiver = mgr.subscribe_to_updates();
                                drop(mgr);
                                receiver_opt = Some(receiver);
                            }

                            let receiver = receiver_opt.as_mut().unwrap();

                            // Wait for next blockchain update event with timeout to prevent busy-waiting
                            let result = tokio::time::timeout(
                                Duration::from_millis(100),
                                receiver.recv()
                            ).await;

                            match result {
                                Ok(Ok(update)) => {
                                    // Received an update
                                    Some((Message::BlockchainUpdate(update), receiver_opt))
                                }
                                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                                    // We missed some updates - that's OK, just get the next one
                                    tracing::warn!("Blockchain update subscription lagged by {} events", n);
                                    Some((Message::SyncRequested, receiver_opt))
                                }
                                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                                    // Channel closed - stop subscription
                                    None
                                }
                                Err(_timeout) => {
                                    // Timeout - no update received, sleep briefly and continue
                                    async_std::task::sleep(Duration::from_millis(100)).await;
                                    Some((Message::Noop, receiver_opt))
                                }
                            }
                        }
                    })
                );

                // Automation status subscription (only when running)
                let automation_sub = if wallet_data.automation_running {
                    iced::Subscription::run_with_id(
                        "automation_status",
                        iced::futures::stream::unfold(Instant::now(), |last_tick| async move {
                            let now = Instant::now();
                            let elapsed = now.duration_since(last_tick);
                            let interval = Duration::from_secs(1); // Update UI every second

                            if elapsed < interval {
                                async_std::task::sleep(interval - elapsed).await;
                            }

                            let next_tick = Instant::now();
                            Some((Message::AutomationStatusUpdate, next_tick))
                        })
                    )
                } else {
                    iced::Subscription::none()
                };

                // Combine subscriptions
                iced::Subscription::batch([balance_sub, automation_sub, Self::keyboard_subscription()])
            }
            _ => Self::keyboard_subscription()
        }
    }

    /// Keyboard event subscription for tab navigation
    fn keyboard_subscription() -> iced::Subscription<Message> {
        use iced::keyboard;
        use iced::keyboard::Key;
        use iced::Event;

        iced::event::listen_with(|event, _status, _window| {
            match event {
                Event::Keyboard(keyboard::Event::KeyPressed {
                    key: Key::Named(keyboard::key::Named::Tab),
                    modifiers,
                    ..
                }) => {
                    if modifiers.shift() {
                        Some(Message::ShiftTabPressed)
                    } else {
                        Some(Message::TabPressed)
                    }
                }
                _ => None,
            }
        })
    }

    fn handle_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Noop => {
                // No-op message for subscription throttling
                Task::none()
            }

            Message::OpenModal(modal) => {
                self.active_modal = Some(modal);
                Task::none()
            }

            Message::CloseModal => {
                self.active_modal = None;
                Task::none()
            }

            Message::MenuOpenWallet => {
                // Show custom scrollable wallet list modal
                println!("Menu: Open Wallet clicked");

                // Scan wallet directory for existing wallets
                let wallet_dir = self.config.network_wallet_dir();
                let available_wallets = std::fs::read_dir(&wallet_dir)
                    .ok()
                    .map(|entries| {
                        entries
                            .filter_map(|e| e.ok())
                            .filter(|e| e.file_type().ok().map(|t| t.is_dir()).unwrap_or(false))
                            .filter(|e| is_wallet_directory(&e.path()))
                            .filter_map(|e| e.file_name().into_string().ok())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                self.active_modal = Some(crate::gui::modal::Modal::OpenWallet {
                    available_wallets,
                    selected: None,
                    password: String::new(),
                    error_message: None,
                });

                Task::none()
            }

            Message::MenuCloseWallet => {
                // Close current wallet and return to wallet list
                println!("Menu: Close Wallet clicked");

                // Scan for available wallets
                let wallet_dir = self.config.network_wallet_dir();
                let available_wallets = std::fs::read_dir(&wallet_dir)
                    .ok()
                    .map(|entries| {
                        entries
                            .filter_map(|e| e.ok())
                            .filter(|e| e.file_type().ok().map(|t| t.is_dir()).unwrap_or(false))
                            .filter(|e| is_wallet_directory(&e.path()))
                            .filter_map(|e| e.file_name().into_string().ok())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                // Transition back to NoWallet state
                self.state = AppState::NoWallet {
                    available_wallets,
                };

                Task::none()
            }

            Message::MenuSettings => {
                // Open settings modal
                let modal = crate::gui::modal::Modal::Settings {
                    edited_config: self.config.clone(),
                };
                self.active_modal = Some(modal);
                Task::none()
            }

            Message::MenuExit => {
                // Exit the application
                println!("Menu: Exit clicked");
                std::process::exit(0);
            }

            Message::WalletSelected(name) => {
                // Update selected wallet in the OpenWallet modal and clear error message
                if let Some(Modal::OpenWallet { selected, error_message, .. }) = &mut self.active_modal {
                    *selected = Some(name);
                    *error_message = None; // Clear error when selecting a new wallet
                }
                Task::none()
            }

            Message::CreateWalletRequested => {
                // Open wallet generation wizard modal
                let modal = crate::gui::modal::Modal::GenerateWallet {
                    step: crate::gui::modal::GenerateWalletStep::EnterName,
                    data: crate::gui::modal::GenerateWalletData::new(
                        self.config.network.as_str().to_string()
                    ),
                };
                self.active_modal = Some(modal);
                Task::none()
            }

            Message::WalletNameChanged(name) => {
                // Update wallet name in modal data
                if let Some(crate::gui::modal::Modal::GenerateWallet { data, .. }) = &mut self.active_modal {
                    data.wallet_name = name;
                }
                Task::none()
            }

            Message::WalletPasswordChanged(password) => {
                // Update password in modal data
                if let Some(crate::gui::modal::Modal::GenerateWallet { data, .. }) = &mut self.active_modal {
                    data.password = password;
                }
                Task::none()
            }

            Message::WalletPasswordConfirmChanged(password_confirm) => {
                // Update password confirmation in modal data
                if let Some(crate::gui::modal::Modal::GenerateWallet { data, .. }) = &mut self.active_modal {
                    data.password_confirm = password_confirm;
                }
                Task::none()
            }

            Message::OpenWalletPasswordChanged(password) => {
                // Update password in OpenWallet modal
                if let Some(crate::gui::modal::Modal::OpenWallet { password: ref mut pw, .. }) = &mut self.active_modal {
                    *pw = password;
                }
                Task::none()
            }

            Message::GenerateWalletRequested => {
                // Get the wallet name, network, and password from modal
                if let Some(crate::gui::modal::Modal::GenerateWallet { step, data }) = &mut self.active_modal {
                    let name = data.wallet_name.clone();
                    let network = data.network.clone();
                    let password = data.password.clone();
                    let recovery_height = self.config.recovery_height;
                    let rt_handle = self.tokio_runtime.handle().clone();

                    // Validate wallet name
                    if name.is_empty() {
                        eprintln!("❌ Wallet name cannot be empty");
                        return Task::none();
                    }

                    // Validate password
                    if password.is_empty() {
                        eprintln!("❌ Password cannot be empty");
                        return Task::none();
                    }

                    println!("🪄 Generating wallet '{}' (recovery_height: {})...", name, recovery_height);

                    // Immediately change to Generating step to show loading UI
                    *step = crate::gui::modal::GenerateWalletStep::Generating;

                    // Spawn async task to generate wallet using the LONG-LIVED Tokio runtime
                    // This ensures background auto-sync tasks continue running
                    return Task::perform(
                        async move {
                            rt_handle.spawn(async move {
                                match crate::manager::Manager::generate(&name, &network, recovery_height, &password).await {
                                    Ok((_manager, mnemonic)) => {
                                        // Manager is dropped here, wallet is already saved to disk
                                        Ok((name.clone(), mnemonic.to_string()))
                                    }
                                    Err(e) => Err(format!("Failed to generate wallet: {}", e))
                                }
                            }).await.unwrap()
                        },
                        Message::WalletGenerated
                    );
                }
                Task::none()
            }

            Message::WalletGenerated(result) => {
                match result {
                    Ok((wallet_name, mnemonic)) => {
                        // Update modal to show mnemonic step
                        if let Some(crate::gui::modal::Modal::GenerateWallet { step, data }) = &mut self.active_modal {
                            *step = crate::gui::modal::GenerateWalletStep::DisplayMnemonic;
                            data.mnemonic = Some(mnemonic);
                            println!("✅ Wallet '{}' generated successfully", wallet_name);
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Wallet generation failed: {}", e);
                        // Close modal and show error
                        self.active_modal = None;
                        self.state = AppState::Error {
                            message: e,
                        };
                    }
                }
                Task::none()
            }

            Message::WalletGenerationConfirmed => {
                // User has confirmed they saved the mnemonic
                // Load the wallet we just created
                if let Some(crate::gui::modal::Modal::GenerateWallet { data, .. }) = &self.active_modal {
                    let name = data.wallet_name.clone();
                    let password = data.password.clone();

                    // Close the modal and show loading state
                    self.active_modal = None;
                    self.state = crate::gui::state::AppState::LoadingWallet {
                        wallet_name: name.clone(),
                    };

                    println!("Loading generated wallet '{}'...", name);
                    return Task::done(Message::LoadWalletRequested(name, password));
                }
                Task::none()
            }

            Message::LoadWalletRequested(wallet_name, password) => {
                // Load a wallet from disk using the provided password
                let network = self.config.network.as_str().to_string();
                let name = wallet_name.clone();
                let recovery_height = self.config.recovery_height;
                let rt_handle = self.tokio_runtime.handle().clone();

                // Close modal and set loading state
                self.active_modal = None;
                self.state = crate::gui::state::AppState::LoadingWallet {
                    wallet_name: name.clone(),
                };

                println!("📁 Loading wallet '{}' (recovery_height: {})...", name, recovery_height);

                // Spawn async task to load wallet using the LONG-LIVED Tokio runtime
                // This ensures background auto-sync tasks continue running
                Task::perform(
                    async move {
                        rt_handle.spawn(async move {
                            crate::manager::Manager::load(&name, &network, recovery_height, &password).await
                        }).await.unwrap()
                    },
                    move |result| match result {
                        Ok(manager) => {
                            let name = wallet_name.clone();
                            let wrapper = ManagerWrapper(Arc::new(Some(manager)));
                            Message::WalletLoadComplete(Ok((name, wrapper)))
                        }
                        Err(e) => Message::WalletLoadComplete(Err(format!("{}", e))),
                    }
                )
            }

            Message::WalletLoadComplete(result) => {
                match result {
                    Ok((wallet_name, manager_wrapper)) => {
                        // Extract the manager from the wrapper
                        let manager = Arc::try_unwrap(manager_wrapper.0)
                            .ok()
                            .and_then(|opt| opt)
                            .expect("Failed to unwrap manager");

                        println!("✅ Wallet '{}' loaded", wallet_name);

                        // Wrap manager in Arc<RwLock<>> for shared mutable access
                        let manager = Arc::new(RwLock::new(manager));

                        // Transition to WalletLoaded state
                        self.state = AppState::WalletLoaded {
                            manager,
                            wallet_data: crate::gui::state::WalletData::default(),
                        };

                        // Close the modal
                        self.active_modal = None;

                        // Fetch initial balance
                        return Task::done(Message::SyncRequested);
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to load wallet: {}", e);

                        // Check if it's a password error - if so, reopen modal for retry
                        if e.contains("Wrong password") || e.contains("Encryption") {
                            // Get wallet name from LoadingWallet state
                            let wallet_name = if let AppState::LoadingWallet { wallet_name } = &self.state {
                                Some(wallet_name.clone())
                            } else {
                                None
                            };

                            // Scan for available wallets
                            let wallet_dir = self.config.network_wallet_dir();
                            let available_wallets = std::fs::read_dir(&wallet_dir)
                                .ok()
                                .map(|entries| {
                                    entries
                                        .filter_map(|e| e.ok())
                                        .filter(|e| e.file_type().ok().map(|t| t.is_dir()).unwrap_or(false))
                                        .filter(|e| is_wallet_directory(&e.path()))
                                        .filter_map(|e| e.file_name().into_string().ok())
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default();

                            // Return to NoWallet state and reopen modal with error
                            self.state = AppState::NoWallet {
                                available_wallets: available_wallets.clone(),
                            };

                            self.active_modal = Some(crate::gui::modal::Modal::OpenWallet {
                                available_wallets,
                                selected: wallet_name,
                                password: String::new(),
                                error_message: Some(e),
                            });
                        } else {
                            // Other errors (file not found, etc.) - show error state
                            self.state = AppState::Error {
                                message: e,
                            };
                            self.active_modal = None;
                        }
                    }
                }
                Task::none()
            }

            Message::ViewChanged(view) => {
                // ViewChanged is deprecated - tabs are now handled within WalletData
                // Settings is now a modal, not a view
                // TODO: Remove this message variant or repurpose for tab changes
                println!("ViewChanged message is deprecated: {:?}", view);
                Task::none()
            }

            Message::SettingsNetworkChanged(network_str) => {
                if let Some(crate::gui::modal::Modal::Settings { edited_config }) = &mut self.active_modal {
                    if let Ok(network) = network_str.parse() {
                        edited_config.network = network;
                    }
                }
                Task::none()
            }

            Message::SettingsPeerChanged(peer) => {
                if let Some(crate::gui::modal::Modal::Settings { edited_config }) = &mut self.active_modal {
                    edited_config.peer = if peer.is_empty() {
                        None
                    } else {
                        Some(peer)
                    };
                }
                Task::none()
            }

            Message::SettingsWalletDirChanged(dir) => {
                if let Some(crate::gui::modal::Modal::Settings { edited_config }) = &mut self.active_modal {
                    edited_config.wallet_dir = std::path::PathBuf::from(dir);
                }
                Task::none()
            }

            Message::SettingsRecoveryHeightChanged(height_str) => {
                if let Some(crate::gui::modal::Modal::Settings { edited_config }) = &mut self.active_modal {
                    if let Ok(height) = height_str.parse::<u32>() {
                        edited_config.recovery_height = height;
                    }
                }
                Task::none()
            }

            Message::SettingsProposalsDirChanged(dir) => {
                if let Some(crate::gui::modal::Modal::Settings { edited_config }) = &mut self.active_modal {
                    edited_config.proposals_directory = std::path::PathBuf::from(dir);
                }
                Task::none()
            }

            Message::SettingsMinChangeOutputSizeChanged(size_str) => {
                if let Some(crate::gui::modal::Modal::Settings { edited_config }) = &mut self.active_modal {
                    if let Ok(size) = size_str.parse::<u64>() {
                        edited_config.snicker_automation.min_change_output_size = size;
                    }
                }
                Task::none()
            }

            Message::SettingsSave => {
                if let Some(crate::gui::modal::Modal::Settings { edited_config }) = &self.active_modal {
                    match edited_config.validate() {
                        Ok(_) => {
                            match edited_config.save() {
                                Ok(_) => {
                                    self.config = edited_config.clone();
                                    self.active_modal = None;
                                    println!("✅ Settings saved successfully");
                                }
                                Err(e) => {
                                    eprintln!("❌ Failed to save settings: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("❌ Invalid settings: {}", e);
                        }
                    }
                }
                Task::none()
            }

            Message::SettingsSaved(_result) => {
                // TODO: Handle save result (show success/error message)
                Task::none()
            }

            Message::WizardStepChanged(new_step) => {
                // Update the wizard step in the modal
                if let Some(crate::gui::modal::Modal::GenerateWallet { step, .. }) = &mut self.active_modal {
                    *step = new_step;
                }
                Task::none()
            }

            Message::FocusPasswordConfirmField => {
                // Focus the password confirmation field (for Tab navigation)
                use iced::widget::text_input;
                text_input::focus(text_input::Id::new("password_confirm_field"))
            }

            Message::TabPressed => {
                // Handle Tab key for focus navigation
                use iced::widget::text_input;

                if let Some(modal) = &self.active_modal {
                    match modal {
                        crate::gui::modal::Modal::GenerateWallet { step, .. } => {
                            match step {
                                crate::gui::modal::GenerateWalletStep::EnterName => {
                                    // No additional fields to tab to in this step
                                    Task::none()
                                }
                                crate::gui::modal::GenerateWalletStep::EnterPassword => {
                                    // Tab from password to password_confirm
                                    text_input::focus(text_input::Id::new("password_confirm_field"))
                                }
                                _ => Task::none(),
                            }
                        }
                        crate::gui::modal::Modal::OpenWallet { .. } => {
                            // No additional fields in open wallet dialog
                            Task::none()
                        }
                        _ => Task::none(),
                    }
                } else {
                    Task::none()
                }
            }

            Message::ShiftTabPressed => {
                // Handle Shift+Tab key for reverse focus navigation
                use iced::widget::text_input;

                if let Some(modal) = &self.active_modal {
                    match modal {
                        crate::gui::modal::Modal::GenerateWallet { step, .. } => {
                            match step {
                                crate::gui::modal::GenerateWalletStep::EnterPassword => {
                                    // Shift+Tab from password_confirm back to password
                                    text_input::focus(text_input::Id::new("password_field"))
                                }
                                _ => Task::none(),
                            }
                        }
                        _ => Task::none(),
                    }
                } else {
                    Task::none()
                }
            }

            Message::WizardNextStep => {
                // Move to next wizard step
                if let Some(crate::gui::modal::Modal::GenerateWallet { step, .. }) = &mut self.active_modal {
                    *step = match step {
                        crate::gui::modal::GenerateWalletStep::EnterName =>
                            crate::gui::modal::GenerateWalletStep::EnterPassword,
                        crate::gui::modal::GenerateWalletStep::EnterPassword =>
                            crate::gui::modal::GenerateWalletStep::ReviewAndGenerate,
                        crate::gui::modal::GenerateWalletStep::ReviewAndGenerate =>
                            crate::gui::modal::GenerateWalletStep::Generating,
                        crate::gui::modal::GenerateWalletStep::Generating =>
                            crate::gui::modal::GenerateWalletStep::Generating, // Stay while generating
                        crate::gui::modal::GenerateWalletStep::DisplayMnemonic =>
                            crate::gui::modal::GenerateWalletStep::VerifyMnemonic,
                        crate::gui::modal::GenerateWalletStep::VerifyMnemonic =>
                            crate::gui::modal::GenerateWalletStep::Complete,
                        crate::gui::modal::GenerateWalletStep::Complete =>
                            crate::gui::modal::GenerateWalletStep::Complete, // Stay at complete
                    };
                }
                Task::none()
            }

            Message::WizardPreviousStep => {
                // Move to previous wizard step
                if let Some(crate::gui::modal::Modal::GenerateWallet { step, .. }) = &mut self.active_modal {
                    *step = match step {
                        crate::gui::modal::GenerateWalletStep::EnterName =>
                            crate::gui::modal::GenerateWalletStep::EnterName, // Stay at first
                        crate::gui::modal::GenerateWalletStep::EnterPassword =>
                            crate::gui::modal::GenerateWalletStep::EnterName,
                        crate::gui::modal::GenerateWalletStep::ReviewAndGenerate =>
                            crate::gui::modal::GenerateWalletStep::EnterPassword,
                        crate::gui::modal::GenerateWalletStep::Generating =>
                            crate::gui::modal::GenerateWalletStep::Generating, // Can't go back while generating
                        crate::gui::modal::GenerateWalletStep::DisplayMnemonic =>
                            crate::gui::modal::GenerateWalletStep::ReviewAndGenerate,
                        crate::gui::modal::GenerateWalletStep::VerifyMnemonic =>
                            crate::gui::modal::GenerateWalletStep::DisplayMnemonic,
                        crate::gui::modal::GenerateWalletStep::Complete =>
                            crate::gui::modal::GenerateWalletStep::VerifyMnemonic,
                    };
                }
                Task::none()
            }

            Message::TabChanged(new_tab) => {
                // Change the active tab in WalletLoaded state
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.current_tab = new_tab;
                }
                Task::none()
            }

            Message::CopyToClipboard(text) => {
                println!("📋 Copied to clipboard: {}", text);
                iced::clipboard::write(text)
            }

            Message::NewAddressRequested => {
                // Generate a new address
                if let AppState::WalletLoaded { manager, .. } = &self.state {
                    let manager_clone = manager.clone();
                    let rt_handle = self.tokio_runtime.handle().clone();

                    return Task::perform(
                        async move {
                            rt_handle.spawn(async move {
                                let mut manager = manager_clone.write().await;
                                manager.get_next_address().await
                            }).await.unwrap()
                        },
                        |result| match result {
                            Ok(addr_str) => {
                                match addr_str.parse::<bdk_wallet::bitcoin::Address<bdk_wallet::bitcoin::address::NetworkUnchecked>>() {
                                    Ok(addr) => Message::AddressGenerated(addr.assume_checked()),
                                    Err(e) => {
                                        eprintln!("❌ Failed to parse address: {}", e);
                                        Message::Placeholder
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("❌ Failed to generate address: {}", e);
                                Message::Placeholder
                            }
                        }
                    );
                }
                Task::none()
            }

            Message::AddressGenerated(address) => {
                // Store the generated address
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.last_address = Some(address.to_string());
                    println!("✅ Generated address: {}", address);
                }
                Task::none()
            }

            Message::BlockchainUpdate(update) => {
                // Event-driven update from Kyoto (new block, transaction, etc.)
                if let AppState::WalletLoaded { manager, wallet_data } = &mut self.state {
                    // Update balance with data from event
                    wallet_data.balance = bdk_wallet::bitcoin::Amount::from_sat(update.balance_sats);
                    wallet_data.is_syncing = false; // Clear syncing flag

                    tracing::info!("📊 Blockchain update: height={}, balance={} sats",
                                  update.height, update.balance_sats);

                    // Fetch updated UTXOs list
                    let manager_clone = manager.clone();
                    let rt_handle = self.tokio_runtime.handle().clone();

                    return Task::perform(
                        async move {
                            rt_handle.spawn(async move {
                                let manager = manager_clone.read().await;
                                manager.list_unspent().await
                            }).await.unwrap()
                        },
                        |utxos_result| {
                            let utxos = match utxos_result {
                                Ok(list) => list,
                                Err(e) => {
                                    tracing::error!("Failed to fetch UTXOs: {}", e);
                                    Vec::new()
                                }
                            };
                            Message::WalletDataUpdated {
                                balance: None, // Balance already updated
                                utxos,
                            }
                        }
                    );
                }
                Task::none()
            }

            Message::SyncRequested => {
                // Trigger wallet sync - fetch balance and UTXOs
                // Called both manually (button) and automatically (subscription)
                if let AppState::WalletLoaded { manager, wallet_data } = &mut self.state {
                    // Guard: Skip if already syncing to prevent task accumulation
                    if wallet_data.is_syncing {
                        tracing::debug!("Skipping sync request - already syncing");
                        return Task::none();
                    }

                    wallet_data.is_syncing = true;

                    let manager_clone = manager.clone();
                    let rt_handle = self.tokio_runtime.handle().clone();

                    return Task::perform(
                        async move {
                            rt_handle.spawn(async move {
                                let manager = manager_clone.read().await;
                                let balance = manager.get_balance().await;
                                let utxos = manager.list_unspent().await;
                                (balance, utxos)
                            }).await.unwrap()
                        },
                        |(balance_result, utxos_result)| {
                            // Parse balance
                            let balance = match balance_result {
                                Ok(balance_str) => {
                                    if let Some(sats_part) = balance_str.split_whitespace().next() {
                                        if let Ok(sats) = sats_part.parse::<u64>() {
                                            Some(bdk_wallet::bitcoin::Amount::from_sat(sats))
                                        } else {
                                            eprintln!("❌ Failed to parse balance: {}", balance_str);
                                            None
                                        }
                                    } else {
                                        eprintln!("❌ Invalid balance format: {}", balance_str);
                                        None
                                    }
                                }
                                Err(e) => {
                                    eprintln!("❌ Failed to fetch balance: {}", e);
                                    None
                                }
                            };

                            // Get UTXOs
                            let utxos = match utxos_result {
                                Ok(list) => list,
                                Err(e) => {
                                    eprintln!("❌ Failed to fetch UTXOs: {}", e);
                                    Vec::new()
                                }
                            };

                            Message::WalletDataUpdated { balance, utxos }
                        }
                    );
                }
                Task::none()
            }

            Message::BalanceUpdated(amount) => {
                // Update the displayed balance (legacy - use WalletDataUpdated instead)
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    // Only log if balance actually changed
                    if wallet_data.balance != amount {
                        println!("💰 Balance updated: {} → {}", wallet_data.balance, amount);
                    }
                    wallet_data.balance = amount;
                    wallet_data.is_syncing = false;
                }
                Task::none()
            }

            Message::WalletDataUpdated { balance, utxos } => {
                // Update balance and UTXOs together
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    // Update balance if provided
                    if let Some(amount) = balance {
                        if wallet_data.balance != amount {
                            println!("💰 Balance updated: {} → {}", wallet_data.balance, amount);
                        }
                        wallet_data.balance = amount;
                    }

                    // Update UTXOs
                    wallet_data.utxos = utxos;
                    wallet_data.is_syncing = false;
                }
                Task::none()
            }

            Message::SendAddressChanged(address) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.send_address = address;
                }
                Task::none()
            }

            Message::SendAmountChanged(amount) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.send_amount = amount;
                }
                Task::none()
            }

            Message::SendFeeRateChanged(fee_rate) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.send_fee_rate = fee_rate;
                }
                Task::none()
            }

            Message::SendRequested => {
                // Validate and send transaction
                if let AppState::WalletLoaded { manager, wallet_data } = &mut self.state {
                    let address = wallet_data.send_address.clone();
                    let amount_str = wallet_data.send_amount.clone();
                    let fee_rate_str = wallet_data.send_fee_rate.clone();

                    // Basic validation
                    if address.is_empty() {
                        eprintln!("❌ Address cannot be empty");
                        return Task::none();
                    }
                    if amount_str.is_empty() {
                        eprintln!("❌ Amount cannot be empty");
                        return Task::none();
                    }

                    // Parse amount (expecting BTC value like "0.001")
                    let amount_sats = match amount_str.parse::<f64>() {
                        Ok(btc) => {
                            if btc <= 0.0 {
                                eprintln!("❌ Amount must be positive");
                                return Task::none();
                            }
                            (btc * 100_000_000.0) as u64
                        }
                        Err(_) => {
                            eprintln!("❌ Invalid amount: {}", amount_str);
                            return Task::none();
                        }
                    };

                    // Parse fee rate
                    let fee_rate = match fee_rate_str.parse::<f32>() {
                        Ok(rate) => {
                            if rate <= 0.0 {
                                eprintln!("❌ Fee rate must be positive");
                                return Task::none();
                            }
                            rate
                        }
                        Err(_) => {
                            eprintln!("❌ Invalid fee rate: {}", fee_rate_str);
                            return Task::none();
                        }
                    };

                    println!("📤 Sending transaction:");
                    println!("   To: {}", address);
                    println!("   Amount: {} sats ({} BTC)", amount_sats, amount_str);
                    println!("   Fee rate: {} sat/vB", fee_rate);

                    let manager_clone = manager.clone();
                    let rt_handle = self.tokio_runtime.handle().clone();

                    return Task::perform(
                        async move {
                            rt_handle.spawn(async move {
                                let mut manager = manager_clone.write().await;
                                manager.send_to_address(&address, amount_sats, fee_rate).await
                            }).await.unwrap()
                        },
                        |result| match result {
                            Ok(txid) => Message::TransactionSent(Ok(txid)),
                            Err(e) => Message::TransactionSent(Err(e.to_string())),
                        }
                    );
                }
                Task::none()
            }

            Message::TransactionSent(result) => {
                match result {
                    Ok(txid) => {
                        println!("✅ Transaction sent successfully!");
                        println!("   Txid: {}", txid);

                        // Clear the send form
                        if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                            wallet_data.send_address.clear();
                            wallet_data.send_amount.clear();
                        }

                        // Trigger balance update
                        Task::done(Message::SyncRequested)
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to send transaction: {}", e);
                        Task::none()
                    }
                }
            }

            Message::SnickerScanRequested => {
                if let AppState::WalletLoaded { manager, wallet_data } = &self.state {
                    let blocks = wallet_data.snicker_scan_blocks_input.parse::<u32>().unwrap_or(100);
                    let min_utxo = wallet_data.snicker_scan_min_utxo_input.parse::<u64>().unwrap_or(10_000);
                    let max_utxo = wallet_data.snicker_scan_max_utxo_input.parse::<u64>().unwrap_or(100_000_000);

                    println!("🔍 Scanning for SNICKER candidates (blocks: {}, min: {}, max: {})...",
                             blocks, min_utxo, max_utxo);

                    let manager_clone = manager.clone();
                    let rt_handle = self.tokio_runtime.handle().clone();

                    return Task::perform(
                        async move {
                            rt_handle.spawn(async move {
                                let manager = manager_clone.read().await;
                                manager.scan_for_snicker_candidates(blocks, min_utxo, max_utxo).await
                            }).await.unwrap()
                        },
                        |result| match result {
                            Ok(count) => Message::SnickerScanCompleted(Ok(count)),
                            Err(e) => Message::SnickerScanCompleted(Err(e.to_string())),
                        }
                    );
                }
                Task::none()
            }

            Message::SnickerScanBlocksInputChanged(value) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.snicker_scan_blocks_input = value;
                }
                Task::none()
            }

            Message::SnickerScanMinUtxoInputChanged(value) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.snicker_scan_min_utxo_input = value;
                }
                Task::none()
            }

            Message::SnickerScanMaxUtxoInputChanged(value) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.snicker_scan_max_utxo_input = value;
                }
                Task::none()
            }

            Message::SnickerFindMinUtxoInputChanged(value) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.snicker_find_min_utxo_input = value;
                }
                Task::none()
            }

            Message::SnickerScanCompleted(result) => {
                match result {
                    Ok(count) => {
                        println!("✅ SNICKER scan completed: found {} candidates", count);

                        // Update the candidates count in state
                        if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                            wallet_data.snicker_candidates = count;
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ SNICKER scan failed: {}", e);
                    }
                }
                Task::none()
            }

            Message::SnickerClearCandidates => {
                if let AppState::WalletLoaded { manager, .. } = &self.state {
                    println!("🗑️  Clearing SNICKER candidates...");

                    let manager_clone = manager.clone();
                    let rt_handle = self.tokio_runtime.handle().clone();

                    return Task::perform(
                        async move {
                            rt_handle.spawn(async move {
                                let manager = manager_clone.read().await;
                                manager.clear_snicker_candidates().await
                            }).await.unwrap()
                        },
                        |result| match result {
                            Ok(count) => Message::SnickerCandidatesCleared(Ok(count)),
                            Err(e) => Message::SnickerCandidatesCleared(Err(e.to_string())),
                        }
                    );
                }
                Task::none()
            }

            Message::SnickerCandidatesCleared(result) => {
                match result {
                    Ok(count) => {
                        println!("✅ Cleared {} SNICKER candidates", count);

                        // Reset the candidates count and clear opportunities
                        if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                            wallet_data.snicker_candidates = 0;
                            wallet_data.snicker_opportunities = 0;
                            wallet_data.snicker_opportunities_list.clear();
                            wallet_data.snicker_opportunities_data.clear();
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to clear candidates: {}", e);
                    }
                }
                Task::none()
            }

            Message::SnickerFindOpportunities => {
                if let AppState::WalletLoaded { manager, wallet_data } = &self.state {
                    let min_utxo = wallet_data.snicker_find_min_utxo_input.parse::<u64>().unwrap_or(10_000);

                    println!("🔍 Finding SNICKER opportunities (min UTXO: {})...", min_utxo);

                    let manager_clone = manager.clone();
                    let rt_handle = self.tokio_runtime.handle().clone();

                    return Task::perform(
                        async move {
                            rt_handle.spawn(async move {
                                let manager = manager_clone.read().await;
                                manager.find_snicker_opportunities(min_utxo).await
                            }).await.unwrap()
                        },
                        |result| match result {
                            Ok(opportunities) => {
                                // Format opportunities for display
                                let list: Vec<(usize, String)> = opportunities.iter().enumerate()
                                    .map(|(i, opp)| {
                                        let our_sats = opp.our_value.to_sat();
                                        let target_sats = opp.target_value.to_sat();
                                        let target_txid = opp.target_tx.compute_txid();
                                        let target_vout = opp.target_output_index;
                                        (i, format!("{}. Our: {} sats → Target: {}:{} ({} sats)",
                                                   i, our_sats, target_txid, target_vout, target_sats))
                                    })
                                    .collect();
                                Message::SnickerOpportunitiesFound(opportunities.len(), list, opportunities)
                            }
                            Err(e) => {
                                eprintln!("❌ Failed to find opportunities: {}", e);
                                Message::SnickerOpportunitiesFound(0, Vec::new(), Vec::new())
                            }
                        }
                    );
                }
                Task::none()
            }

            Message::SnickerOpportunitiesFound(count, list, data) => {
                println!("✅ Found {} SNICKER opportunities", count);

                // Update the opportunities count, list, and data in state
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.snicker_opportunities = count;
                    wallet_data.snicker_opportunities_list = list;
                    wallet_data.snicker_opportunities_data = data;
                }
                Task::none()
            }

            Message::SnickerCreateProposal(index, delta_sats) => {
                if let AppState::WalletLoaded { manager, wallet_data, .. } = &mut self.state {
                    // Get the opportunity from stored data
                    if index >= wallet_data.snicker_opportunities_data.len() {
                        eprintln!("❌ Invalid opportunity index");
                        return Task::none();
                    }

                    let opportunity = wallet_data.snicker_opportunities_data[index].clone();
                    let manager_clone = manager.clone();
                    let proposals_dir = self.config.proposals_directory.clone();
                    let rt_handle = self.tokio_runtime.handle().clone();

                    println!("📝 Creating SNICKER proposal (index {}, delta {} sats)...", index, delta_sats);

                    return Task::perform(
                        async move {
                            rt_handle.spawn(async move {
                                let mut manager = manager_clone.write().await;
                                let (proposal, encrypted) = manager.create_snicker_proposal(&opportunity, delta_sats as i64, crate::config::DEFAULT_MIN_CHANGE_OUTPUT_SIZE).await?;

                                let tag_hex = ::hex::encode(&proposal.tag);

                                // Serialize the proposal
                                let serialized = manager.serialize_encrypted_proposal(&encrypted);

                                // Ensure proposals directory exists
                                tokio::fs::create_dir_all(&proposals_dir).await?;

                                // Write to file in proposals directory
                                let filename = proposals_dir.join(&tag_hex);
                                tokio::fs::write(&filename, serialized).await?;

                                println!("✅ Proposal created and saved to {}", filename.display());
                                Ok(tag_hex)
                            }).await.unwrap()
                        },
                        |result: Result<String, anyhow::Error>| match result {
                            Ok(tag_hex) => {
                                Message::SnickerProposalCreated(Ok(tag_hex))
                            }
                            Err(e) => {
                                eprintln!("❌ Failed to create proposal: {}", e);
                                Message::SnickerProposalCreated(Err(e.to_string()))
                            }
                        }
                    );
                }
                Task::none()
            }

            Message::SnickerProposalCreated(result) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    match result {
                        Ok(tag) => {
                            wallet_data.snicker_last_proposal = Some(tag);
                        }
                        Err(_) => {
                            // Error already printed
                        }
                    }
                }
                Task::none()
            }

            Message::SnickerScanIncomingProposals(min_delta, max_delta) => {
                if let AppState::WalletLoaded { manager, .. } = &self.state {
                    println!("🔍 Scanning proposals directory (delta range: {} to {} sats)...",
                             min_delta, max_delta);

                    let manager_clone = manager.clone();
                    let proposals_dir = self.config.proposals_directory.clone();
                    let rt_handle = self.tokio_runtime.handle().clone();

                    return Task::perform(
                        async move {
                            rt_handle.spawn(async move {
                                let mut manager = manager_clone.write().await;
                                manager.scan_proposals_directory(&proposals_dir, (min_delta, max_delta)).await
                            }).await.unwrap()
                        },
                        |result| match result {
                            Ok(proposals) => {
                                println!("✅ Found {} matching proposals", proposals.len());
                                Message::SnickerProposalsScanned(proposals)
                            }
                            Err(e) => {
                                eprintln!("❌ Failed to scan proposals: {}", e);
                                Message::SnickerProposalsScanned(Vec::new())
                            }
                        }
                    );
                }
                Task::none()
            }

            Message::SnickerProposalsScanned(proposals) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.snicker_scanned_proposals = proposals;
                    wallet_data.snicker_selected_proposal = None;
                }
                Task::none()
            }

            Message::SnickerProposalSelected(index) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.snicker_selected_proposal = Some(index);
                }
                Task::none()
            }

            Message::SnickerShowAcceptDialog(index) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &self.state {
                    if let Some(result) = wallet_data.snicker_scanned_proposals.get(index) {
                        self.active_modal = Some(crate::gui::modal::Modal::AcceptProposalConfirmation {
                            proposal_index: index,
                            tag_hex: result.tag_hex.clone(),
                            proposer_input: result.proposer_input.clone(),
                            proposer_value: result.proposer_value,
                            receiver_output_value: result.receiver_output_value,
                            delta: result.delta,
                        });
                    }
                }
                Task::none()
            }

            Message::SnickerConfirmAccept(index) => {
                self.active_modal = None;

                if let AppState::WalletLoaded { manager, wallet_data, .. } = &self.state {
                    if let Some(result) = wallet_data.snicker_scanned_proposals.get(index) {
                        let tag = result.tag;
                        let manager_clone = manager.clone();
                        let rt_handle = self.tokio_runtime.handle().clone();

                        println!("✅ Accepting SNICKER proposal: {}", ::hex::encode(&tag));

                        return Task::perform(
                            async move {
                                rt_handle.spawn(async move {
                                    let mut manager = manager_clone.write().await;
                                    manager.accept_and_broadcast_snicker_proposal(&tag, (-1_000_000, 1_000_000)).await
                                }).await.unwrap()
                            },
                            |result| match result {
                                Ok(txid) => {
                                    println!("✅ SNICKER coinjoin broadcast: {}", txid);
                                    Message::SnickerProposalAccepted(Ok(txid.to_string()))
                                }
                                Err(e) => {
                                    eprintln!("❌ Failed to accept proposal: {}", e);
                                    Message::SnickerProposalAccepted(Err(e.to_string()))
                                }
                            }
                        );
                    }
                }
                Task::none()
            }

            Message::SnickerCancelAccept => {
                self.active_modal = None;
                Task::none()
            }

            Message::SnickerProposalDeltaInputChanged(value) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.snicker_proposal_delta_input = value;
                }
                Task::none()
            }

            Message::SnickerScanMinDeltaInputChanged(value) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.snicker_scan_min_delta_input = value;
                }
                Task::none()
            }

            Message::SnickerScanMaxDeltaInputChanged(value) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.snicker_scan_max_delta_input = value;
                }
                Task::none()
            }

            Message::SnickerProposalAccepted(result) => {
                match result {
                    Ok(txid) => {
                        println!("🎉 SNICKER coinjoin complete! Txid: {}", txid);
                        // Trigger balance update
                        return Task::done(Message::SyncRequested);
                    }
                    Err(_) => {
                        // Error already printed
                    }
                }
                Task::none()
            }

            // Automation handlers
            Message::AutomationStart => {
                if let AppState::WalletLoaded { manager, wallet_data } = &mut self.state {
                    use crate::automation::{AutomationTask, AutomationConfig};
                    use crate::config::SnickerAutomation;

                    // Parse configuration from UI inputs
                    let interval_secs = wallet_data.automation_interval_secs
                        .parse::<u64>()
                        .unwrap_or(10);
                    let max_delta = wallet_data.automation_max_delta
                        .parse::<i64>()
                        .unwrap_or(10_000);
                    let max_per_day = wallet_data.automation_max_per_day
                        .parse::<u32>()
                        .unwrap_or(10);

                    let task_config = AutomationConfig {
                        interval_secs,
                        min_utxo_sats: 75_000, // TODO: Make configurable
                        proposal_delta_sats: 1_000, // TODO: Make configurable
                    };

                    let snicker_config = SnickerAutomation {
                        mode: wallet_data.automation_mode,
                        max_delta,
                        max_proposals_per_day: max_per_day,
                        prefer_snicker_outputs: true,  // Default
                        snicker_pattern_only: true,    // Default
                        min_change_output_size: crate::config::DEFAULT_MIN_CHANGE_OUTPUT_SIZE,
                    };

                    let mode = wallet_data.automation_mode;
                    let manager_clone = manager.clone();
                    let rt_handle = self.tokio_runtime.handle().clone();

                    // Get proposals directory from config
                    let proposals_dir = match crate::config::Config::load() {
                        Ok(cfg) => cfg.proposals_directory,
                        Err(_) => {
                            eprintln!("❌ Failed to load config, using default proposals directory");
                            std::path::PathBuf::from(".local/share/ambient/proposals")
                        }
                    };

                    println!("🤖 Starting SNICKER automation...");
                    println!("   Mode: {:?}", mode);
                    println!("   Max delta: {} sats", max_delta);
                    println!("   Max proposals/day: {}", max_per_day);

                    // Create the task wrapped in Arc<Mutex<>>
                    let task = Arc::new(tokio::sync::Mutex::new(AutomationTask::new()));
                    wallet_data.automation_task = Some(task.clone());

                    // Start the task asynchronously in the tokio runtime context
                    return Task::perform(
                        async move {
                            // Run the start operation in the tokio runtime context
                            rt_handle.spawn(async move {
                                let mut task_guard = task.lock().await;
                                task_guard.start(
                                    manager_clone,
                                    snicker_config,
                                    task_config,
                                    proposals_dir,
                                ).await;
                                println!("✅ Automation started");
                            }).await.map_err(|e| e.to_string())
                        },
                        |result| Message::AutomationStarted(result)
                    );
                }
                Task::none()
            }

            Message::AutomationStop => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    if let Some(task) = wallet_data.automation_task.take() {
                        println!("🛑 Stopping automation...");
                        wallet_data.automation_running = false;

                        let rt_handle = self.tokio_runtime.handle().clone();

                        // Stop the task asynchronously in the tokio runtime context
                        return Task::perform(
                            async move {
                                rt_handle.spawn(async move {
                                    let mut task_guard = task.lock().await;
                                    task_guard.stop().await;
                                }).await.map_err(|e| e.to_string())
                            },
                            |_result| Message::AutomationStopped
                        );
                    }
                }
                Task::none()
            }

            Message::AutomationStarted(result) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    match result {
                        Ok(()) => {
                            println!("✅ Automation running");
                            wallet_data.automation_running = true;
                        }
                        Err(e) => {
                            eprintln!("❌ Automation start failed: {}", e);
                            wallet_data.automation_running = false;
                            wallet_data.automation_task = None;
                        }
                    }
                }
                Task::none()
            }

            Message::AutomationStopped => {
                println!("🛑 Automation stopped");
                Task::none()
            }

            Message::AutomationModeChanged(mode_str) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    use std::str::FromStr;
                    if let Ok(mode) = crate::config::AutomationMode::from_str(&mode_str) {
                        wallet_data.automation_mode = mode;
                    }
                }
                Task::none()
            }

            Message::AutomationMaxDeltaChanged(value) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.automation_max_delta = value;
                }
                Task::none()
            }

            Message::AutomationMaxPerDayChanged(value) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.automation_max_per_day = value;
                }
                Task::none()
            }

            Message::AutomationIntervalChanged(value) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.automation_interval_secs = value;
                }
                Task::none()
            }

            Message::AutomationStatusUpdate => {
                // This is triggered by subscription to update status
                // For now, just refresh the view
                Task::none()
            }

            Message::Placeholder => {
                // No-op for now
                Task::none()
            }

            _ => {
                // TODO: Implement other message handlers
                println!("Unhandled message: {:?}", message);
                Task::none()
            }
        }
    }

    fn render_view(&self) -> Element<Message> {
        use widget::{column, container, text, button};
        use iced::Length;

        // Main content (persistent views based on state)
        let main_view = match &self.state {
            AppState::NoWallet { available_wallets } => {
                crate::gui::views::no_wallet::view(available_wallets)
            }

            AppState::LoadingWallet { wallet_name } => {
                let wallet_name = wallet_name.clone();
                container(
                    column![
                        text("Loading Wallet").size(32),
                        text(format!("Loading '{}'...", wallet_name)).size(20),
                        text("🔐 Decrypting wallet files").size(16),
                        text("⏳ This may take a few seconds...").size(14),
                    ]
                    .spacing(20)
                    .padding(40)
                )
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .into()
            }

            AppState::WalletLoaded { manager, wallet_data } => {
                crate::gui::views::wallet_loaded::view(manager, wallet_data)
            }

            AppState::Error { message } => {
                let message = message.clone();
                container(
                    column![
                        text("Error").size(32),
                        text(message),
                        button("Close").on_press(Message::CloseModal).padding(10),
                    ]
                    .spacing(20)
                    .padding(40)
                )
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .into()
            }
        };

        // Overlay modal if active
        if let Some(ref modal) = self.active_modal {
            crate::gui::widgets::modal_overlay(main_view, modal.render())
        } else {
            main_view
        }
    }
}

// Implement the required traits for running the application
impl Default for AmbientApp {
    fn default() -> Self {
        let (app, _) = Self::new();
        app
    }
}

/// Check if a directory is a valid wallet directory
///
/// A wallet directory should contain at least one of the core wallet files.
/// This can be updated if the wallet structure changes.
fn is_wallet_directory(path: &std::path::Path) -> bool {
    // Check for presence of encrypted wallet files (production)
    let has_encrypted_wallet_db = path.join("wallet.sqlite.enc").exists();
    let has_encrypted_mnemonic = path.join("mnemonic.enc").exists();

    // Also check for unencrypted files (test environments)
    let has_wallet_db = path.join("wallet.sqlite").exists();
    let has_mnemonic = path.join("mnemonic.txt").exists();

    // Directory is a wallet if it has any of the wallet database or mnemonic files
    has_encrypted_wallet_db || has_encrypted_mnemonic || has_wallet_db || has_mnemonic
}
