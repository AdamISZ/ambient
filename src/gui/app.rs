//! Main Iced application

use iced::{Element, Task, Theme};
use iced::widget;

use crate::gui::message::{Message, ManagerWrapper};
use crate::gui::state::AppState;
use crate::gui::modal::Modal;
use crate::config::Config;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Main application struct
pub struct AmbientApp {
    state: AppState,
    config: Config,
    // Active modal dialog (if any)
    active_modal: Option<crate::gui::modal::Modal>,
    // Long-lived Tokio runtime for wallet operations
    tokio_runtime: tokio::runtime::Runtime,
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
        let tokio_runtime = tokio::runtime::Runtime::new()
            .expect("Failed to create Tokio runtime");

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

        // Only poll balance when wallet is loaded
        match &self.state {
            AppState::WalletLoaded { .. } => {
                // Create a stream that emits every 2 seconds
                // Use futures::stream::unfold with manual timing
                iced::Subscription::run_with_id(
                    "balance_poller",
                    iced::futures::stream::unfold(Instant::now(), |last_tick| async move {
                        // Calculate time until next tick
                        let now = Instant::now();
                        let elapsed = now.duration_since(last_tick);
                        let interval = Duration::from_secs(2);

                        if elapsed < interval {
                            // Sleep using async-std which is runtime-agnostic
                            async_std::task::sleep(interval - elapsed).await;
                        }

                        let next_tick = Instant::now();
                        Some((Message::SyncRequested, next_tick))
                    })
                )
            }
            _ => iced::Subscription::none()
        }
    }

    fn handle_message(&mut self, message: Message) -> Task<Message> {
        match message {
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
                // Update selected wallet in the OpenWallet modal
                if let Some(Modal::OpenWallet { available_wallets, selected }) = &mut self.active_modal {
                    *selected = Some(name);
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

            Message::GenerateWalletRequested => {
                // Get the wallet name and network from modal
                if let Some(crate::gui::modal::Modal::GenerateWallet { data, .. }) = &self.active_modal {
                    let name = data.wallet_name.clone();
                    let network = data.network.clone();
                    let recovery_height = self.config.recovery_height;
                    let rt_handle = self.tokio_runtime.handle().clone();

                    // Validate wallet name
                    if name.is_empty() {
                        eprintln!("❌ Wallet name cannot be empty");
                        return Task::none();
                    }

                    println!("🪄 Generating wallet '{}' (recovery_height: {})...", name, recovery_height);

                    // Spawn async task to generate wallet using the LONG-LIVED Tokio runtime
                    // This ensures background auto-sync tasks continue running
                    return Task::perform(
                        async move {
                            rt_handle.spawn(async move {
                                match crate::manager::Manager::generate(&name, &network, recovery_height).await {
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

                    // Close the modal
                    self.active_modal = None;

                    println!("Loading generated wallet '{}'...", name);
                    return Task::done(Message::LoadWalletRequested(name));
                }
                Task::none()
            }

            Message::LoadWalletRequested(wallet_name) => {
                // Load a wallet from disk
                let network = self.config.network.as_str().to_string();
                let name = wallet_name.clone();
                let recovery_height = self.config.recovery_height;
                let rt_handle = self.tokio_runtime.handle().clone();

                println!("📁 Loading wallet '{}' (recovery_height: {})...", name, recovery_height);

                // Spawn async task to load wallet using the LONG-LIVED Tokio runtime
                // This ensures background auto-sync tasks continue running
                Task::perform(
                    async move {
                        rt_handle.spawn(async move {
                            crate::manager::Manager::load(&name, &network, recovery_height).await
                        }).await.unwrap()
                    },
                    move |result| match result {
                        Ok(manager) => {
                            let name = wallet_name.clone();
                            let wrapper = ManagerWrapper(Arc::new(Some(manager)));
                            Message::WalletLoadComplete(Ok((name, wrapper)))
                        }
                        Err(e) => Message::WalletLoadComplete(Err(format!("Failed to load wallet: {}", e))),
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

                        // Wrap manager in Arc<Mutex<>> for shared mutable access
                        let manager = Arc::new(Mutex::new(manager));

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
                        self.state = AppState::Error {
                            message: e,
                        };
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

            Message::WizardNextStep => {
                // Move to next wizard step
                if let Some(crate::gui::modal::Modal::GenerateWallet { step, .. }) = &mut self.active_modal {
                    *step = match step {
                        crate::gui::modal::GenerateWalletStep::EnterName =>
                            crate::gui::modal::GenerateWalletStep::ReviewAndGenerate,
                        crate::gui::modal::GenerateWalletStep::ReviewAndGenerate =>
                            crate::gui::modal::GenerateWalletStep::DisplayMnemonic,
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
                        crate::gui::modal::GenerateWalletStep::ReviewAndGenerate =>
                            crate::gui::modal::GenerateWalletStep::EnterName,
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
                                let mut manager = manager_clone.lock().await;
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

            Message::SyncRequested => {
                // Trigger wallet sync - fetch balance and UTXOs
                // Called both manually (button) and automatically (subscription)
                if let AppState::WalletLoaded { manager, wallet_data } = &mut self.state {
                    wallet_data.is_syncing = true;

                    let manager_clone = manager.clone();
                    let rt_handle = self.tokio_runtime.handle().clone();

                    return Task::perform(
                        async move {
                            rt_handle.spawn(async move {
                                let manager = manager_clone.lock().await;
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
                                let mut manager = manager_clone.lock().await;
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
                                let manager = manager_clone.lock().await;
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
                                let manager = manager_clone.lock().await;
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
                                let manager = manager_clone.lock().await;
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
                    let rt_handle = self.tokio_runtime.handle().clone();

                    println!("📝 Creating SNICKER proposal (index {}, delta {} sats)...", index, delta_sats);

                    return Task::perform(
                        async move {
                            rt_handle.spawn(async move {
                                let mut manager = manager_clone.lock().await;
                                let (proposal, encrypted) = manager.create_snicker_proposal(&opportunity, delta_sats as i64).await?;

                                let tag_hex = ::hex::encode(&proposal.tag);

                                // Serialize the proposal
                                let serialized = manager.serialize_encrypted_proposal(&encrypted);

                                // Write to file named by tag
                                let filename = format!("./{}", tag_hex);
                                tokio::fs::write(&filename, serialized).await?;

                                println!("✅ Proposal created and saved to {}", filename);
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
                    println!("🔍 Scanning for incoming SNICKER proposals (delta range: {} to {} sats)...",
                             min_delta, max_delta);

                    let manager_clone = manager.clone();
                    let rt_handle = self.tokio_runtime.handle().clone();

                    return Task::perform(
                        async move {
                            rt_handle.spawn(async move {
                                let manager = manager_clone.lock().await;
                                manager.scan_for_our_proposals((min_delta, max_delta)).await
                            }).await.unwrap()
                        },
                        |result| match result {
                            Ok(proposals) => {
                                let tags: Vec<String> = proposals.iter()
                                    .map(|p| ::hex::encode(&p.tag))
                                    .collect();
                                println!("✅ Found {} incoming proposals", tags.len());
                                Message::SnickerIncomingProposalsFound(tags)
                            }
                            Err(e) => {
                                eprintln!("❌ Failed to scan proposals: {}", e);
                                Message::SnickerIncomingProposalsFound(Vec::new())
                            }
                        }
                    );
                }
                Task::none()
            }

            Message::SnickerIncomingProposalsFound(tags) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.snicker_incoming_proposals = tags;
                }
                Task::none()
            }

            Message::SnickerProposalTagInputChanged(value) => {
                if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                    wallet_data.snicker_proposal_tag_input = value;
                }
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

            Message::SnickerLoadProposalFromFile(filename) => {
                if let AppState::WalletLoaded { manager, .. } = &self.state {
                    println!("📂 Loading proposal from file: {}", filename);

                    let manager_clone = manager.clone();
                    let rt_handle = self.tokio_runtime.handle().clone();
                    let filename_clone = filename.clone();

                    return Task::perform(
                        async move {
                            rt_handle.spawn(async move {
                                // Read file
                                let contents = tokio::fs::read_to_string(&filename_clone).await?;

                                // Load and store proposal via manager
                                let manager = manager_clone.lock().await;
                                let tag = manager.load_proposal_from_serialized(&contents).await?;

                                Ok(::hex::encode(&tag))
                            }).await.unwrap()
                        },
                        |result: Result<String, anyhow::Error>| match result {
                            Ok(tag_hex) => {
                                println!("✅ Proposal loaded! Tag: {}", tag_hex);
                                Message::SnickerProposalLoaded(Ok(tag_hex))
                            }
                            Err(e) => {
                                eprintln!("❌ Failed to load proposal: {}", e);
                                Message::SnickerProposalLoaded(Err(e.to_string()))
                            }
                        }
                    );
                }
                Task::none()
            }

            Message::SnickerProposalLoaded(result) => {
                match result {
                    Ok(tag_hex) => {
                        // Add the loaded proposal to the incoming list so it shows up with Accept button
                        if let AppState::WalletLoaded { wallet_data, .. } = &mut self.state {
                            if !wallet_data.snicker_incoming_proposals.contains(&tag_hex) {
                                wallet_data.snicker_incoming_proposals.push(tag_hex);
                            }
                        }
                    }
                    Err(_) => {
                        // Error already printed
                    }
                }
                Task::none()
            }

            Message::SnickerAcceptProposal(tag_hex) => {
                if let AppState::WalletLoaded { manager, .. } = &self.state {
                    println!("✅ Accepting SNICKER proposal {}...", tag_hex);

                    let manager_clone = manager.clone();
                    let rt_handle = self.tokio_runtime.handle().clone();

                    // Parse tag from hex
                    let tag_bytes = match ::hex::decode(&tag_hex) {
                        Ok(bytes) if bytes.len() == 8 => {
                            let mut tag = [0u8; 8];
                            tag.copy_from_slice(&bytes);
                            tag
                        }
                        _ => {
                            eprintln!("❌ Invalid proposal tag");
                            return Task::none();
                        }
                    };

                    return Task::perform(
                        async move {
                            rt_handle.spawn(async move {
                                let mut manager = manager_clone.lock().await;
                                // Use the high-level manager method that handles everything
                                manager.accept_and_broadcast_snicker_proposal(&tag_bytes, (-1_000_000, 1_000_000)).await
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
    // Check for presence of core wallet files
    let has_wallet_db = path.join("wallet.sqlite").exists();
    let has_mnemonic = path.join("mnemonic.txt").exists();
    let has_snicker_db = path.join("snicker.sqlite").exists();

    // Directory is a wallet if it has the wallet database or mnemonic
    // (snicker.sqlite alone isn't sufficient as it might be orphaned)
    has_wallet_db || has_mnemonic
}
