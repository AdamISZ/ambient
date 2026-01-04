//! SNICKER automation background task runner
//!
//! Provides a background task that periodically scans for and processes
//! SNICKER proposals based on user configuration.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

/// Automation task configuration
#[derive(Debug, Clone)]
pub struct AutomationConfig {
    /// How often to run automation (in seconds)
    pub interval_secs: u64,
    /// Minimum UTXO size for creating proposals (in sats)
    pub min_utxo_sats: u64,
    /// Delta to use when creating proposals (in sats)
    pub proposal_delta_sats: i64,
}

impl Default for AutomationConfig {
    fn default() -> Self {
        Self {
            interval_secs: 10,  // 10 seconds (for testing - change back to 300 for production)
            min_utxo_sats: 75_000,
            proposal_delta_sats: 100,  // Low default allows ~25 coinjoins/day with 2500 daily limit
        }
    }
}

/// Background automation task runner
pub struct AutomationTask {
    /// Handle to the running task
    task_handle: Option<JoinHandle<()>>,
    /// Flag to signal task cancellation
    cancel_flag: Arc<RwLock<bool>>,
}

impl AutomationTask {
    /// Create a new automation task (not yet started)
    pub fn new() -> Self {
        Self {
            task_handle: None,
            cancel_flag: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the automation task
    ///
    /// # Arguments
    /// * `manager` - Arc to the Manager (internal mutability via Mutex fields)
    /// * `snicker_config` - SNICKER automation configuration
    /// * `task_config` - Task runner configuration
    pub async fn start(
        &mut self,
        manager: Arc<crate::manager::Manager>,
        snicker_config: crate::config::SnickerAutomation,
        task_config: AutomationConfig,
    ) {
        use crate::config::AutomationMode;

        // If already running, don't start again
        if self.is_running() {
            tracing::warn!("Automation task already running");
            return;
        }

        // Reset cancel flag
        let cancel_flag = self.cancel_flag.clone();
        *cancel_flag.write().await = false;

        let handle = tokio::spawn(async move {
            use futures::StreamExt;
            use crate::network::ProposalFilter;

            tracing::info!("🤖 SNICKER automation task started (pub-sub mode)");
            tracing::info!("   Mode: {:?}", snicker_config.mode);
            tracing::info!("   Max sats/coinjoin: {}", snicker_config.max_sats_per_coinjoin);
            tracing::info!("   Max sats/day: {}", snicker_config.max_sats_per_day);
            tracing::info!("   Max sats/week: {}", snicker_config.max_sats_per_week);
            tracing::info!("   Outstanding proposals target: {}", snicker_config.outstanding_proposals);
            tracing::info!("   Receiver timeout: {} blocks", snicker_config.receiver_timeout_blocks);

            // Clone network Arc - allows network operations without blocking Manager
            let network = manager.network.clone();

            // Step 0: Initialize automation state if needed
            {
                let current_height = manager.get_tip_height().await.unwrap_or(0);
                match manager.snicker.initialize_automation_state(current_height) {
                    Ok(true) => {
                        tracing::info!("📊 Initialized automation state at height {}", current_height);
                    }
                    Ok(false) => {
                        let state = manager.snicker.get_automation_state();
                        tracing::info!(
                            "📊 Automation state: {} mode (last coinjoin at height {})",
                            state.role, state.last_coinjoin_height
                        );
                    }
                    Err(e) => {
                        tracing::error!("❌ Failed to initialize automation state: {}", e);
                    }
                }
            }

            // Step 1: Initial scan - fetch proposals WITHOUT holding Manager lock
            tracing::info!("📂 Initial scan of existing proposals...");
            match network.fetch_proposals(ProposalFilter::default()).await {
                Ok(proposals) if !proposals.is_empty() => {
                    tracing::info!("📥 Fetched {} proposal(s) from network, processing...", proposals.len());
                    let mut processed = 0;
                    for proposal in proposals {
                        let delta_range = (i64::MIN, i64::MAX);
                        if manager.process_incoming_proposal(&proposal, delta_range).await.is_ok() {
                            processed += 1;
                        }
                    }
                    tracing::info!("📥 Processed {} proposal(s)", processed);
                }
                Ok(_) => {
                    tracing::debug!("No existing proposals");
                }
                Err(e) => {
                    tracing::error!("❌ Initial scan failed: {}", e);
                }
            }

            // Step 2: Subscribe to proposal stream WITHOUT holding Manager lock
            let proposal_stream = match network.subscribe_proposals(ProposalFilter::default()).await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::error!("❌ Failed to subscribe to proposals: {}", e);
                    tracing::info!("🤖 SNICKER automation task stopped");
                    return;
                }
            };

            // Step 3: Set up auto-create interval (Advanced mode only)
            let mut auto_create_interval = tokio::time::interval(Duration::from_secs(task_config.interval_secs));
            auto_create_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            // Pin the stream for select! macro
            tokio::pin!(proposal_stream);

            // Main event loop: process proposals and run auto-create
            loop {
                tokio::select! {
                    // New proposal arrived on the stream
                    Some(result) = proposal_stream.next() => {
                        // Check cancel flag
                        if *cancel_flag.read().await {
                            tracing::info!("🛑 Automation task cancelled");
                            break;
                        }

                        // Check if automation is disabled
                        if snicker_config.mode == AutomationMode::Disabled {
                            tracing::debug!("Automation disabled, skipping incoming proposal");
                            continue;
                        }

                        // Process the incoming proposal
                        match result {
                            Ok(proposal) => {
                                tracing::debug!("📨 Received proposal: {}", hex::encode(&proposal.tag));

                                let delta_range = (i64::MIN, snicker_config.max_sats_per_coinjoin as i64);

                                match manager.process_incoming_proposal(&proposal, delta_range).await {
                                    Ok(Some(scan_result)) => {
                                        tracing::info!("✅ Valid proposal {} (delta: {} sats)",
                                                 hex::encode(&scan_result.tag), scan_result.delta);

                                        // Auto-accept if enabled
                                        match manager.auto_accept_proposals(&snicker_config).await {
                                            Ok(count) if count > 0 => {
                                                tracing::info!("✅ Auto-accepted {} proposal(s)", count);
                                            }
                                            Err(e) => {
                                                tracing::error!("❌ Auto-accept failed: {}", e);
                                            }
                                            _ => {}
                                        }
                                    }
                                    Ok(None) => {
                                        tracing::debug!("Proposal not for us or outside delta range");
                                    }
                                    Err(e) => {
                                        tracing::debug!("Failed to process proposal: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Failed to receive proposal: {}", e);
                            }
                        }
                    }

                    // Auto-create interval tick (Advanced mode only)
                    _ = auto_create_interval.tick() => {
                        // Check cancel flag
                        if *cancel_flag.read().await {
                            tracing::info!("🛑 Automation task cancelled");
                            break;
                        }

                        // Only run auto-create in Advanced mode
                        if snicker_config.mode == AutomationMode::Advanced {
                            // Check automation state - only create proposals in Proposer role
                            let automation_state = manager.snicker.get_automation_state();

                            // Check receiver timeout and reroll if needed
                            if automation_state.role == crate::snicker::AutomationRole::Receiver {
                                let current_height = manager.get_tip_height().await.unwrap_or(0);
                                match manager.snicker.check_receiver_timeout(
                                    current_height,
                                    snicker_config.receiver_timeout_blocks,
                                ) {
                                    Ok(Some(new_role)) => {
                                        tracing::info!("🎲 Receiver timeout - rerolled to {:?}", new_role);
                                    }
                                    Ok(None) => {
                                        // Still in receiver mode, no timeout yet
                                        tracing::debug!("📥 In Receiver mode, waiting for incoming proposals");
                                    }
                                    Err(e) => {
                                        tracing::error!("❌ Failed to check receiver timeout: {}", e);
                                    }
                                }
                                continue;
                            }

                            // In Proposer role - maintain N outstanding proposals
                            let outstanding = manager.snicker.count_outstanding_proposals();
                            let target = snicker_config.outstanding_proposals as usize;

                            if outstanding >= target {
                                tracing::debug!(
                                    "📊 Have {} outstanding proposals (target: {}), skipping",
                                    outstanding, target
                                );
                                continue;
                            }

                            let proposals_to_create = target - outstanding;
                            tracing::debug!(
                                "📊 Have {} outstanding proposals, creating {} more (target: {})",
                                outstanding, proposals_to_create, target
                            );

                            // Create proposals to reach target
                            for _ in 0..proposals_to_create {
                                match manager.auto_create_proposals(
                                    &snicker_config,
                                    task_config.min_utxo_sats,
                                    task_config.proposal_delta_sats,
                                ).await {
                                    Ok(count) if count > 0 => {
                                        tracing::info!("✅ Auto-created {} proposal(s)", count);
                                    }
                                    Ok(_) => {
                                        tracing::debug!("No proposals to create (no opportunities)");
                                        break; // No point continuing if no opportunities
                                    }
                                    Err(e) => {
                                        tracing::error!("❌ Auto-create failed: {}", e);
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    // Cancellation signal
                    _ = async {
                        // Poll cancel flag every 100ms for responsive shutdown
                        loop {
                            if *cancel_flag.read().await {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    } => {
                        tracing::info!("🛑 Automation task cancelled");
                        break;
                    }
                }
            }

            tracing::info!("🤖 SNICKER automation task stopped");
        });

        self.task_handle = Some(handle);
    }

    /// Check if the automation task is running
    pub fn is_running(&self) -> bool {
        self.task_handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or(false)
    }

    /// Get the status of the automation task as a string
    pub fn status(&self) -> &'static str {
        if self.is_running() {
            "Running"
        } else {
            "Stopped"
        }
    }

    /// Stop the automation task
    pub async fn stop(&mut self) {
        // Set cancel flag
        *self.cancel_flag.write().await = true;

        // Wait for task to finish
        if let Some(handle) = self.task_handle.take() {
            // Give it a moment to finish gracefully
            tokio::time::sleep(Duration::from_millis(200)).await;

            // If still running, abort it
            if !handle.is_finished() {
                handle.abort();
            }
        }
    }
}

impl Default for AutomationTask {
    fn default() -> Self {
        Self::new()
    }
}
