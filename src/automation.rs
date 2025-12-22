//! SNICKER automation background task runner
//!
//! Provides a background task that periodically scans for and processes
//! SNICKER proposals based on user configuration.

use anyhow::Result;
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
            proposal_delta_sats: 1_000,
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
    /// * `manager` - Arc to the Manager (must be wrapped in Arc<RwLock<Manager>>)
    /// * `snicker_config` - SNICKER automation configuration
    /// * `task_config` - Task runner configuration
    pub async fn start(
        &mut self,
        manager: Arc<RwLock<crate::manager::Manager>>,
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
            tracing::info!("   Max delta: {} sats", snicker_config.max_delta);
            tracing::info!("   Max proposals/day: {}", snicker_config.max_proposals_per_day);

            // Step 1: Initial scan of existing proposals on startup
            {
                let mut mgr = manager.write().await;
                tracing::info!("📂 Initial scan of existing proposals...");
                match mgr.scan_proposals_directory(
                    (i64::MIN, i64::MAX),  // Scan all proposals regardless of delta
                ).await {
                    Ok(results) if !results.is_empty() => {
                        tracing::info!("📥 Found {} existing proposal(s)", results.len());
                    }
                    Ok(_) => {
                        tracing::debug!("No existing proposals");
                    }
                    Err(e) => {
                        tracing::error!("❌ Initial scan failed: {}", e);
                    }
                }
                drop(mgr);
            }

            // Step 2: Subscribe to proposal stream for real-time updates
            let proposal_stream = {
                let mgr = manager.read().await;
                match mgr.network.subscribe_proposals(ProposalFilter::default()).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        tracing::error!("❌ Failed to subscribe to proposals: {}", e);
                        tracing::info!("🤖 SNICKER automation task stopped");
                        return;
                    }
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

                                let mut mgr = manager.write().await;

                                // Process and check if it's valid for us
                                let delta_range = (i64::MIN, snicker_config.max_delta);
                                match mgr.process_incoming_proposal(&proposal, delta_range).await {
                                    Ok(Some(scan_result)) => {
                                        tracing::info!("✅ Valid proposal {} (delta: {} sats)",
                                                 hex::encode(&scan_result.tag), scan_result.delta);

                                        // Auto-accept if enabled
                                        match mgr.auto_accept_proposals(&snicker_config).await {
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

                                drop(mgr);
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
                            tracing::debug!("🔄 Running auto-create cycle");

                            let mut mgr = manager.write().await;

                            match mgr.auto_create_proposals(
                                &snicker_config,
                                task_config.min_utxo_sats,
                                task_config.proposal_delta_sats,
                            ).await {
                                Ok(count) if count > 0 => {
                                    tracing::info!("✅ Auto-created {} proposal(s)", count);
                                }
                                Ok(_) => {
                                    tracing::debug!("No proposals to create");
                                }
                                Err(e) => {
                                    tracing::error!("❌ Auto-create failed: {}", e);
                                }
                            }

                            drop(mgr);
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

    /// Stop the automation task
    pub async fn stop(&mut self) {
        if !self.is_running() {
            tracing::warn!("Automation task not running");
            return;
        }

        // Set cancel flag
        *self.cancel_flag.write().await = true;

        // Wait for task to finish
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }
    }

    /// Check if the automation task is currently running
    pub fn is_running(&self) -> bool {
        self.task_handle.as_ref().map_or(false, |h| !h.is_finished())
    }

    /// Get the current status as a string
    pub fn status(&self) -> &'static str {
        if self.is_running() {
            "Running"
        } else {
            "Stopped"
        }
    }
}

impl Drop for AutomationTask {
    fn drop(&mut self) {
        // Abort the task if it's still running
        if let Some(handle) = self.task_handle.take() {
            handle.abort();
        }
    }
}
