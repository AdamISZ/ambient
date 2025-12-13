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
    /// * `proposals_dir` - Directory to scan for incoming proposals
    pub async fn start(
        &mut self,
        manager: Arc<RwLock<crate::manager::Manager>>,
        snicker_config: crate::config::SnickerAutomation,
        task_config: AutomationConfig,
        proposals_dir: std::path::PathBuf,
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
            tracing::info!("🤖 SNICKER automation task started");
            tracing::info!("   Mode: {:?}", snicker_config.mode);
            tracing::info!("   Interval: {} seconds", task_config.interval_secs);
            tracing::info!("   Max delta: {} sats", snicker_config.max_delta);
            tracing::info!("   Max proposals/day: {}", snicker_config.max_proposals_per_day);

            let mut interval = tokio::time::interval(Duration::from_secs(task_config.interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                // Wait for next tick OR cancellation (whichever comes first)
                tokio::select! {
                    _ = interval.tick() => {
                        // Time for next automation cycle
                    }
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

                // Double-check cancel flag after tick (in case it was set during work)
                if *cancel_flag.read().await {
                    tracing::info!("🛑 Automation task cancelled");
                    break;
                }

                // Check if automation is disabled
                if snicker_config.mode == AutomationMode::Disabled {
                    tracing::debug!("Automation disabled, skipping");
                    continue;
                }

                tracing::debug!("🔄 Running automation cycle");

                // Get manager lock
                let mut mgr = manager.write().await;

                // Step 1: Scan proposals directory for new proposals
                // This loads and decrypts any new proposals into the database
                match mgr.scan_proposals_directory(
                    &proposals_dir,
                    (i64::MIN, i64::MAX),  // Scan all proposals regardless of delta
                ).await {
                    Ok(results) if !results.is_empty() => {
                        tracing::info!("📥 Found {} new proposal(s) in directory", results.len());
                    }
                    Ok(_) => {
                        tracing::debug!("No new proposals in directory");
                    }
                    Err(e) => {
                        tracing::error!("❌ Directory scan failed: {}", e);
                    }
                }

                // Step 2: Run auto-accept (works in both Basic and Advanced modes)
                match mgr.auto_accept_proposals(&snicker_config).await {
                    Ok(count) if count > 0 => {
                        tracing::info!("✅ Auto-accepted {} proposals", count);
                    }
                    Ok(_) => {
                        tracing::debug!("No proposals to accept");
                    }
                    Err(e) => {
                        tracing::error!("❌ Auto-accept failed: {}", e);
                    }
                }

                // Step 3: Run auto-create (only in Advanced mode)
                if snicker_config.mode == AutomationMode::Advanced {
                    match mgr.auto_create_proposals(
                        &snicker_config,
                        task_config.min_utxo_sats,
                        task_config.proposal_delta_sats,
                    ).await {
                        Ok(count) if count > 0 => {
                            tracing::info!("✅ Auto-created {} proposals", count);
                        }
                        Ok(_) => {
                            tracing::debug!("No proposals to create");
                        }
                        Err(e) => {
                            tracing::error!("❌ Auto-create failed: {}", e);
                        }
                    }
                }

                // Release lock
                drop(mgr);
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
