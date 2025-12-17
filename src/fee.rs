//! Fee estimation using mempool.space API with fallback to static defaults
//!
//! Provides real-time fee rate estimates for different confirmation targets.
//! Uses mempool.space for mainnet/testnet/signet, falls back to static defaults for regtest.

use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::RwLock;
use bdk_wallet::bitcoin::Network;

/// Fee estimation errors
#[derive(Debug, thiserror::Error)]
pub enum FeeEstimationError {
    #[error("Network not supported by fee estimation service: {0:?}")]
    UnsupportedNetwork(Network),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("API returned no fee estimates")]
    NoEstimatesAvailable,

    #[error("Fee estimation service timeout after {0}s")]
    Timeout(u64),

    #[error("All fee estimation sources failed")]
    AllSourcesFailed,
}

/// Fee estimate for a specific target
#[derive(Debug, Clone)]
pub struct FeeEstimate {
    pub rate_sat_vb: f64,
    pub target_blocks: u32,
    pub source: FeeSource,
    pub timestamp: Instant,
}

#[derive(Debug, Clone, Copy)]
pub enum FeeSource {
    MempoolSpace,
    Blockstream,
    Default,
}

impl std::fmt::Display for FeeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeeSource::MempoolSpace => write!(f, "mempool.space"),
            FeeSource::Blockstream => write!(f, "blockstream.info"),
            FeeSource::Default => write!(f, "static defaults"),
        }
    }
}

/// Main fee estimator with caching and fallback logic
pub struct FeeEstimator {
    network: Network,
    cache_ttl_secs: u64,
    timeout_secs: u64,
    cache: Arc<RwLock<Option<FeeEstimate>>>,
}

impl FeeEstimator {
    /// Create a new fee estimator
    pub fn new(network: Network, cache_ttl_secs: u64, timeout_secs: u64) -> Self {
        Self {
            network,
            cache_ttl_secs,
            timeout_secs,
            cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Get fee estimate for target confirmation blocks
    ///
    /// # Arguments
    /// * `target_blocks` - Number of blocks for confirmation (e.g., 6)
    ///
    /// # Returns
    /// Fee rate in sat/vB or specific error type for handling by consumers
    pub async fn estimate(&self, target_blocks: u32) -> Result<f64, FeeEstimationError> {
        // Check cache first
        if let Some(cached) = self.get_cached_estimate(target_blocks).await {
            tracing::debug!(
                "Using cached fee estimate: {:.2} sat/vB from {} (age: {}s)",
                cached.rate_sat_vb,
                cached.source,
                cached.timestamp.elapsed().as_secs()
            );
            return Ok(cached.rate_sat_vb);
        }

        // For regtest, always use defaults (no external APIs support it)
        if matches!(self.network, Network::Regtest) {
            let rate = self.get_default_rate(target_blocks);
            tracing::debug!("Using regtest default: {:.2} sat/vB", rate);
            self.cache_estimate(rate, target_blocks, FeeSource::Default).await;
            return Ok(rate);
        }

        // Try mempool.space
        match self.estimate_from_mempool_space(target_blocks).await {
            Ok(rate) => {
                tracing::info!(
                    "Fee estimate from mempool.space: {:.2} sat/vB for {} blocks",
                    rate, target_blocks
                );
                self.cache_estimate(rate, target_blocks, FeeSource::MempoolSpace).await;
                return Ok(rate);
            }
            Err(e) => {
                tracing::warn!("mempool.space fee estimation failed: {}", e);
            }
        }

        // Try blockstream.info (mainnet only)
        if matches!(self.network, Network::Bitcoin) {
            match self.estimate_from_blockstream(target_blocks).await {
                Ok(rate) => {
                    tracing::info!(
                        "Fee estimate from blockstream.info: {:.2} sat/vB for {} blocks",
                        rate, target_blocks
                    );
                    self.cache_estimate(rate, target_blocks, FeeSource::Blockstream).await;
                    return Ok(rate);
                }
                Err(e) => {
                    tracing::warn!("blockstream.info fee estimation failed: {}", e);
                }
            }
        }

        // No sources worked - return error instead of silent fallback
        Err(FeeEstimationError::AllSourcesFailed)
    }

    /// Get cached estimate if valid
    async fn get_cached_estimate(&self, target_blocks: u32) -> Option<FeeEstimate> {
        let cache = self.cache.read().await;
        if let Some(ref estimate) = *cache {
            // Check if cache is still valid
            if estimate.target_blocks == target_blocks
                && estimate.timestamp.elapsed() < Duration::from_secs(self.cache_ttl_secs)
            {
                return Some(estimate.clone());
            }
        }
        None
    }

    /// Cache an estimate
    async fn cache_estimate(&self, rate: f64, target_blocks: u32, source: FeeSource) {
        let mut cache = self.cache.write().await;
        *cache = Some(FeeEstimate {
            rate_sat_vb: rate,
            target_blocks,
            source,
            timestamp: Instant::now(),
        });
    }

    /// Estimate from mempool.space API
    async fn estimate_from_mempool_space(&self, target_blocks: u32) -> Result<f64, FeeEstimationError> {
        let base_url = match self.network {
            Network::Bitcoin => "https://mempool.space/api/v1",
            Network::Testnet => "https://mempool.space/testnet/api/v1",
            Network::Signet => "https://mempool.space/signet/api/v1",
            Network::Regtest => {
                return Err(FeeEstimationError::UnsupportedNetwork(Network::Regtest));
            }
            _ => {
                return Err(FeeEstimationError::UnsupportedNetwork(self.network));
            }
        };

        let url = format!("{}/fees/recommended", base_url);

        // Make HTTP request with timeout
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.timeout_secs))
            .build()?;

        let response = client.get(&url).send().await?;
        let fees: MempoolSpaceFees = response.json().await?;

        // Map target_blocks to mempool.space's fee tiers
        let rate = match target_blocks {
            1 => fees.fastest_fee,
            2..=3 => fees.half_hour_fee,
            4..=6 => fees.hour_fee,
            _ => fees.economy_fee,
        };

        Ok(rate as f64)
    }

    /// Estimate from blockstream.info API (mainnet only)
    async fn estimate_from_blockstream(&self, target_blocks: u32) -> Result<f64, FeeEstimationError> {
        if !matches!(self.network, Network::Bitcoin) {
            return Err(FeeEstimationError::UnsupportedNetwork(self.network));
        }

        let url = "https://blockstream.info/api/fee-estimates";

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.timeout_secs))
            .build()?;

        let response = client.get(url).send().await?;
        let estimates: std::collections::HashMap<String, f64> = response.json().await?;

        // Get estimate for target blocks or closest available
        let key = target_blocks.to_string();
        if let Some(&rate) = estimates.get(&key) {
            return Ok(rate);
        }

        // Find closest target
        let mut closest = None;
        let mut closest_diff = u32::MAX;
        for (k, v) in estimates.iter() {
            if let Ok(blocks) = k.parse::<u32>() {
                let diff = (blocks as i32 - target_blocks as i32).unsigned_abs();
                if diff < closest_diff {
                    closest = Some(*v);
                    closest_diff = diff;
                }
            }
        }

        closest.ok_or(FeeEstimationError::NoEstimatesAvailable)
    }

    /// Get static default rate based on network and target
    fn get_default_rate(&self, target_blocks: u32) -> f64 {
        match self.network {
            Network::Bitcoin => {
                // Mainnet defaults (conservative)
                match target_blocks {
                    1 => 20.0,
                    2..=3 => 10.0,
                    4..=6 => 5.0,
                    _ => 2.0,
                }
            }
            Network::Regtest => {
                // Regtest: always use minimum
                2.0
            }
            _ => {
                // Testnet/Signet: moderate rates
                match target_blocks {
                    1 => 5.0,
                    2..=6 => 2.0,
                    _ => 1.0,
                }
            }
        }
    }

    /// Clear the cache (useful for testing)
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        *cache = None;
    }
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new(Network::Bitcoin, 300, 10)
    }
}

/// mempool.space API response format
#[derive(Debug, Clone, serde::Deserialize)]
struct MempoolSpaceFees {
    #[serde(rename = "fastestFee")]
    fastest_fee: u32,
    #[serde(rename = "halfHourFee")]
    half_hour_fee: u32,
    #[serde(rename = "hourFee")]
    hour_fee: u32,
    #[serde(rename = "economyFee")]
    economy_fee: u32,
    #[serde(rename = "minimumFee")]
    #[allow(dead_code)]
    minimum_fee: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_regtest_defaults() {
        let estimator = FeeEstimator::new(Network::Regtest, 300, 10);

        let rate = estimator.estimate(6).await.unwrap();
        assert_eq!(rate, 2.0);
    }

    #[tokio::test]
    async fn test_mainnet_defaults() {
        let estimator = FeeEstimator::new(Network::Bitcoin, 300, 10);

        // Test fallback defaults (in case APIs are down)
        let rate_fast = estimator.get_default_rate(1);
        let rate_normal = estimator.get_default_rate(6);
        let rate_slow = estimator.get_default_rate(144);

        assert_eq!(rate_fast, 20.0);
        assert_eq!(rate_normal, 5.0);
        assert_eq!(rate_slow, 2.0);
    }

    #[tokio::test]
    async fn test_caching() {
        let estimator = FeeEstimator::new(Network::Regtest, 300, 10);

        // First call
        let rate1 = estimator.estimate(6).await.unwrap();

        // Second call should be cached
        let rate2 = estimator.estimate(6).await.unwrap();

        assert_eq!(rate1, rate2);

        // Check cache exists
        let cache = estimator.cache.read().await;
        assert!(cache.is_some());
    }

    #[tokio::test]
    async fn test_cache_expiry() {
        let estimator = FeeEstimator::new(Network::Regtest, 1, 10); // 1 second TTL

        // First call
        estimator.estimate(6).await.unwrap();

        // Wait for cache to expire
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should get new estimate (not cached)
        let cache_before = estimator.cache.read().await.clone();
        drop(cache_before);

        estimator.estimate(6).await.unwrap();

        let cache_after = estimator.cache.read().await;
        assert!(cache_after.is_some());
        assert!(cache_after.as_ref().unwrap().timestamp.elapsed() < Duration::from_secs(1));
    }
}
