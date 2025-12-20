//! Blockchain data access abstraction
//!
//! Provides a unified interface for accessing blockchain data from various sources:
//! - mempool.space API (current implementation)
//! - Bitcoin Core RPC (future)
//! - Other public APIs (future)

use std::time::Duration;
use bdk_wallet::bitcoin::{Network, BlockHash};
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum BlockchainDataError {
    #[error("Network not supported: {0:?}")]
    UnsupportedNetwork(Network),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Block not found at height {0}")]
    BlockNotFound(u32),

    #[error("Invalid block hash returned: {0}")]
    InvalidBlockHash(String),

    #[error("API timeout after {0}s")]
    Timeout(u64),

    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Trait for accessing blockchain data from various sources
#[async_trait::async_trait]
pub trait BlockchainDataProvider: Send + Sync {
    /// Fetch block hash at a specific height
    async fn get_block_hash(&self, height: u32) -> Result<BlockHash, BlockchainDataError>;

    /// Fetch current blockchain tip height
    async fn get_tip_height(&self) -> Result<u32, BlockchainDataError>;

    /// Get fee estimates for a target confirmation blocks
    async fn estimate_fee(&self, target_blocks: u32) -> Result<f64, BlockchainDataError>;
}

/// mempool.space API implementation
pub struct MempoolSpaceApi {
    network: Network,
    timeout_secs: u64,
}

impl MempoolSpaceApi {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            timeout_secs: 10,
        }
    }

    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    fn base_url(&self) -> Result<&'static str, BlockchainDataError> {
        match self.network {
            Network::Bitcoin => Ok("https://mempool.space/api"),
            Network::Testnet => Ok("https://mempool.space/testnet/api"),
            Network::Signet => Ok("https://mempool.space/signet/api"),
            Network::Regtest => Err(BlockchainDataError::UnsupportedNetwork(Network::Regtest)),
            _ => Err(BlockchainDataError::UnsupportedNetwork(self.network)),
        }
    }

    fn client(&self) -> Result<reqwest::Client, BlockchainDataError> {
        Ok(reqwest::Client::builder()
            .timeout(Duration::from_secs(self.timeout_secs))
            .build()?)
    }
}

#[async_trait::async_trait]
impl BlockchainDataProvider for MempoolSpaceApi {
    async fn get_block_hash(&self, height: u32) -> Result<BlockHash, BlockchainDataError> {
        tracing::info!("🌐 [1/5] get_block_hash called for height {}", height);

        let base_url = match self.base_url() {
            Ok(url) => {
                tracing::info!("🌐 [2/5] Base URL: {}", url);
                url
            }
            Err(e) => {
                tracing::error!("❌ Failed to get base URL: {:?}", e);
                return Err(e);
            }
        };

        let url = format!("{}/block-height/{}", base_url, height);
        tracing::info!("🌐 [3/5] Full URL: {}", url);

        let client = match self.client() {
            Ok(c) => {
                tracing::info!("🌐 [4/5] HTTP client created");
                c
            }
            Err(e) => {
                tracing::error!("❌ Failed to create HTTP client: {:?}", e);
                return Err(e);
            }
        };

        tracing::info!("🌐 [5/5] Sending HTTP GET request...");
        let response = match client.get(&url).send().await {
            Ok(r) => {
                tracing::info!("🌐 ✅ Got response!");
                r
            }
            Err(e) => {
                tracing::error!("❌ HTTP request failed: {:?}", e);
                return Err(BlockchainDataError::HttpError(e));
            }
        };

        let status = response.status();
        tracing::info!("🌐 API response status: {}", status);

        if !status.is_success() {
            tracing::error!("❌ API returned error status: {} for URL: {}", status, url);
            return Err(BlockchainDataError::BlockNotFound(height));
        }

        let block_hash_str = response.text().await?;
        tracing::info!("🌐 API returned hash string: '{}'", block_hash_str);

        // Validate it's a valid 64-character hex string
        if block_hash_str.len() != 64 || !block_hash_str.chars().all(|c| c.is_ascii_hexdigit()) {
            tracing::error!("Invalid block hash from API: {}", block_hash_str);
            return Err(BlockchainDataError::InvalidBlockHash(block_hash_str));
        }

        let block_hash = BlockHash::from_str(&block_hash_str)
            .map_err(|e| BlockchainDataError::ParseError(e.to_string()))?;

        tracing::info!("✅ Fetched block hash for height {}: {}", height, block_hash);

        Ok(block_hash)
    }

    async fn get_tip_height(&self) -> Result<u32, BlockchainDataError> {
        let base_url = self.base_url()?;
        let url = format!("{}/v1/blocks/tip/height", base_url);

        tracing::debug!("Fetching tip height from {}", url);

        let client = self.client()?;
        let response = client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(BlockchainDataError::ParseError("Failed to fetch tip height".to_string()));
        }

        let height_str = response.text().await?;
        let height = height_str.trim().parse::<u32>()
            .map_err(|e| BlockchainDataError::ParseError(e.to_string()))?;

        tracing::debug!("Current tip height: {}", height);

        Ok(height)
    }

    async fn estimate_fee(&self, target_blocks: u32) -> Result<f64, BlockchainDataError> {
        let base_url = self.base_url()?;
        let url = format!("{}/v1/fees/recommended", base_url);

        tracing::debug!("Fetching fee estimates from {}", url);

        let client = self.client()?;
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
}

/// mempool.space API response format for fees
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
    #[ignore] // Requires network access
    async fn test_get_block_hash_signet() {
        let api = MempoolSpaceApi::new(Network::Signet);
        let hash = api.get_block_hash(200000).await.unwrap();

        // Verify it's a valid block hash
        assert_eq!(hash.to_string().len(), 64);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_get_tip_height_signet() {
        let api = MempoolSpaceApi::new(Network::Signet);
        let height = api.get_tip_height().await.unwrap();

        // Signet should have blocks
        assert!(height > 0);
    }

    #[tokio::test]
    async fn test_regtest_not_supported() {
        let api = MempoolSpaceApi::new(Network::Regtest);
        let result = api.get_block_hash(0).await;

        assert!(matches!(result, Err(BlockchainDataError::UnsupportedNetwork(_))));
    }
}
