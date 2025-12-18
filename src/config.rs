//! Configuration management for Ambient Wallet
//!
//! Handles loading and saving configuration that is shared between CLI and GUI.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;

/// Default minimum change output size to create (in satoshis)
///
/// Set to 5× the dust limit (546 sats) = 2730 sats.
///
/// Rationale: The dust limit (546 sats) is a Bitcoin Core policy rule that prevents
/// creation of economically unspendable outputs. While technically valid above 546 sats,
/// small UTXOs between 546-2730 sats are still uneconomical to spend in many scenarios:
/// - At 10 sat/vB, spending a P2TR input costs ~580 sats in fees
/// - At 50 sat/vB (high fee environment), it costs ~2900 sats
/// - Creating slightly larger UTXOs (5× dust) provides a safety margin
///
/// For SNICKER proposals, when change would fall below this threshold, we drop the
/// change output entirely and bump the miner fee instead. This keeps the UTXO set
/// smaller and avoids creating economically marginal outputs.
///
/// Note: This applies to ALL SNICKER proposal creation (manual and automated), not just
/// automation. It controls transaction building logic for the final "leftover" amount.
pub const DEFAULT_MIN_CHANGE_OUTPUT_SIZE: u64 = 5 * 546; // 2730 sats

/// Network type for Bitcoin
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Regtest,
    Signet,
    Mainnet,
}

impl Network {
    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Regtest => "regtest",
            Network::Signet => "signet",
            Network::Mainnet => "mainnet",
        }
    }

    pub fn to_bdk_network(&self) -> bdk_wallet::bitcoin::Network {
        match self {
            Network::Regtest => bdk_wallet::bitcoin::Network::Regtest,
            Network::Signet => bdk_wallet::bitcoin::Network::Signet,
            Network::Mainnet => bdk_wallet::bitcoin::Network::Bitcoin,
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Network {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "regtest" => Ok(Network::Regtest),
            "signet" => Ok(Network::Signet),
            "mainnet" | "bitcoin" => Ok(Network::Mainnet),
            _ => Err(anyhow::anyhow!("Invalid network: {}", s)),
        }
    }
}

/// SNICKER automation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AutomationMode {
    /// Disabled - no automation
    Disabled,
    /// Basic mode - automatically accept receiver proposals only
    Basic,
    /// Advanced mode - accept receiver proposals AND create proposer proposals
    Advanced,
}

impl Default for AutomationMode {
    fn default() -> Self {
        AutomationMode::Disabled
    }
}

impl std::fmt::Display for AutomationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AutomationMode::Disabled => write!(f, "Disabled"),
            AutomationMode::Basic => write!(f, "Basic (Auto-Accept)"),
            AutomationMode::Advanced => write!(f, "Advanced (Accept + Create)"),
        }
    }
}

impl std::str::FromStr for AutomationMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "Disabled" => Ok(AutomationMode::Disabled),
            "Basic (Auto-Accept)" => Ok(AutomationMode::Basic),
            "Advanced (Accept + Create)" => Ok(AutomationMode::Advanced),
            _ => Err(anyhow::anyhow!("Invalid automation mode: {}", s)),
        }
    }
}

/// SNICKER automation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnickerAutomation {
    /// Automation mode
    #[serde(default)]
    pub mode: AutomationMode,

    /// Maximum delta (in sats) to auto-accept as receiver
    /// Positive delta = receiver loses money (contributes to fees)
    /// Negative delta = receiver gains money
    /// Example: max_delta = 10000 means auto-accept proposals where we lose up to 10k sats
    #[serde(default = "default_max_delta")]
    pub max_delta: i64,

    /// Maximum proposals to accept per day (rate limiting)
    #[serde(default = "default_max_proposals_per_day")]
    pub max_proposals_per_day: u32,

    /// Prefer proposals that consume SNICKER outputs (creating chains)
    #[serde(default = "default_prefer_snicker_outputs")]
    pub prefer_snicker_outputs: bool,

    /// For proposer mode: only create proposals to SNICKER-pattern transactions
    /// (vs all taproot UTXOs in range)
    #[serde(default = "default_snicker_pattern_only")]
    pub snicker_pattern_only: bool,

    /// Minimum change output size to create (in sats)
    /// Change outputs smaller than this will be dropped (bumping miner fee instead)
    /// Default: 5 × 546 (dust limit) = 2730 sats
    /// Applies to all SNICKER proposal creation (manual and automated)
    #[serde(default = "default_min_change_output_size")]
    pub min_change_output_size: u64,
}

impl Default for SnickerAutomation {
    fn default() -> Self {
        Self {
            mode: AutomationMode::Disabled,
            max_delta: default_max_delta(),
            max_proposals_per_day: default_max_proposals_per_day(),
            prefer_snicker_outputs: default_prefer_snicker_outputs(),
            snicker_pattern_only: default_snicker_pattern_only(),
            min_change_output_size: default_min_change_output_size(),
        }
    }
}

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Bitcoin network to use
    pub network: Network,

    /// Optional single peer to connect to (useful for localhost nodes)
    /// Format: "ip:port" or "hostname:port"
    pub peer: Option<String>,

    /// Directory where wallet data is stored
    pub wallet_dir: PathBuf,

    /// Recovery height - blockchain height to start scanning from when loading/creating wallets
    /// For regtest, use 0. For signet/mainnet, use a recent block height to avoid long sync times.
    #[serde(default = "default_recovery_height")]
    pub recovery_height: u32,

    /// Directory where SNICKER proposals are stored for auto-discovery
    /// Default: ~/.local/share/ambient/{network}/proposals/
    #[serde(default = "default_proposals_dir")]
    pub proposals_directory: PathBuf,

    /// SNICKER automation settings
    #[serde(default)]
    pub snicker_automation: SnickerAutomation,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: Network::Signet,
            peer: None,
            wallet_dir: default_wallet_dir(),
            recovery_height: default_recovery_height(),
            proposals_directory: default_proposals_dir(),
            snicker_automation: SnickerAutomation::default(),
        }
    }
}

impl Config {
    /// Load configuration from file, or create default if it doesn't exist
    pub fn load() -> Result<Self> {
        let config_path = config_file_path()?;

        if config_path.exists() {
            let contents = fs::read_to_string(&config_path)
                .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;

            let config: Config = toml::from_str(&contents)
                .with_context(|| format!("Failed to parse config file: {}", config_path.display()))?;

            tracing::info!("📝 Loaded config from: {}", config_path.display());
            Ok(config)
        } else {
            tracing::info!("📝 No config file found, creating default at: {}", config_path.display());
            let config = Self::default();
            config.save()?;
            Ok(config)
        }
    }

    /// Save configuration to file
    pub fn save(&self) -> Result<()> {
        let config_path = config_file_path()?;

        // Ensure config directory exists
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {}", parent.display()))?;
        }

        let contents = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;

        fs::write(&config_path, contents)
            .with_context(|| format!("Failed to write config file: {}", config_path.display()))?;

        tracing::info!("💾 Saved config to: {}", config_path.display());
        Ok(())
    }

    /// Get the path where wallet data is stored for this network
    pub fn network_wallet_dir(&self) -> PathBuf {
        self.wallet_dir.join(self.network.as_str())
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate peer format if provided
        if let Some(ref peer) = self.peer {
            if !peer.contains(':') {
                return Err(anyhow::anyhow!("Peer must be in format 'host:port', got: {}", peer));
            }
            // Try to parse the port
            let port_str = peer.split(':').last().unwrap();
            port_str.parse::<u16>()
                .with_context(|| format!("Invalid port in peer: {}", peer))?;
        }

        // Validate wallet directory can be created
        if !self.wallet_dir.exists() {
            fs::create_dir_all(&self.wallet_dir)
                .with_context(|| format!("Cannot create wallet directory: {}", self.wallet_dir.display()))?;
        }

        Ok(())
    }
}

/// Get the default wallet directory
fn default_wallet_dir() -> PathBuf {
    directories::ProjectDirs::from("", "", "ambient")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".ambient")
        })
}

/// Get the default recovery height
fn default_recovery_height() -> u32 {
    200_000
}

/// Get the default proposals directory
fn default_proposals_dir() -> PathBuf {
    directories::ProjectDirs::from("", "", "ambient")
        .map(|dirs| dirs.data_local_dir().join("proposals"))
        .unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".local/share/ambient/proposals")
        })
}

/// Get the default max delta for automation (10,000 sats)
fn default_max_delta() -> i64 {
    10_000
}

/// Get the default max proposals per day
fn default_max_proposals_per_day() -> u32 {
    5
}

/// Get the default for prefer_snicker_outputs
fn default_prefer_snicker_outputs() -> bool {
    true
}

/// Get the default for snicker_pattern_only
fn default_snicker_pattern_only() -> bool {
    true
}

/// Get the default minimum change output size (5 × dust limit)
fn default_min_change_output_size() -> u64 {
    DEFAULT_MIN_CHANGE_OUTPUT_SIZE
}

/// Get the configuration file path
fn config_file_path() -> Result<PathBuf> {
    let config_dir = directories::ProjectDirs::from("", "", "ambient")
        .map(|dirs| dirs.config_dir().to_path_buf())
        .unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".config").join("ambient")
        });

    Ok(config_dir.join("config.toml"))
}

/// Get the config file path for display purposes
pub fn get_config_path() -> Result<PathBuf> {
    config_file_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_conversion() {
        assert_eq!(Network::Regtest.as_str(), "regtest");
        assert_eq!(Network::Signet.as_str(), "signet");
        assert_eq!(Network::Mainnet.as_str(), "mainnet");
    }

    #[test]
    fn test_network_from_str() {
        assert_eq!("regtest".parse::<Network>().unwrap(), Network::Regtest);
        assert_eq!("SIGNET".parse::<Network>().unwrap(), Network::Signet);
        assert_eq!("mainnet".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("bitcoin".parse::<Network>().unwrap(), Network::Mainnet);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config {
            network: Network::Regtest,
            peer: Some("localhost:18444".to_string()),
            wallet_dir: PathBuf::from("/tmp/wallets"),
            recovery_height: 0,
            proposals_directory: PathBuf::from("/tmp/proposals"),
            snicker_automation: SnickerAutomation::default(),
        };

        let toml = toml::to_string(&config).unwrap();
        assert!(toml.contains("network = \"regtest\""));
        assert!(toml.contains("peer = \"localhost:18444\""));

        let deserialized: Config = toml::from_str(&toml).unwrap();
        assert_eq!(deserialized.network, Network::Regtest);
        assert_eq!(deserialized.peer, Some("localhost:18444".to_string()));
    }

    #[test]
    fn test_peer_validation() {
        let mut config = Config::default();

        // Valid peer
        config.peer = Some("localhost:18444".to_string());
        assert!(config.validate().is_ok());

        // Invalid peer (no port)
        config.peer = Some("localhost".to_string());
        assert!(config.validate().is_err());

        // Invalid peer (bad port)
        config.peer = Some("localhost:abc".to_string());
        assert!(config.validate().is_err());
    }
}
