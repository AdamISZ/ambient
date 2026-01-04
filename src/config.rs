//! Configuration management for Ambient Wallet
//!
//! Handles loading and saving configuration that is shared between CLI and GUI.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;

/// Minimum UTXO size to track and create (in satoshis)
///
/// This value serves dual purposes:
/// 1. Minimum change output size - change below this is dropped and added to miner fee
/// 2. Minimum tracked UTXO size - partial_utxo_set only stores UTXOs >= this amount
///
/// At 3000 sats, outputs are economically spendable even in moderate fee environments.
/// NOT user-configurable to prevent inconsistency between change creation and UTXO tracking.
pub const MIN_UTXO_SIZE: u64 = 3000;

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

/// Validation mode for proposer UTXOs not in partial set
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationMode {
    /// Reject anything outside scan window (enforces freshness)
    Strict,
    /// Fall back to Tor APIs for validation
    Fallback,
}

impl Default for ValidationMode {
    fn default() -> Self {
        ValidationMode::Strict
    }
}

impl std::fmt::Display for ValidationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationMode::Strict => write!(f, "Strict"),
            ValidationMode::Fallback => write!(f, "Fallback (Tor APIs)"),
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

/// Proposal network backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProposalNetworkBackend {
    /// File-based proposal distribution (default)
    FileBased,
    /// Nostr-based distribution
    Nostr,
}

impl Default for ProposalNetworkBackend {
    fn default() -> Self {
        ProposalNetworkBackend::FileBased
    }
}

impl std::fmt::Display for ProposalNetworkBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalNetworkBackend::FileBased => write!(f, "File-Based"),
            ProposalNetworkBackend::Nostr => write!(f, "Nostr"),
        }
    }
}

impl std::str::FromStr for ProposalNetworkBackend {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "filebased" | "file-based" | "file" => Ok(ProposalNetworkBackend::FileBased),
            "nostr" => Ok(ProposalNetworkBackend::Nostr),
            _ => Err(anyhow::anyhow!("Invalid network backend: {}", s)),
        }
    }
}

/// Proposal network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalNetworkConfig {
    /// Backend type to use
    #[serde(default)]
    pub backend: ProposalNetworkBackend,

    /// Directory for file-based backend
    /// Default: ~/.local/share/ambient/{network}/proposals/
    #[serde(default = "default_proposals_dir")]
    pub file_directory: PathBuf,

    /// Relay URLs for Nostr backend
    #[serde(default = "default_nostr_relays")]
    pub nostr_relays: Vec<String>,

    /// PoW difficulty for publishing to Nostr (0-255, higher = more spam protection)
    /// Default: 20 (moderate protection, ~1-2 seconds to compute)
    #[serde(default = "default_nostr_pow_difficulty")]
    pub nostr_pow_difficulty: Option<u8>,
}

impl Default for ProposalNetworkConfig {
    fn default() -> Self {
        Self {
            backend: ProposalNetworkBackend::FileBased,
            file_directory: default_proposals_dir(),
            nostr_relays: default_nostr_relays(),
            nostr_pow_difficulty: default_nostr_pow_difficulty(),
        }
    }
}

/// Partial UTXO set configuration for trustless proposer UTXO validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialUtxoSetConfig {
    /// Scan window (number of recent blocks to keep in partial UTXO set)
    /// Default: 1000 blocks (~1 week)
    /// Adjustable: 500-5000 for desktop
    #[serde(default = "default_scan_window_blocks")]
    pub scan_window_blocks: u32,

    /// Minimum UTXO amount to track (sats)
    /// Default: 5000 sats (anti-dust/inscription filter)
    #[serde(default = "default_min_utxo_amount")]
    pub min_utxo_amount_sats: u64,

    /// Maximum age difference between proposer and receiver UTXOs (blocks)
    /// Must be <= scan_window_blocks
    /// Default: 1000 blocks
    #[serde(default = "default_max_utxo_age_delta")]
    pub max_utxo_age_delta_blocks: u32,

    /// Validation mode when proposer UTXO not in partial set
    /// strict = reject if outside scan window (enforces freshness)
    /// fallback = use Tor APIs (adds latency, reduces privacy slightly)
    #[serde(default)]
    pub validation_mode: ValidationMode,
}

impl Default for PartialUtxoSetConfig {
    fn default() -> Self {
        Self {
            scan_window_blocks: default_scan_window_blocks(),
            min_utxo_amount_sats: default_min_utxo_amount(),
            max_utxo_age_delta_blocks: default_max_utxo_age_delta(),
            validation_mode: ValidationMode::Strict,
        }
    }
}

/// SNICKER automation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnickerAutomation {
    /// Automation mode
    #[serde(default)]
    pub mode: AutomationMode,

    /// Maximum sats to lose per coinjoin (fee contribution limit)
    /// Default: 1000 sats
    #[serde(default = "default_max_sats_per_coinjoin")]
    pub max_sats_per_coinjoin: u64,

    /// Maximum sats to spend on coinjoins per day
    /// Default: 2500 sats
    #[serde(default = "default_max_sats_per_day")]
    pub max_sats_per_day: u64,

    /// Maximum sats to spend on coinjoins per week
    /// Default: 10000 sats
    #[serde(default = "default_max_sats_per_week")]
    pub max_sats_per_week: u64,

    /// Prefer proposals that consume SNICKER outputs (creating chains)
    #[serde(default = "default_prefer_snicker_outputs")]
    pub prefer_snicker_outputs: bool,

    /// For proposer mode: only create proposals to SNICKER-pattern transactions
    /// (vs all taproot UTXOs in range)
    #[serde(default = "default_snicker_pattern_only")]
    pub snicker_pattern_only: bool,

    /// Number of outstanding proposals to maintain in Proposer mode
    /// Default: 5 (aggressive for bootstrapping new ecosystem)
    #[serde(default = "default_outstanding_proposals")]
    pub outstanding_proposals: u32,

    /// Timeout window in blocks before reroll in Receiver mode
    /// If no coinjoin occurs within this many blocks, flip coin again
    /// Default: 144 blocks (~1 day)
    #[serde(default = "default_receiver_timeout_blocks")]
    pub receiver_timeout_blocks: u32,
}

impl Default for SnickerAutomation {
    fn default() -> Self {
        Self {
            mode: AutomationMode::Disabled,
            max_sats_per_coinjoin: default_max_sats_per_coinjoin(),
            max_sats_per_day: default_max_sats_per_day(),
            max_sats_per_week: default_max_sats_per_week(),
            prefer_snicker_outputs: default_prefer_snicker_outputs(),
            snicker_pattern_only: default_snicker_pattern_only(),
            outstanding_proposals: default_outstanding_proposals(),
            receiver_timeout_blocks: default_receiver_timeout_blocks(),
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

    /// Proposal network configuration (backend type and settings)
    #[serde(default)]
    pub proposal_network: ProposalNetworkConfig,

    /// DEPRECATED: Use proposal_network.file_directory instead
    /// Kept for backward compatibility - if present, it will override proposal_network.file_directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposals_directory: Option<PathBuf>,

    /// Partial UTXO set configuration for trustless proposer validation
    #[serde(default)]
    pub partial_utxo_set: PartialUtxoSetConfig,

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
            proposal_network: ProposalNetworkConfig::default(),
            proposals_directory: None,
            partial_utxo_set: PartialUtxoSetConfig::default(),
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

    /// Create a proposal network backend based on configuration
    ///
    /// Returns an Arc<dyn ProposalNetwork> configured according to the user's settings.
    /// Handles backward compatibility with deprecated proposals_directory field.
    ///
    /// # Panics
    /// Panics if Nostr network creation fails (should only happen with invalid config)
    pub fn create_proposal_network(&self) -> std::sync::Arc<dyn crate::network::ProposalNetwork> {
        use std::sync::Arc;
        use crate::network::ProposalNetwork;

        // Get the directory to use (backward compatibility)
        let directory = self.proposals_directory
            .clone()
            .unwrap_or_else(|| self.proposal_network.file_directory.clone());

        match self.proposal_network.backend {
            ProposalNetworkBackend::FileBased => {
                Arc::new(crate::network::file_based::FileBasedNetwork::new(directory))
                    as Arc<dyn ProposalNetwork>
            }
            ProposalNetworkBackend::Nostr => {
                // Nostr network creation is async, so we need to block on it
                // This is okay since it's only called during Manager initialization
                let network = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        crate::network::nostr::NostrNetwork::new(
                            self.proposal_network.nostr_relays.clone(),
                            self.proposal_network.nostr_pow_difficulty,
                        ).await
                    })
                });

                Arc::new(network.expect("Failed to create Nostr network"))
                    as Arc<dyn ProposalNetwork>
            }
        }
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

/// Get the default max sats per coinjoin (1000 sats)
fn default_max_sats_per_coinjoin() -> u64 {
    1000
}

/// Get the default max sats per day (2500 sats)
fn default_max_sats_per_day() -> u64 {
    2500
}

/// Get the default max sats per week (10000 sats)
fn default_max_sats_per_week() -> u64 {
    10000
}

/// Get the default for prefer_snicker_outputs
fn default_prefer_snicker_outputs() -> bool {
    true
}

/// Get the default for snicker_pattern_only
/// Default to false to allow bootstrapping - targeting any P2TR UTXO
fn default_snicker_pattern_only() -> bool {
    false
}

/// Get the default number of outstanding proposals to maintain (5)
fn default_outstanding_proposals() -> u32 {
    5
}

/// Get the default receiver timeout in blocks (144 = ~1 day)
fn default_receiver_timeout_blocks() -> u32 {
    144
}

/// Get the default Nostr relays
fn default_nostr_relays() -> Vec<String> {
    vec![
        "wss://relay.damus.io".to_string(),
        "wss://nostr.wine".to_string(),
    ]
}

/// Get the default Nostr PoW difficulty
fn default_nostr_pow_difficulty() -> Option<u8> {
    Some(20)
}

/// Get the default scan window (1000 blocks ~1 week)
fn default_scan_window_blocks() -> u32 {
    1000
}

/// Get the default minimum UTXO amount
fn default_min_utxo_amount() -> u64 {
    MIN_UTXO_SIZE
}

/// Get the default maximum UTXO age delta (1000 blocks)
fn default_max_utxo_age_delta() -> u32 {
    1000
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
            proposal_network: ProposalNetworkConfig {
                backend: ProposalNetworkBackend::FileBased,
                file_directory: PathBuf::from("/tmp/proposals"),
                nostr_relays: vec![],
                nostr_pow_difficulty: None,
            },
            proposals_directory: None,
            partial_utxo_set: PartialUtxoSetConfig::default(),
            snicker_automation: SnickerAutomation::default(),
        };

        let toml = toml::to_string(&config).unwrap();
        assert!(toml.contains("network = \"regtest\""));
        assert!(toml.contains("peer = \"localhost:18444\""));
        assert!(toml.contains("backend = \"filebased\""));
        assert!(toml.contains("scan_window_blocks"));

        let deserialized: Config = toml::from_str(&toml).unwrap();
        assert_eq!(deserialized.network, Network::Regtest);
        assert_eq!(deserialized.peer, Some("localhost:18444".to_string()));
        assert_eq!(deserialized.proposal_network.backend, ProposalNetworkBackend::FileBased);
        assert_eq!(deserialized.partial_utxo_set.scan_window_blocks, 1000);
        assert_eq!(deserialized.partial_utxo_set.min_utxo_amount_sats, MIN_UTXO_SIZE);
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
