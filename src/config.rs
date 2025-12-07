//! Configuration management for Ambient Wallet
//!
//! Handles loading and saving configuration that is shared between CLI and GUI.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;

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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: Network::Signet,
            peer: None,
            wallet_dir: default_wallet_dir(),
            recovery_height: default_recovery_height(),
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
