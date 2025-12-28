//! Network abstraction layer for SNICKER proposal distribution
//!
//! Provides a unified interface for publishing and subscribing to proposals
//! across different network backends (file-based, Nostr, etc.)

pub mod file_based;
pub mod nostr;
pub mod serialization;

// Test utilities (available with test-utils feature or in tests)
#[cfg(any(test, feature = "test-utils"))]
pub mod test_relay;

// Embedded relay (only with test-utils feature, needs external dependencies)
#[cfg(feature = "test-utils")]
pub mod embedded_relay;

use anyhow::Result;
use async_trait::async_trait;
use futures::stream::BoxStream;

/// Trait for proposal network backends
#[async_trait]
pub trait ProposalNetwork: Send + Sync {
    /// Publish a proposal to the network
    ///
    /// # Arguments
    /// * `proposal` - The encrypted proposal to publish
    ///
    /// # Returns
    /// A receipt confirming publication with metadata
    async fn publish_proposal(
        &self,
        proposal: &crate::snicker::EncryptedProposal,
    ) -> Result<PublishReceipt>;

    /// Subscribe to proposals matching criteria (real-time stream)
    ///
    /// # Arguments
    /// * `filter` - Criteria for filtering proposals
    ///
    /// # Returns
    /// An async stream of proposals matching the filter
    async fn subscribe_proposals(
        &self,
        filter: ProposalFilter,
    ) -> Result<BoxStream<'static, Result<crate::snicker::EncryptedProposal>>>;

    /// Fetch proposals matching filter (one-time query)
    ///
    /// # Arguments
    /// * `filter` - Criteria for filtering proposals
    ///
    /// # Returns
    /// Vector of proposals matching the filter
    async fn fetch_proposals(
        &self,
        filter: ProposalFilter,
    ) -> Result<Vec<crate::snicker::EncryptedProposal>>;

    /// Health check / connection status
    async fn check_connection(&self) -> Result<NetworkStatus>;
}

/// Filter criteria for querying proposals
#[derive(Debug, Clone)]
pub struct ProposalFilter {
    /// Only proposals created after this timestamp (Unix seconds)
    pub since: Option<u64>,

    /// Only proposals created before this timestamp (Unix seconds)
    pub until: Option<u64>,

    /// Minimum proof-of-work difficulty (for spam protection)
    pub min_pow: Option<u8>,

    /// Maximum number of proposals to return
    pub limit: Option<usize>,
}

impl Default for ProposalFilter {
    fn default() -> Self {
        Self {
            since: None,
            until: None,
            min_pow: None,
            limit: Some(1000), // Default limit to prevent unbounded queries
        }
    }
}

/// Receipt confirming successful proposal publication
#[derive(Debug, Clone)]
pub struct PublishReceipt {
    /// Unique identifier (file path, Nostr event ID, etc.)
    pub id: String,

    /// Publication timestamp (Unix seconds)
    pub timestamp: u64,

    /// Proof-of-work difficulty used (if applicable)
    pub pow_difficulty: Option<u8>,
}

/// Network connection status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkStatus {
    /// Connected and operational
    Connected,

    /// In the process of connecting
    Connecting,

    /// Disconnected (not connected)
    Disconnected,

    /// Error state with description
    Error(String),
}
