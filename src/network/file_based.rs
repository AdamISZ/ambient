//! File-based proposal network implementation
//!
//! Implements proposal distribution via filesystem directory:
//! - Publishers write `.snicker` files to shared directory
//! - Subscribers scan directory for new files
//!
//! This is the original/default implementation, useful for:
//! - Local testing
//! - Air-gapped setups
//! - Small-scale deployments

use super::{NetworkStatus, ProposalFilter, ProposalNetwork, PublishReceipt};
use super::serialization::{serialize_proposal_json_pretty, deserialize_proposal_json};
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::stream::BoxStream;
use notify::{Watcher, RecursiveMode, Event, EventKind};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// File-based proposal network
pub struct FileBasedNetwork {
    /// Directory where proposal files are stored
    proposals_dir: PathBuf,
}

impl FileBasedNetwork {
    /// Create a new file-based network
    ///
    /// # Arguments
    /// * `proposals_dir` - Directory for storing/reading proposals
    pub fn new(proposals_dir: PathBuf) -> Self {
        Self { proposals_dir }
    }

    /// Get the proposals directory path
    pub fn proposals_dir(&self) -> &Path {
        &self.proposals_dir
    }
}

#[async_trait]
impl ProposalNetwork for FileBasedNetwork {
    async fn publish_proposal(
        &self,
        proposal: &crate::snicker::EncryptedProposal,
    ) -> Result<PublishReceipt> {
        // Create directory if it doesn't exist
        tokio::fs::create_dir_all(&self.proposals_dir).await
            .with_context(|| format!("Failed to create proposals directory: {}", self.proposals_dir.display()))?;

        // Use tag as filename (hex-encoded)
        let tag_hex = hex::encode(&proposal.tag);
        let file_path = self.proposals_dir.join(&tag_hex);

        // Serialize and write
        let serialized = serialize_proposal_json_pretty(proposal);
        tokio::fs::write(&file_path, serialized).await
            .with_context(|| format!("Failed to write proposal file: {}", file_path.display()))?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        tracing::info!("📁 Published proposal {} to {}", tag_hex, file_path.display());

        Ok(PublishReceipt {
            id: file_path.to_string_lossy().to_string(),
            timestamp,
            pow_difficulty: None, // File-based doesn't use PoW
        })
    }

    async fn subscribe_proposals(
        &self,
        filter: ProposalFilter,
    ) -> Result<BoxStream<'static, Result<crate::snicker::EncryptedProposal>>> {
        // Create directory if it doesn't exist
        tokio::fs::create_dir_all(&self.proposals_dir).await?;

        let proposals_dir = self.proposals_dir.clone();

        // Create channel for file system events
        let (tx, mut rx) = mpsc::unbounded_channel::<PathBuf>();

        // Set up file watcher
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    tracing::debug!("📁 File system event: {:?} for paths: {:?}", event.kind, event.paths);

                    // Process Create, Modify, and also handle Rename (for atomic writes)
                    match event.kind {
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Any => {
                            for path in event.paths {
                                // Don't check is_file() here - it might not exist yet
                                // Let the stream handler check when it tries to read
                                tracing::debug!("📁 Queueing path for processing: {}", path.display());
                                if let Err(e) = tx.send(path) {
                                    tracing::warn!("Failed to send path to channel: {}", e);
                                }
                            }
                        }
                        _ => {
                            tracing::trace!("Ignoring event kind: {:?}", event.kind);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("File watch error: {}", e);
                }
            }
        })?;

        watcher.watch(&proposals_dir, RecursiveMode::NonRecursive)?;

        tracing::info!("👀 Watching directory for proposals: {}", proposals_dir.display());

        // First, yield existing files if requested by filter
        let existing_proposals = if filter.since.is_none() {
            // No "since" filter means we want existing files too
            self.fetch_proposals(filter.clone()).await.unwrap_or_default()
        } else {
            Vec::new()
        };

        // Create async stream that:
        // 1. First yields existing proposals
        // 2. Then watches for new files and yields them
        let stream = async_stream::stream! {
            // Yield existing proposals first
            for proposal in existing_proposals {
                yield Ok(proposal);
            }

            // Keep watcher alive by moving it into the stream
            let _watcher = watcher;

            // Watch for new files
            while let Some(path) = rx.recv().await {
                tracing::info!("📁 File event received: {}", path.display());

                // Skip if not a file (e.g., directory)
                if !path.is_file() {
                    tracing::debug!("Skipping non-file path: {}", path.display());
                    continue;
                }

                // Small delay to ensure file is fully written
                // (some editors/programs write atomically via temp files)
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

                // Read and deserialize the file
                match tokio::fs::read_to_string(&path).await {
                    Ok(contents) => {
                        tracing::debug!("📄 Read {} bytes from {}", contents.len(), path.display());

                        match deserialize_proposal_json(&contents) {
                            Ok(proposal) => {
                                tracing::info!("✅ Parsed proposal from {}: tag={}",
                                         path.display(), hex::encode(&proposal.tag));
                                // TODO: Apply filter.min_pow if needed
                                yield Ok(proposal);
                            }
                            Err(e) => {
                                tracing::debug!("Skipped {} (not a valid proposal): {}", path.display(), e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to read {}: {}", path.display(), e);
                    }
                }
            }

            tracing::info!("👀 File watcher stopped");
        };

        Ok(Box::pin(stream))
    }

    async fn fetch_proposals(
        &self,
        filter: ProposalFilter,
    ) -> Result<Vec<crate::snicker::EncryptedProposal>> {
        // Create directory if it doesn't exist
        if !self.proposals_dir.exists() {
            tokio::fs::create_dir_all(&self.proposals_dir).await?;
            tracing::debug!("📁 Created proposals directory: {}", self.proposals_dir.display());
            return Ok(Vec::new());
        }

        tracing::debug!("🔍 Scanning proposals directory: {}", self.proposals_dir.display());

        // Read all files in directory
        let mut read_dir = tokio::fs::read_dir(&self.proposals_dir).await
            .with_context(|| format!("Failed to read proposals directory: {}", self.proposals_dir.display()))?;

        let mut proposals = Vec::new();
        let mut file_count = 0;
        let mut skipped_count = 0;
        let limit = filter.limit.unwrap_or(1000);

        while let Some(entry) = read_dir.next_entry().await? {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            file_count += 1;

            // Apply limit
            if file_count > limit {
                tracing::warn!("Directory has >{} files, limiting scan", limit);
                break;
            }

            // Try to read and deserialize file
            match tokio::fs::read_to_string(&path).await {
                Ok(contents) => {
                    match deserialize_proposal_json(&contents) {
                        Ok(proposal) => {
                            // TODO: Apply filter.since/until/min_pow if needed
                            proposals.push(proposal);
                        }
                        Err(e) => {
                            // Skip invalid files silently (might not be proposal files)
                            skipped_count += 1;
                            if file_count < 10 { // Only log first few to avoid spam
                                tracing::debug!("Skipped {}: {}", path.display(), e);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to read {}: {}", path.display(), e);
                    skipped_count += 1;
                }
            }
        }

        tracing::debug!("📄 Found {} files, {} valid proposal(s), {} skipped",
                 file_count, proposals.len(), skipped_count);

        Ok(proposals)
    }

    async fn check_connection(&self) -> Result<NetworkStatus> {
        // For file-based network, just check if directory is accessible
        if self.proposals_dir.exists() && self.proposals_dir.is_dir() {
            Ok(NetworkStatus::Connected)
        } else if self.proposals_dir.exists() {
            Ok(NetworkStatus::Error(format!("{} is not a directory", self.proposals_dir.display())))
        } else {
            // Directory doesn't exist yet, but can be created
            Ok(NetworkStatus::Disconnected)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        use std::str::FromStr;
        use bdk_wallet::bitcoin::secp256k1::PublicKey;

        // Valid compressed secp256k1 public key
        let pubkey = PublicKey::from_str("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5").unwrap();

        let proposal = crate::snicker::EncryptedProposal {
            ephemeral_pubkey: pubkey,
            tag: [1, 2, 3, 4, 5, 6, 7, 8],
            version: 1,
            encrypted_data: vec![0xde, 0xad, 0xbe, 0xef],
        };

        let serialized = serialize_proposal_json_pretty(&proposal);
        let deserialized = deserialize_proposal_json(&serialized).unwrap();

        assert_eq!(proposal.ephemeral_pubkey, deserialized.ephemeral_pubkey);
        assert_eq!(proposal.tag, deserialized.tag);
        assert_eq!(proposal.version, deserialized.version);
        assert_eq!(proposal.encrypted_data, deserialized.encrypted_data);
    }

    #[tokio::test]
    async fn test_publish_and_fetch() {
        use std::str::FromStr;
        use bdk_wallet::bitcoin::secp256k1::PublicKey;

        let temp_dir = tempfile::tempdir().unwrap();
        let network = FileBasedNetwork::new(temp_dir.path().to_path_buf());

        // Valid compressed secp256k1 public key
        let pubkey = PublicKey::from_str("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5").unwrap();

        let proposal = crate::snicker::EncryptedProposal {
            ephemeral_pubkey: pubkey,
            tag: [1, 2, 3, 4, 5, 6, 7, 8],
            version: 1,
            encrypted_data: vec![0xaa, 0xbb],
        };

        // Publish
        let receipt = network.publish_proposal(&proposal).await.unwrap();
        assert!(receipt.id.contains("0102030405060708"));

        // Fetch
        let proposals = network.fetch_proposals(ProposalFilter::default()).await.unwrap();
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].tag, proposal.tag);
    }
}
