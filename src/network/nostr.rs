//! Nostr-based proposal network implementation
//!
//! Implements proposal distribution via Nostr relays:
//! - Publishers create Nostr events with embedded proposals
//! - Events use custom kind (38383) for SNICKER proposals
//! - Proof-of-Work for spam protection
//! - Real-time subscription to new proposals
//!
//! This enables:
//! - Decentralized proposal distribution
//! - No central server required
//! - Censorship resistance
//! - Global discovery

use super::{NetworkStatus, ProposalFilter, ProposalNetwork, PublishReceipt};
use super::serialization::{serialize_proposal_json, deserialize_proposal_json};
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::stream::{self, BoxStream, StreamExt};
use nostr_sdk::{Client, Event, EventBuilder, EventId, Filter, Keys, Kind, Tag, TagKind};
use std::time::{SystemTime, UNIX_EPOCH};

/// Custom Nostr kind for SNICKER proposals
/// Using 38383 in the "experimental" range (38000-39999)
const SNICKER_PROPOSAL_KIND: u16 = 38383;

/// Nostr-based proposal network
pub struct NostrNetwork {
    /// Nostr client for relay communication
    client: Client,
    /// Relay URLs to connect to
    relay_urls: Vec<String>,
    /// Keys for signing events
    keys: Keys,
    /// PoW difficulty for publishing
    pow_difficulty: Option<u8>,
}

impl NostrNetwork {
    /// Create a new Nostr network backend
    ///
    /// # Arguments
    /// * `relay_urls` - List of relay URLs to connect to
    /// * `pow_difficulty` - Optional PoW difficulty for published events
    pub async fn new(relay_urls: Vec<String>, pow_difficulty: Option<u8>) -> Result<Self> {
        // Generate random keys if none provided
        let keys = Keys::generate();

        // Create client (keys moved, client takes ownership)
        let client = Client::new(keys.clone());

        // Add relays
        for url in &relay_urls {
            client.add_relay(url).await?;
        }

        // Connect to relays
        client.connect().await;

        Ok(Self {
            client,
            relay_urls,
            keys,
            pow_difficulty,
        })
    }

    /// Create with specific keys (for testing or persistent identity)
    pub async fn with_keys(
        relay_urls: Vec<String>,
        keys: Keys,
        pow_difficulty: Option<u8>,
    ) -> Result<Self> {
        let client = Client::new(keys.clone());

        for url in &relay_urls {
            client.add_relay(url).await?;
        }

        client.connect().await;

        Ok(Self {
            client,
            relay_urls,
            keys,
            pow_difficulty,
        })
    }

    /// Serialize a proposal to hex-encoded wire format
    fn serialize_proposal(proposal: &crate::snicker::EncryptedProposal) -> String {
        // Use shared JSON serialization then hex encode for Nostr
        let json = serialize_proposal_json(proposal);
        hex::encode(json.as_bytes())
    }

    /// Deserialize a proposal from hex-encoded wire format
    fn deserialize_proposal(content: &str) -> Result<crate::snicker::EncryptedProposal> {
        // Decode hex to JSON string
        let bytes = hex::decode(content).context("Invalid hex encoding")?;
        let json = String::from_utf8(bytes).context("Invalid UTF-8")?;

        // Use shared JSON deserialization
        deserialize_proposal_json(&json)
    }
}

#[async_trait]
impl ProposalNetwork for NostrNetwork {
    async fn publish_proposal(
        &self,
        proposal: &crate::snicker::EncryptedProposal,
    ) -> Result<PublishReceipt> {
        let content = Self::serialize_proposal(proposal);
        let tag_hex = hex::encode(&proposal.tag);

        // Build event with tags for filtering
        let mut event_builder = EventBuilder::new(
            Kind::Custom(SNICKER_PROPOSAL_KIND),
            content
        )
        .tag(Tag::custom(
            TagKind::Custom(std::borrow::Cow::Borrowed("snicker_tag")),
            vec![tag_hex.clone()]
        ))
        .tag(Tag::custom(
            TagKind::Custom(std::borrow::Cow::Borrowed("version")),
            vec![proposal.version.to_string()]
        ));

        // Build event
        let event = if let Some(difficulty) = self.pow_difficulty {
            // For PoW, we need to use a different approach with nostr-sdk 0.37
            event_builder.pow(difficulty).sign(&self.keys).await?
        } else {
            event_builder.sign(&self.keys).await?
        };

        // Send to relays
        let send_output = self.client.send_event(event).await?;
        let event_id = send_output.id();

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        tracing::info!("📡 Published proposal {} to Nostr (event: {})", tag_hex, event_id);

        Ok(PublishReceipt {
            id: event_id.to_hex(),
            timestamp,
            pow_difficulty: self.pow_difficulty,
        })
    }

    async fn subscribe_proposals(
        &self,
        filter: ProposalFilter,
    ) -> Result<BoxStream<'static, Result<crate::snicker::EncryptedProposal>>> {
        // Build Nostr filter
        let mut nostr_filter = Filter::new()
            .kind(Kind::Custom(SNICKER_PROPOSAL_KIND));

        if let Some(since) = filter.since {
            nostr_filter = nostr_filter.since(nostr_sdk::Timestamp::from(since));
        }

        if let Some(until) = filter.until {
            nostr_filter = nostr_filter.until(nostr_sdk::Timestamp::from(until));
        }

        if let Some(limit) = filter.limit {
            nostr_filter = nostr_filter.limit(limit);
        }

        // Subscribe to filter
        self.client.subscribe(vec![nostr_filter], None).await?;

        // Get notification stream
        let mut notifications = self.client.notifications();
        let min_pow = filter.min_pow;

        // Create stream from notifications
        let stream = async_stream::stream! {
            while let Ok(notification) = notifications.recv().await {
                use nostr_sdk::RelayPoolNotification;

                if let RelayPoolNotification::Event { event, .. } = notification {
                    // Verify it's our kind
                    if event.kind != Kind::Custom(SNICKER_PROPOSAL_KIND) {
                        continue;
                    }

                    // Check PoW if required
                    if let Some(min_difficulty) = min_pow {
                        if !event.check_pow(min_difficulty) {
                            continue;
                        }
                    }

                    // Deserialize proposal
                    match Self::deserialize_proposal(&event.content) {
                        Ok(proposal) => yield Ok(proposal),
                        Err(e) => {
                            tracing::debug!("Failed to deserialize proposal: {}", e);
                            continue;
                        }
                    }
                }
            }
        };

        Ok(Box::pin(stream))
    }

    async fn fetch_proposals(
        &self,
        filter: ProposalFilter,
    ) -> Result<Vec<crate::snicker::EncryptedProposal>> {
        // Build Nostr filter
        let mut nostr_filter = Filter::new()
            .kind(Kind::Custom(SNICKER_PROPOSAL_KIND));

        if let Some(since) = filter.since {
            nostr_filter = nostr_filter.since(nostr_sdk::Timestamp::from(since));
        }

        if let Some(until) = filter.until {
            nostr_filter = nostr_filter.until(nostr_sdk::Timestamp::from(until));
        }

        if let Some(limit) = filter.limit {
            nostr_filter = nostr_filter.limit(limit);
        }

        tracing::debug!("🔍 Fetching proposals from Nostr relays");

        // Query events from relays
        let events = self.client.database()
            .query(vec![nostr_filter])
            .await?;

        tracing::debug!("📄 Found {} events from database", events.len());

        let mut proposals = Vec::new();
        let mut skipped_count = 0;

        for event in events {
            // Check PoW if required
            if let Some(min_pow) = filter.min_pow {
                if !event.check_pow(min_pow) {
                    skipped_count += 1;
                    continue;
                }
            }

            // Deserialize proposal
            match Self::deserialize_proposal(&event.content) {
                Ok(proposal) => proposals.push(proposal),
                Err(e) => {
                    tracing::debug!("Skipped event {}: {}", event.id, e);
                    skipped_count += 1;
                }
            }
        }

        tracing::debug!("✅ Fetched {} valid proposals, {} skipped", proposals.len(), skipped_count);

        Ok(proposals)
    }

    async fn check_connection(&self) -> Result<NetworkStatus> {
        // Check relay connection status
        let relays = self.client.relays().await;

        if relays.is_empty() {
            return Ok(NetworkStatus::Disconnected);
        }

        // Count connected relays by checking relay status
        let mut connected_count = 0;
        for (_url, relay) in relays.iter() {
            if relay.is_connected() {
                connected_count += 1;
            }
        }

        if connected_count == 0 {
            Ok(NetworkStatus::Disconnected)
        } else if connected_count < relays.len() {
            Ok(NetworkStatus::Error(
                format!("{}/{} relays connected", connected_count, relays.len())
            ))
        } else {
            Ok(NetworkStatus::Connected)
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

        let pubkey = PublicKey::from_str("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5").unwrap();

        let proposal = crate::snicker::EncryptedProposal {
            ephemeral_pubkey: pubkey,
            tag: [1, 2, 3, 4, 5, 6, 7, 8],
            version: 1,
            encrypted_data: vec![0xde, 0xad, 0xbe, 0xef],
        };

        let serialized = NostrNetwork::serialize_proposal(&proposal);
        let deserialized = NostrNetwork::deserialize_proposal(&serialized).unwrap();

        assert_eq!(proposal.ephemeral_pubkey, deserialized.ephemeral_pubkey);
        assert_eq!(proposal.tag, deserialized.tag);
        assert_eq!(proposal.version, deserialized.version);
        assert_eq!(proposal.encrypted_data, deserialized.encrypted_data);
    }
}
