//! Proposal serialization utilities
//!
//! Provides default JSON-based serialization for encrypted proposals.
//! Different network backends can use this directly or wrap it (e.g., hex-encoding).

use anyhow::{Context, Result};
use std::str::FromStr;
use bdk_wallet::bitcoin::secp256k1::PublicKey;

/// Serialize a proposal to compact JSON format
///
/// This is the default serialization format. Network backends can use it directly
/// or encode it further (e.g., hex-encoding for Nostr).
pub fn serialize_proposal_json(proposal: &crate::snicker::EncryptedProposal) -> String {
    format!(
        "{{\"ephemeral_pubkey\":\"{}\",\"tag\":\"{}\",\"version\":{},\"encrypted_data\":\"{}\"}}",
        proposal.ephemeral_pubkey,
        hex::encode(&proposal.tag),
        proposal.version,
        hex::encode(&proposal.encrypted_data)
    )
}

/// Serialize a proposal to formatted JSON (human-readable)
///
/// Same as compact JSON but with newlines and indentation for readability.
/// Useful for file-based storage.
pub fn serialize_proposal_json_pretty(proposal: &crate::snicker::EncryptedProposal) -> String {
    format!(
        "{{\n  \"ephemeral_pubkey\": \"{}\",\n  \"tag\": \"{}\",\n  \"version\": {},\n  \"encrypted_data\": \"{}\"\n}}",
        proposal.ephemeral_pubkey,
        hex::encode(&proposal.tag),
        proposal.version,
        hex::encode(&proposal.encrypted_data)
    )
}

/// Deserialize a proposal from JSON format (compact or formatted)
///
/// Parses both compact and pretty-printed JSON formats.
pub fn deserialize_proposal_json(json: &str) -> Result<crate::snicker::EncryptedProposal> {
    // Parse ephemeral_pubkey
    let ephemeral_pubkey_str = json
        .split("\"ephemeral_pubkey\"")
        .nth(1)
        .and_then(|s| s.split('\"').nth(1))  // Fixed: nth(1) not nth(2)
        .ok_or_else(|| anyhow::anyhow!("Missing ephemeral_pubkey"))?;

    let ephemeral_pubkey = PublicKey::from_str(ephemeral_pubkey_str)
        .context("Invalid ephemeral_pubkey")?;

    // Parse tag
    let tag_hex = json
        .split("\"tag\"")
        .nth(1)
        .and_then(|s| s.split('\"').nth(1))  // Fixed: nth(1) not nth(2)
        .ok_or_else(|| anyhow::anyhow!("Missing tag"))?;

    let tag_bytes = hex::decode(tag_hex).context("Invalid tag hex")?;
    let tag: [u8; 8] = tag_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Tag must be exactly 8 bytes"))?;

    // Parse version
    let version = json
        .split("\"version\"")
        .nth(1)
        .and_then(|s| s.split(':').nth(1))
        .and_then(|s| {
            // Handle both "version":1, and "version": 1,
            s.trim()
                .trim_start_matches(':')
                .trim()
                .split(|c: char| c == ',' || c == '}')
                .next()
                .and_then(|v| v.trim().parse::<u8>().ok())
        })
        .unwrap_or(1); // Default to v1 if missing

    // Parse encrypted_data
    let encrypted_data_hex = json
        .split("\"encrypted_data\"")
        .nth(1)
        .and_then(|s| s.split('\"').nth(1))  // Fixed: nth(1) not nth(2)
        .ok_or_else(|| anyhow::anyhow!("Missing encrypted_data"))?;

    let encrypted_data = hex::decode(encrypted_data_hex)
        .context("Invalid encrypted_data hex")?;

    Ok(crate::snicker::EncryptedProposal {
        ephemeral_pubkey,
        tag,
        version,
        encrypted_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize_compact() {
        let pubkey = PublicKey::from_str(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        ).unwrap();

        let proposal = crate::snicker::EncryptedProposal {
            ephemeral_pubkey: pubkey,
            tag: [1, 2, 3, 4, 5, 6, 7, 8],
            version: 1,
            encrypted_data: vec![0xde, 0xad, 0xbe, 0xef],
        };

        let serialized = serialize_proposal_json(&proposal);
        let deserialized = deserialize_proposal_json(&serialized).unwrap();

        assert_eq!(proposal.ephemeral_pubkey, deserialized.ephemeral_pubkey);
        assert_eq!(proposal.tag, deserialized.tag);
        assert_eq!(proposal.version, deserialized.version);
        assert_eq!(proposal.encrypted_data, deserialized.encrypted_data);
    }

    #[test]
    fn test_serialize_deserialize_pretty() {
        let pubkey = PublicKey::from_str(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        ).unwrap();

        let proposal = crate::snicker::EncryptedProposal {
            ephemeral_pubkey: pubkey,
            tag: [1, 2, 3, 4, 5, 6, 7, 8],
            version: 2,
            encrypted_data: vec![0xca, 0xfe],
        };

        let serialized = serialize_proposal_json_pretty(&proposal);
        let deserialized = deserialize_proposal_json(&serialized).unwrap();

        assert_eq!(proposal.ephemeral_pubkey, deserialized.ephemeral_pubkey);
        assert_eq!(proposal.tag, deserialized.tag);
        assert_eq!(proposal.version, deserialized.version);
        assert_eq!(proposal.encrypted_data, deserialized.encrypted_data);
    }
}
