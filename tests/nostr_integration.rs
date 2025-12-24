//! Nostr network integration tests
//!
//! These tests include an embedded relay for zero-setup testing.
//!
//! Run all tests with embedded relay:
//! ```bash
//! cargo test --test nostr_integration --features test-utils -- --ignored --nocapture
//! ```
//!
//! Or test against an external relay (without embedded relay):
//! ```bash
//! NOSTR_RELAY_URL=ws://localhost:7777 cargo test --test nostr_integration -- --ignored
//! ```
//!
//! Note: The --features test-utils flag is required for embedded relay support

use ambient::network::nostr::NostrNetwork;
use ambient::network::embedded_relay::EmbeddedRelay;
use ambient::network::{ProposalNetwork, ProposalFilter};
use ambient::snicker::EncryptedProposal;
use nostr_sdk::Keys;
use std::str::FromStr;
use bdk_wallet::bitcoin::secp256k1::PublicKey;
use tokio_stream::StreamExt;

/// Get relay URL from environment or use default
fn relay_url() -> String {
    std::env::var("NOSTR_RELAY_URL")
        .unwrap_or_else(|_| "ws://localhost:7777".to_string())
}

#[tokio::test]
#[ignore] // Only run when relay is available
async fn test_relay_available() {
    use ambient::network::test_relay::check_relay_available;
    use std::time::Duration;

    let url = relay_url();
    let available = check_relay_available(&url, Duration::from_secs(5)).await;

    assert!(
        available,
        "Relay not available at {}. Start relay with: nostr-rs-relay --port 7777",
        url
    );

    println!("✅ Relay available at {}", url);
}

#[tokio::test]
#[ignore]
async fn test_publish_proposal() {
    let url = relay_url();

    // Create test proposal
    let pubkey = PublicKey::from_str(
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    ).unwrap();

    let proposal = EncryptedProposal {
        ephemeral_pubkey: pubkey,
        tag: [1, 2, 3, 4, 5, 6, 7, 8],
        version: 1,
        encrypted_data: vec![0xaa, 0xbb, 0xcc, 0xdd],
    };

    // Connect to relay
    let keys = Keys::generate();
    let network = NostrNetwork::with_keys(
        vec![url.clone()],
        keys,
        Some(10), // Low PoW for fast testing
    ).await.expect("Failed to create NostrNetwork");

    // Publish proposal
    let receipt = network.publish_proposal(&proposal).await
        .expect("Failed to publish proposal");

    println!("✅ Published proposal to {}", url);
    println!("   Event ID: {}", receipt.id);
    println!("   Timestamp: {}", receipt.timestamp);
    println!("   PoW: {:?}", receipt.pow_difficulty);

    assert!(!receipt.id.is_empty());
}

#[tokio::test]
#[ignore]
async fn test_subscribe_proposals() {
    let url = relay_url();

    // Connect to relay
    let keys = Keys::generate();
    let network = NostrNetwork::with_keys(
        vec![url.clone()],
        keys,
        Some(10),
    ).await.expect("Failed to create NostrNetwork");

    // Subscribe to proposals
    let filter = ProposalFilter {
        since: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() - 3600 // Last hour
        ),
        until: None,
        min_pow: None,
        limit: Some(10),
    };

    let mut stream = network.subscribe_proposals(filter).await
        .expect("Failed to subscribe");

    println!("✅ Subscribed to proposals at {}", url);
    println!("   Waiting for proposals (timeout: 5s)...");

    // Wait for at least one proposal or timeout
    let timeout = tokio::time::sleep(tokio::time::Duration::from_secs(5));
    tokio::pin!(timeout);

    tokio::select! {
        Some(result) = stream.next() => {
            match result {
                Ok(proposal) => {
                    println!("✅ Received proposal: tag={}", hex::encode(&proposal.tag));
                    assert_eq!(proposal.version, 1);
                }
                Err(e) => {
                    panic!("Failed to receive proposal: {}", e);
                }
            }
        }
        _ = &mut timeout => {
            println!("⏱️  No proposals received (timeout)");
            println!("   This is OK if no proposals were published recently");
        }
    }
}

#[tokio::test]
#[ignore]
async fn test_publish_and_receive() {
    let url = relay_url();

    // Create two clients (proposer and receiver)
    let proposer_keys = Keys::generate();
    let receiver_keys = Keys::generate();

    let proposer = NostrNetwork::with_keys(
        vec![url.clone()],
        proposer_keys,
        Some(10),
    ).await.expect("Failed to create proposer");

    let receiver = NostrNetwork::with_keys(
        vec![url.clone()],
        receiver_keys,
        Some(10),
    ).await.expect("Failed to create receiver");

    // Subscribe first (before publishing)
    let filter = ProposalFilter {
        since: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() - 10
        ),
        until: None,
        min_pow: None,
        limit: Some(10),
    };

    let mut stream = receiver.subscribe_proposals(filter).await
        .expect("Failed to subscribe");

    println!("✅ Receiver subscribed");

    // Give subscription a moment to establish
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Create and publish test proposal
    let pubkey = PublicKey::from_str(
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    ).unwrap();

    let test_tag = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let test_data = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    let proposal = EncryptedProposal {
        ephemeral_pubkey: pubkey,
        tag: test_tag,
        version: 1,
        encrypted_data: test_data.clone(),
    };

    let receipt = proposer.publish_proposal(&proposal).await
        .expect("Failed to publish");

    println!("✅ Proposer published event {}", receipt.id);

    // Wait to receive the proposal
    let timeout = tokio::time::sleep(tokio::time::Duration::from_secs(10));
    tokio::pin!(timeout);

    let mut received = false;

    loop {
        tokio::select! {
            Some(result) = stream.next() => {
                match result {
                    Ok(received_proposal) => {
                        println!("✅ Receiver got proposal: tag={}", hex::encode(&received_proposal.tag));

                        if received_proposal.tag == test_tag {
                            assert_eq!(received_proposal.version, 1);
                            assert_eq!(received_proposal.encrypted_data, test_data);
                            assert_eq!(received_proposal.ephemeral_pubkey, pubkey);
                            println!("✅ Proposal matches!");
                            received = true;
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Error receiving proposal: {}", e);
                    }
                }
            }
            _ = &mut timeout => {
                eprintln!("❌ Timeout waiting for proposal");
                break;
            }
        }
    }

    assert!(received, "Did not receive published proposal");
}

#[tokio::test]
#[ignore]
async fn test_with_embedded_relay() {
    // This test uses an embedded relay - no external infrastructure needed!
    let temp_dir = tempfile::tempdir().unwrap();
    let relay = EmbeddedRelay::start(7780, temp_dir.path())
        .await
        .expect("Failed to start embedded relay");

    let url = relay.url().await;
    println!("✅ Embedded relay started at {}", url);

    // Give relay a moment to be ready
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Create two clients
    let proposer_keys = Keys::generate();
    let receiver_keys = Keys::generate();

    let proposer = NostrNetwork::with_keys(
        vec![url.clone()],
        proposer_keys,
        Some(10),
    ).await.expect("Failed to create proposer");

    let receiver = NostrNetwork::with_keys(
        vec![url.clone()],
        receiver_keys,
        Some(10),
    ).await.expect("Failed to create receiver");

    println!("✅ Clients connected");

    // Subscribe before publishing
    let filter = ProposalFilter {
        since: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() - 10
        ),
        until: None,
        min_pow: None,
        limit: Some(10),
    };

    let mut stream = receiver.subscribe_proposals(filter).await
        .expect("Failed to subscribe");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Publish proposal
    let pubkey = PublicKey::from_str(
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    ).unwrap();

    let test_tag = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22];
    let proposal = EncryptedProposal {
        ephemeral_pubkey: pubkey,
        tag: test_tag,
        version: 1,
        encrypted_data: vec![0x12, 0x34, 0x56, 0x78],
    };

    let receipt = proposer.publish_proposal(&proposal).await
        .expect("Failed to publish");

    println!("✅ Published proposal: {}", receipt.id);

    // Receive proposal
    let timeout = tokio::time::sleep(std::time::Duration::from_secs(5));
    tokio::pin!(timeout);

    let mut received = false;
    loop {
        tokio::select! {
            Some(result) = stream.next() => {
                match result {
                    Ok(received_proposal) => {
                        println!("✅ Received proposal: {}", hex::encode(&received_proposal.tag));
                        if received_proposal.tag == test_tag {
                            received = true;
                            break;
                        }
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            _ = &mut timeout => break,
        }
    }

    assert!(received, "Should have received the published proposal");
    println!("✅ Test passed with embedded relay!");

    relay.shutdown().await.expect("Failed to stop relay");
}

#[tokio::test]
#[ignore]
async fn test_pow_verification() {
    let url = relay_url();

    let keys = Keys::generate();
    let network = NostrNetwork::with_keys(
        vec![url.clone()],
        keys,
        Some(15), // Moderate PoW
    ).await.expect("Failed to create network");

    // Create test proposal
    let pubkey = PublicKey::from_str(
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    ).unwrap();

    let proposal = EncryptedProposal {
        ephemeral_pubkey: pubkey,
        tag: [0x99; 8],
        version: 1,
        encrypted_data: vec![0x42; 16],
    };

    println!("⛏️  Generating PoW (difficulty 15)...");
    let start = std::time::Instant::now();

    let receipt = network.publish_proposal(&proposal).await
        .expect("Failed to publish");

    let elapsed = start.elapsed();
    println!("✅ PoW generated in {:?}", elapsed);
    println!("   Event ID: {}", receipt.id);
    println!("   PoW difficulty: {:?}", receipt.pow_difficulty);

    assert_eq!(receipt.pow_difficulty, Some(15));
}
