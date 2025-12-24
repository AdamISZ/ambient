//! Test utilities for Nostr relay testing
//!
//! This module provides utilities for testing SNICKER proposals over Nostr.
//! It does NOT embed a relay to avoid version conflicts and complexity.
//! Instead, it provides helpers for working with external test relays.

use anyhow::{Context, Result};
use std::time::Duration;

/// Configuration for test relay
#[derive(Debug, Clone)]
pub struct TestRelayConfig {
    /// Relay WebSocket URL
    pub url: String,
    /// Connection timeout
    pub timeout: Duration,
}

impl Default for TestRelayConfig {
    fn default() -> Self {
        Self {
            // Default to local relay for testing
            url: "ws://localhost:7777".to_string(),
            timeout: Duration::from_secs(5),
        }
    }
}

impl TestRelayConfig {
    /// Create config for local relay
    pub fn local(port: u16) -> Self {
        Self {
            url: format!("ws://localhost:{}", port),
            timeout: Duration::from_secs(5),
        }
    }

    /// Create config for public test relay
    pub fn public_test() -> Self {
        Self {
            url: "wss://relay.damus.io".to_string(),
            timeout: Duration::from_secs(10),
        }
    }
}

/// Check if a relay is accessible
pub async fn check_relay_available(url: &str, timeout: Duration) -> bool {
    use tokio::time::timeout as tokio_timeout;

    // Try to create a client and connect
    let check = async {
        let keys = nostr_sdk::Keys::generate();
        let client = nostr_sdk::Client::new(keys);
        client.add_relay(url).await?;
        client.connect().await;

        // Give it a moment to connect
        tokio::time::sleep(Duration::from_millis(500)).await;

        let relays = client.relays().await;
        for (_url, relay) in relays.iter() {
            if relay.is_connected() {
                return Ok::<_, anyhow::Error>(true);
            }
        }
        Ok(false)
    };

    match tokio_timeout(timeout, check).await {
        Ok(Ok(connected)) => connected,
        _ => false,
    }
}

/// Wait for relay to become available (useful when starting external relay process)
pub async fn wait_for_relay(url: &str, timeout: Duration, retry_interval: Duration) -> Result<()> {
    let start = std::time::Instant::now();

    loop {
        if check_relay_available(url, Duration::from_secs(2)).await {
            tracing::info!("✅ Relay available at {}", url);
            return Ok(());
        }

        if start.elapsed() > timeout {
            return Err(anyhow::anyhow!(
                "Relay at {} did not become available within {:?}",
                url, timeout
            ));
        }

        tracing::debug!("⏳ Waiting for relay at {}...", url);
        tokio::time::sleep(retry_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Only run when relay is available
    async fn test_check_local_relay() {
        let available = check_relay_available(
            "ws://localhost:7777",
            Duration::from_secs(2)
        ).await;

        if available {
            println!("✅ Local relay is available");
        } else {
            println!("❌ Local relay not available - skipping test");
        }
    }

    #[tokio::test]
    #[ignore] // Don't hit public relays in CI
    async fn test_check_public_relay() {
        let available = check_relay_available(
            "wss://relay.damus.io",
            Duration::from_secs(5)
        ).await;

        println!("Public relay available: {}", available);
    }
}
