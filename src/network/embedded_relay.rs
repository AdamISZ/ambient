//! Embedded Nostr relay for testing
//!
//! Provides a lightweight in-process relay using nostr-relay-builder and nostr-lmdb.
//! This allows tests to run without requiring external relay infrastructure.

use anyhow::Result;
use nostr_lmdb::NostrLmdb;
use nostr_relay_builder::prelude::*;
use std::path::Path;
use tokio::task::JoinHandle;

/// An embedded Nostr relay for testing
pub struct EmbeddedRelay {
    relay: LocalRelay,
    _handle: JoinHandle<()>,
}

impl EmbeddedRelay {
    /// Start an embedded relay on the specified port
    ///
    /// # Arguments
    /// * `port` - Port to bind the relay to
    /// * `db_path` - Directory path for the LMDB database
    ///
    /// # Returns
    /// An EmbeddedRelay instance that will automatically shutdown when dropped
    pub async fn start<P: AsRef<Path>>(port: u16, db_path: P) -> Result<Self> {
        tracing::info!("🚀 Starting embedded Nostr relay on port {}", port);

        // Create database directory if it doesn't exist
        let db_path = db_path.as_ref();
        if !db_path.exists() {
            std::fs::create_dir_all(db_path)?;
        }

        // Open LMDB database
        let db_path_str = db_path.to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid database path"))?;

        let db = NostrLmdb::open(db_path_str).await?;
        tracing::debug!("📦 LMDB database opened at {}", db_path_str);

        // Build relay
        let relay = LocalRelay::builder()
            .port(port)
            .database(db)
            .build();

        // Start relay in background task
        let relay_clone = relay.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = relay_clone.run().await {
                tracing::error!("❌ Embedded relay error: {}", e);
            }
        });

        // Give relay a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let url = relay.url().await;
        tracing::info!("✅ Embedded relay started at {}", url);

        Ok(Self {
            relay,
            _handle: handle,
        })
    }

    /// Get the relay's WebSocket URL
    pub async fn url(&self) -> String {
        self.relay.url().await.to_string()
    }

    /// Shutdown the relay gracefully
    pub async fn shutdown(self) -> Result<()> {
        tracing::info!("🛑 Shutting down embedded relay");
        self.relay.shutdown();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_embedded_relay_startup() {
        let temp_dir = tempfile::tempdir().unwrap();

        let relay = EmbeddedRelay::start(17777, temp_dir.path())
            .await
            .expect("Failed to start relay");

        let url = relay.url().await;
        assert!(url.starts_with("ws://"));
        assert!(url.contains("17777"));

        relay.shutdown().await.expect("Failed to shutdown");
    }
}
