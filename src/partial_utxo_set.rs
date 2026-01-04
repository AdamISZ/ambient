//! Partial UTXO Set - Trustless Proposer UTXO Validation
//!
//! Maintains a filtered subset of the global Bitcoin UTXO set to enable
//! trustless validation of proposer UTXOs in a light client environment.
//!
//! ## Three-Dimensional Filtering
//! 1. **Script Type**: P2TR (taproot) only
//! 2. **Amount**: >= 5000 sats only (anti-dust/inscription filter)
//! 3. **Age**: Last N blocks only (default: 1000 blocks ~1 week)
//!
//! ## Storage
//! - 1000 block window: ~750,000 UTXOs × 83 bytes = ~60 MB
//! - Trivial on desktop Linux
//!
//! ## Privacy
//! We download ALL blocks (not selectively), which makes us indistinguishable
//! from full node observers - paradoxically better privacy than selective downloads.

use anyhow::{Context, Result};
use bdk_wallet::bitcoin::{Block, OutPoint, ScriptBuf, Txid};
use rusqlite::{Connection, params};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Minimum UTXO amount to track (must match config default)
pub const MIN_SNICKER_OUTPUT: u64 = 5000;

/// UTXO status in partial set
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtxoStatus {
    /// UTXO is unspent (available for proposals)
    Unspent,
    /// UTXO has been spent
    Spent,
}

impl UtxoStatus {
    fn to_str(&self) -> &'static str {
        match self {
            UtxoStatus::Unspent => "unspent",
            UtxoStatus::Spent => "spent",
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "unspent" => Ok(UtxoStatus::Unspent),
            "spent" => Ok(UtxoStatus::Spent),
            _ => Err(anyhow::anyhow!("Invalid UTXO status: {}", s)),
        }
    }
}

/// A UTXO in the partial set
#[derive(Debug, Clone)]
pub struct PartialUtxo {
    pub txid: Txid,
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: ScriptBuf,
    pub block_height: u32,
    pub status: UtxoStatus,
    pub spent_in_txid: Option<Txid>,
    pub spent_at_height: Option<u32>,
    pub created_at: u64, // Unix timestamp
    pub transaction_type: Option<String>, // e.g., "v1" for SNICKER v1, None for regular
}

/// Partial UTXO Set manager
///
/// Maintains a lightweight, filtered view of recent P2TR UTXOs >= 5000 sats
/// for trustless proposer UTXO validation in SNICKER proposals.
pub struct PartialUtxoSet {
    conn: Connection,
    min_amount: u64,
    pub scan_window: u32,
}

impl PartialUtxoSet {
    /// Create or open a partial UTXO set database
    pub fn new<P: AsRef<Path>>(
        db_path: P,
        min_amount: u64,
        scan_window: u32,
    ) -> Result<Self> {
        let conn = Connection::open(db_path.as_ref())
            .with_context(|| {
                format!("Failed to open partial UTXO set database: {}",
                       db_path.as_ref().display())
            })?;

        // Create tables
        conn.execute(
            "CREATE TABLE IF NOT EXISTS partial_utxo_set (
                txid TEXT NOT NULL,
                vout INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                script_pubkey BLOB NOT NULL,
                block_height INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'unspent',
                spent_in_txid TEXT,
                spent_at_height INTEGER,
                created_at INTEGER NOT NULL,
                transaction_type TEXT,
                PRIMARY KEY (txid, vout)
            )",
            [],
        )?;

        // Create indexes for efficient queries
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_status ON partial_utxo_set(status)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_height ON partial_utxo_set(block_height)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_amount ON partial_utxo_set(amount)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_transaction_type ON partial_utxo_set(transaction_type)",
            [],
        )?;

        // Metadata table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS partial_utxo_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        // Initialize last_scanned_height if not exists
        conn.execute(
            "INSERT OR IGNORE INTO partial_utxo_metadata (key, value)
             VALUES ('last_scanned_height', '0')",
            [],
        )?;

        tracing::info!(
            "📊 Partial UTXO set opened: {} (min_amount={}, window={})",
            db_path.as_ref().display(),
            min_amount,
            scan_window
        );

        Ok(Self {
            conn,
            min_amount,
            scan_window,
        })
    }

    /// Scan a single block and update the partial UTXO set
    ///
    /// This processes both spends (inputs) and creations (outputs):
    /// 1. Mark any existing UTXOs in our set as spent (process inputs)
    /// 2. Add new P2TR UTXOs >= min_amount (process outputs)
    ///
    /// Returns: Vector of outpoints that were marked as spent (for cleanup of proposal pairings)
    pub fn scan_block(&mut self, height: u32, block: &Block) -> Result<Vec<OutPoint>> {
        let mut utxos_added = 0;
        let mut spent_outpoints = Vec::new();

        for tx in &block.txdata {
            let txid = tx.compute_txid();

            // ═══════════════════════════════════════════
            // PHASE 1: Track spends (process inputs)
            // ═══════════════════════════════════════════
            for input in &tx.input {
                let outpoint = input.previous_output;
                if self.exists(&outpoint)? {
                    self.mark_spent(outpoint, txid, height)?;
                    spent_outpoints.push(outpoint);
                }
            }

            // ═══════════════════════════════════════════
            // PHASE 2: Track creations (process outputs)
            // ═══════════════════════════════════════════
            // Detect if this is a SNICKER transaction
            let transaction_type = if crate::snicker::is_likely_snicker_transaction(tx) {
                Some("v1".to_string())
            } else {
                None
            };

            for (vout, output) in tx.output.iter().enumerate() {
                // Filter 1: P2TR only
                if !output.script_pubkey.is_p2tr() {
                    tracing::trace!(
                        "Block {} tx {} output {}: skipping non-P2TR (type: {:?})",
                        height, txid, vout, output.script_pubkey
                    );
                    continue;
                }

                // Filter 2: >= min_amount only
                let amount = output.value.to_sat();
                if amount < self.min_amount {
                    tracing::trace!(
                        "Block {} tx {} output {}: skipping amount {} < min {}",
                        height, txid, vout, amount, self.min_amount
                    );
                    continue;
                }

                tracing::debug!(
                    "Block {} tx {} output {}: ADDING P2TR UTXO {} sats{}",
                    height, txid, vout, amount,
                    if transaction_type.is_some() { " (SNICKER v1)" } else { "" }
                );

                // Filter 3: Age is implicit (we're scanning recent blocks)

                // Add to partial set
                self.insert(PartialUtxo {
                    txid,
                    vout: vout as u32,
                    amount,
                    script_pubkey: output.script_pubkey.clone(),
                    block_height: height,
                    status: UtxoStatus::Unspent,
                    spent_in_txid: None,
                    spent_at_height: None,
                    created_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    transaction_type: transaction_type.clone(),
                })?;

                utxos_added += 1;
            }
        }

        if utxos_added > 0 || !spent_outpoints.is_empty() {
            tracing::debug!(
                "Block {}: +{} UTXOs, -{} spends",
                height, utxos_added, spent_outpoints.len()
            );
        }

        Ok(spent_outpoints)
    }

    /// Insert a UTXO into the partial set
    fn insert(&mut self, utxo: PartialUtxo) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO partial_utxo_set
             (txid, vout, amount, script_pubkey, block_height, status,
              spent_in_txid, spent_at_height, created_at, transaction_type)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                utxo.txid.to_string(),
                utxo.vout,
                utxo.amount as i64,
                utxo.script_pubkey.as_bytes(),
                utxo.block_height,
                utxo.status.to_str(),
                utxo.spent_in_txid.map(|t| t.to_string()),
                utxo.spent_at_height,
                utxo.created_at as i64,
                utxo.transaction_type,
            ],
        )?;
        Ok(())
    }

    /// Check if a UTXO exists in the partial set
    pub fn exists(&self, outpoint: &OutPoint) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM partial_utxo_set WHERE txid = ? AND vout = ?",
            params![outpoint.txid.to_string(), outpoint.vout],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Mark a UTXO as spent
    fn mark_spent(&mut self, outpoint: OutPoint, spent_in: Txid, spent_at: u32) -> Result<()> {
        self.conn.execute(
            "UPDATE partial_utxo_set
             SET status = 'spent', spent_in_txid = ?, spent_at_height = ?
             WHERE txid = ? AND vout = ?",
            params![
                spent_in.to_string(),
                spent_at,
                outpoint.txid.to_string(),
                outpoint.vout,
            ],
        )?;
        Ok(())
    }

    /// Get a UTXO from the partial set
    pub fn get(&self, outpoint: &OutPoint) -> Result<Option<PartialUtxo>> {
        let result = self.conn.query_row(
            "SELECT txid, vout, amount, script_pubkey, block_height, status,
                    spent_in_txid, spent_at_height, created_at, transaction_type
             FROM partial_utxo_set
             WHERE txid = ? AND vout = ?",
            params![outpoint.txid.to_string(), outpoint.vout],
            |row| {
                let txid_str: String = row.get(0)?;
                let vout: u32 = row.get(1)?;
                let amount: i64 = row.get(2)?;
                let script_bytes: Vec<u8> = row.get(3)?;
                let block_height: u32 = row.get(4)?;
                let status_str: String = row.get(5)?;
                let spent_in_str: Option<String> = row.get(6)?;
                let spent_at_height: Option<u32> = row.get(7)?;
                let created_at: i64 = row.get(8)?;
                let transaction_type: Option<String> = row.get(9)?;

                Ok(PartialUtxo {
                    txid: txid_str.parse().unwrap(),
                    vout,
                    amount: amount as u64,
                    script_pubkey: ScriptBuf::from_bytes(script_bytes),
                    block_height,
                    status: UtxoStatus::from_str(&status_str).unwrap(),
                    spent_in_txid: spent_in_str.map(|s| s.parse().unwrap()),
                    spent_at_height,
                    created_at: created_at as u64,
                    transaction_type,
                })
            },
        );

        match result {
            Ok(utxo) => Ok(Some(utxo)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Prune UTXOs older than the scan window
    ///
    /// This keeps the database size bounded by removing UTXOs outside the window.
    pub fn prune_older_than(&mut self, min_height: u32) -> Result<usize> {
        let deleted = self.conn.execute(
            "DELETE FROM partial_utxo_set WHERE block_height < ?",
            params![min_height],
        )?;

        if deleted > 0 {
            tracing::info!("🗑️  Pruned {} UTXOs older than height {}", deleted, min_height);
        }

        Ok(deleted)
    }

    /// Get the total count of UTXOs in the partial set
    pub fn count(&self) -> Result<usize> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM partial_utxo_set",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Get the count of unspent UTXOs
    pub fn count_unspent(&self) -> Result<usize> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM partial_utxo_set WHERE status = 'unspent'",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Get the last scanned block height
    pub fn get_last_scanned_height(&self) -> Result<u32> {
        let height_str: String = self.conn.query_row(
            "SELECT value FROM partial_utxo_metadata WHERE key = 'last_scanned_height'",
            [],
            |row| row.get(0),
        )?;
        Ok(height_str.parse()?)
    }

    /// Set the last scanned block height
    pub fn set_last_scanned_height(&mut self, height: u32) -> Result<()> {
        self.conn.execute(
            "UPDATE partial_utxo_metadata SET value = ? WHERE key = 'last_scanned_height'",
            params![height.to_string()],
        )?;
        Ok(())
    }

    /// Rollback to a specific height (for reorg handling)
    ///
    /// Removes all UTXOs created at or after the given height, and un-spends
    /// any UTXOs that were marked as spent at or after that height.
    pub fn rollback_to(&mut self, height: u32) -> Result<()> {
        // Delete UTXOs created at or after the reorg point
        let deleted = self.conn.execute(
            "DELETE FROM partial_utxo_set WHERE block_height >= ?",
            params![height],
        )?;

        // Un-spend UTXOs that were spent at or after the reorg point
        let unspent = self.conn.execute(
            "UPDATE partial_utxo_set
             SET status = 'unspent', spent_in_txid = NULL, spent_at_height = NULL
             WHERE spent_at_height >= ?",
            params![height],
        )?;

        tracing::warn!(
            "⚠️  Reorg rollback to height {}: deleted {} UTXOs, un-spent {} UTXOs",
            height, deleted, unspent
        );

        // Update last scanned height
        self.set_last_scanned_height(height.saturating_sub(1))?;

        Ok(())
    }

    /// Reset the partial UTXO set (clear all data)
    ///
    /// Used for rebuilding from scratch or recovering from corruption.
    pub fn reset(&mut self) -> Result<()> {
        self.conn.execute("DELETE FROM partial_utxo_set", [])?;
        self.set_last_scanned_height(0)?;
        tracing::info!("🔧 Partial UTXO set reset");
        Ok(())
    }

    /// Query UTXOs within a height and amount range
    ///
    /// Returns unspent UTXOs matching all filters:
    /// - Block height between start_height and end_height (inclusive)
    /// - Amount between min_amount and max_amount (inclusive)
    /// - Status = unspent
    /// - Optional: transaction_type filter (e.g., Some("v1") for SNICKER v1 only)
    ///
    /// Results are grouped by txid (multiple UTXOs from same tx will be included)
    pub fn query_range(
        &self,
        start_height: u32,
        end_height: u32,
        min_amount: u64,
        max_amount: u64,
        transaction_type_filter: Option<&str>,
    ) -> Result<Vec<PartialUtxo>> {
        // Cap max_amount at i64::MAX to avoid overflow when casting to i64 for SQLite
        // (u64::MAX as i64 would become -1, breaking the query)
        let max_amount_safe = std::cmp::min(max_amount, i64::MAX as u64) as i64;
        let min_amount_i64 = min_amount as i64;

        // Build query dynamically based on whether we filter by transaction_type
        let (query, params_vec): (String, Vec<Box<dyn rusqlite::ToSql>>) = if let Some(tx_type) = transaction_type_filter {
            (
                "SELECT txid, vout, amount, script_pubkey, block_height, status,
                        spent_in_txid, spent_at_height, created_at, transaction_type
                 FROM partial_utxo_set
                 WHERE status = 'unspent'
                   AND block_height >= ?
                   AND block_height <= ?
                   AND amount >= ?
                   AND amount <= ?
                   AND transaction_type = ?
                 ORDER BY block_height DESC, txid, vout".to_string(),
                vec![
                    Box::new(start_height),
                    Box::new(end_height),
                    Box::new(min_amount_i64),
                    Box::new(max_amount_safe),
                    Box::new(tx_type.to_string()),
                ]
            )
        } else {
            (
                "SELECT txid, vout, amount, script_pubkey, block_height, status,
                        spent_in_txid, spent_at_height, created_at, transaction_type
                 FROM partial_utxo_set
                 WHERE status = 'unspent'
                   AND block_height >= ?
                   AND block_height <= ?
                   AND amount >= ?
                   AND amount <= ?
                 ORDER BY block_height DESC, txid, vout".to_string(),
                vec![
                    Box::new(start_height),
                    Box::new(end_height),
                    Box::new(min_amount_i64),
                    Box::new(max_amount_safe),
                ]
            )
        };

        let mut stmt = self.conn.prepare(&query)?;

        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        let utxos = stmt.query_map(params_refs.as_slice(), |row| {
            let txid_str: String = row.get(0)?;
            let vout: u32 = row.get(1)?;
            let amount: i64 = row.get(2)?;
            let script_bytes: Vec<u8> = row.get(3)?;
            let block_height: u32 = row.get(4)?;
            let status_str: String = row.get(5)?;
            let spent_in_str: Option<String> = row.get(6)?;
            let spent_at_height: Option<u32> = row.get(7)?;
            let created_at: i64 = row.get(8)?;
            let transaction_type: Option<String> = row.get(9)?;

            Ok(PartialUtxo {
                txid: txid_str.parse().unwrap(),
                vout,
                amount: amount as u64,
                script_pubkey: ScriptBuf::from_bytes(script_bytes),
                block_height,
                status: UtxoStatus::from_str(&status_str).unwrap(),
                spent_in_txid: spent_in_str.map(|s| s.parse().unwrap()),
                spent_at_height,
                created_at: created_at as u64,
                transaction_type,
            })
        })?;

        let mut result = Vec::new();
        for utxo in utxos {
            result.push(utxo?);
        }

        Ok(result)
    }

    /// Get database statistics
    pub fn stats(&self) -> Result<PartialUtxoSetStats> {
        let total = self.count()?;
        let unspent = self.count_unspent()?;
        let spent = total - unspent;
        let last_height = self.get_last_scanned_height()?;

        // Get size distribution (count by amount ranges)
        let small_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM partial_utxo_set
             WHERE status = 'unspent' AND amount < 100000",
            [],
            |row| row.get(0),
        )?;

        let medium_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM partial_utxo_set
             WHERE status = 'unspent' AND amount >= 100000 AND amount < 1000000",
            [],
            |row| row.get(0),
        )?;

        let large_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM partial_utxo_set
             WHERE status = 'unspent' AND amount >= 1000000",
            [],
            |row| row.get(0),
        )?;

        Ok(PartialUtxoSetStats {
            total_utxos: total,
            unspent_utxos: unspent,
            spent_utxos: spent,
            last_scanned_height: last_height,
            small_utxos: small_count as usize,  // < 0.001 BTC
            medium_utxos: medium_count as usize, // 0.001-0.01 BTC
            large_utxos: large_count as usize,   // >= 0.01 BTC
        })
    }
}

/// Statistics about the partial UTXO set
#[derive(Debug, Clone)]
pub struct PartialUtxoSetStats {
    pub total_utxos: usize,
    pub unspent_utxos: usize,
    pub spent_utxos: usize,
    pub last_scanned_height: u32,
    pub small_utxos: usize,  // < 0.001 BTC
    pub medium_utxos: usize, // 0.001-0.01 BTC
    pub large_utxos: usize,  // >= 0.01 BTC
}

impl std::fmt::Display for PartialUtxoSetStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Partial UTXO Set Statistics:")?;
        writeln!(f, "  Total UTXOs:     {}", self.total_utxos)?;
        writeln!(f, "  Unspent:         {}", self.unspent_utxos)?;
        writeln!(f, "  Spent:           {}", self.spent_utxos)?;
        writeln!(f, "  Last Height:     {}", self.last_scanned_height)?;
        writeln!(f, "  Size Distribution (unspent only):")?;
        writeln!(f, "    < 0.001 BTC:   {}", self.small_utxos)?;
        writeln!(f, "    0.001-0.01 BTC: {}", self.medium_utxos)?;
        writeln!(f, "    >= 0.01 BTC:   {}", self.large_utxos)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::{Amount, Network, TxOut};

    #[test]
    fn test_partial_utxo_set_creation() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_partial_utxo_set.db");
        let _ = std::fs::remove_file(&db_path); // Clean up if exists

        let utxo_set = PartialUtxoSet::new(&db_path, 5000, 1000).unwrap();
        assert_eq!(utxo_set.count().unwrap(), 0);
        assert_eq!(utxo_set.get_last_scanned_height().unwrap(), 0);

        std::fs::remove_file(&db_path).unwrap();
    }

    #[test]
    fn test_insert_and_get() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_insert_get.db");
        let _ = std::fs::remove_file(&db_path);

        let mut utxo_set = PartialUtxoSet::new(&db_path, 5000, 1000).unwrap();

        let txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap();
        let utxo = PartialUtxo {
            txid,
            vout: 0,
            amount: 10000,
            script_pubkey: ScriptBuf::new(),
            block_height: 100,
            status: UtxoStatus::Unspent,
            spent_in_txid: None,
            spent_at_height: None,
            created_at: 0,
            transaction_type: None,
        };

        utxo_set.insert(utxo).unwrap();

        let outpoint = OutPoint { txid, vout: 0 };
        assert!(utxo_set.exists(&outpoint).unwrap());

        let retrieved = utxo_set.get(&outpoint).unwrap().unwrap();
        assert_eq!(retrieved.amount, 10000);
        assert_eq!(retrieved.status, UtxoStatus::Unspent);

        std::fs::remove_file(&db_path).unwrap();
    }

    #[test]
    fn test_mark_spent() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_mark_spent.db");
        let _ = std::fs::remove_file(&db_path);

        let mut utxo_set = PartialUtxoSet::new(&db_path, 5000, 1000).unwrap();

        let txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap();
        let utxo = PartialUtxo {
            txid,
            vout: 0,
            amount: 10000,
            script_pubkey: ScriptBuf::new(),
            block_height: 100,
            status: UtxoStatus::Unspent,
            spent_in_txid: None,
            spent_at_height: None,
            created_at: 0,
            transaction_type: None,
        };

        utxo_set.insert(utxo).unwrap();

        let spent_in = "0000000000000000000000000000000000000000000000000000000000000002"
            .parse().unwrap();
        let outpoint = OutPoint { txid, vout: 0 };

        utxo_set.mark_spent(outpoint, spent_in, 101).unwrap();

        let retrieved = utxo_set.get(&outpoint).unwrap().unwrap();
        assert_eq!(retrieved.status, UtxoStatus::Spent);
        assert_eq!(retrieved.spent_in_txid, Some(spent_in));
        assert_eq!(retrieved.spent_at_height, Some(101));

        std::fs::remove_file(&db_path).unwrap();
    }
}
