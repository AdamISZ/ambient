//! Database operations for SNICKER wallet state
//!
//! This module contains all SQLite database operations for the SNICKER wallet,
//! including table initialization, CRUD operations for various tables, and
//! state management.
//!
//! The functions in this module operate on raw `Connection` objects, allowing
//! them to be used both within the `Snicker` struct methods and independently.

use anyhow::{Result, anyhow};
use bdk_wallet::rusqlite::{Connection, OptionalExtension};
use serde::{Serialize, Deserialize};

// ============================================================
// AUTOMATION STATE TYPES
// ============================================================

/// Role in the SNICKER automation state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AutomationRole {
    /// Actively maintaining N outstanding proposals
    Proposer,
    /// Waiting only, no new proposals created
    Receiver,
}

impl AutomationRole {
    /// Flip a coin to get a random role
    pub fn coin_flip() -> Self {
        if rand::random::<bool>() {
            AutomationRole::Proposer
        } else {
            AutomationRole::Receiver
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AutomationRole::Proposer => "proposer",
            AutomationRole::Receiver => "receiver",
        }
    }
}

impl std::str::FromStr for AutomationRole {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "proposer" => Ok(AutomationRole::Proposer),
            "receiver" => Ok(AutomationRole::Receiver),
            _ => Err(anyhow!("Invalid automation role: {}", s)),
        }
    }
}

impl std::fmt::Display for AutomationRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Persisted automation state
#[derive(Debug, Clone)]
pub struct AutomationState {
    /// Current role (Proposer or Receiver)
    pub role: AutomationRole,
    /// Block height of most recent successful coinjoin (or wallet creation height)
    pub last_coinjoin_height: u32,
}

impl Default for AutomationState {
    fn default() -> Self {
        Self {
            role: AutomationRole::Proposer,
            last_coinjoin_height: 0,
        }
    }
}

// ============================================================
// TRANSACTION HISTORY TYPES
// ============================================================

/// A recorded transaction in our history
#[derive(Debug, Clone)]
pub struct TransactionHistoryEntry {
    /// Transaction ID
    pub txid: String,
    /// Full transaction hex
    pub tx_hex: String,
    /// Balance change in satoshis (positive = received, negative = sent)
    pub balance_change_sats: i64,
    /// Transaction type: 'receive', 'send', 'coinjoin_proposer', 'coinjoin_receiver'
    pub tx_type: String,
    /// Block height where the transaction was confirmed
    pub block_height: u32,
    /// Unix timestamp of when the transaction was recorded
    pub timestamp: u64,
}

// ============================================================
// CONSTANTS
// ============================================================

/// Approximate blocks per day (144 = 24 hours * 6 blocks/hour)
pub const BLOCKS_PER_DAY: u32 = 144;
/// Approximate blocks per week (1008 = 144 * 7)
pub const BLOCKS_PER_WEEK: u32 = 1008;

// ============================================================
// DATABASE INITIALIZATION
// ============================================================

/// Initialize all SNICKER database tables
pub fn init_snicker_db(conn: &mut Connection) -> Result<()> {
    init_decrypted_proposals_table(conn)?;
    init_snicker_utxos_table(conn)?;
    init_automation_log_table(conn)?;
    init_pending_transactions_table(conn)?;
    init_automation_state_table(conn)?;
    init_transaction_history_table(conn)?;
    Ok(())
}

/// Run database migrations on an existing database (called when loading a wallet)
pub fn run_migrations(conn: &Connection) {
    fix_orphaned_pending_utxos(conn);
}

/// Fix SNICKER UTXOs that are stuck in "pending" status but whose spending transaction
/// no longer exists in pending_transactions (e.g., it was cleaned up after a conflict).
fn fix_orphaned_pending_utxos(conn: &Connection) {
    // Check if both required tables exist (handles legacy wallets)
    let tables_exist: bool = conn.query_row(
        "SELECT COUNT(*) = 2 FROM sqlite_master WHERE type = 'table' AND name IN ('snicker_utxos', 'pending_transactions')",
        [],
        |row| row.get(0),
    ).unwrap_or(false);

    if !tables_exist {
        return;
    }

    // Find and fix orphaned pending UTXOs
    let fixed = conn.execute(
        "UPDATE snicker_utxos
         SET status = 'unspent', spent_in_txid = NULL, pending_since = NULL
         WHERE status = 'pending'
           AND spent_in_txid IS NOT NULL
           AND spent_in_txid NOT IN (SELECT txid FROM pending_transactions)",
        [],
    ).unwrap_or(0);

    if fixed > 0 {
        tracing::warn!(
            "Fixed {} orphaned SNICKER UTXO(s) stuck in 'pending' status (restored to 'unspent')",
            fixed
        );
    }
}

/// Initialize the decrypted proposals database table
fn init_decrypted_proposals_table(conn: &mut Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS decrypted_proposals (
            tag BLOB PRIMARY KEY,
            psbt BLOB NOT NULL,
            tweak_info BLOB NOT NULL,
            role TEXT NOT NULL,
            status TEXT NOT NULL,
            our_utxo TEXT NOT NULL,
            counterparty_utxo TEXT NOT NULL,
            delta_sats INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_decrypted_status
         ON decrypted_proposals(status)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_decrypted_delta
         ON decrypted_proposals(delta_sats)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_utxo_pair
         ON decrypted_proposals(our_utxo, counterparty_utxo, role, status)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_decrypted_our_utxo
         ON decrypted_proposals(our_utxo)",
        [],
    )?;

    // Migration: add our_utxo_amount column if it doesn't exist
    let has_amount_col: bool = conn.query_row(
        "SELECT 1 FROM pragma_table_info('decrypted_proposals') WHERE name = 'our_utxo_amount'",
        [],
        |_| Ok(true),
    ).unwrap_or(false);
    if !has_amount_col {
        conn.execute(
            "ALTER TABLE decrypted_proposals ADD COLUMN our_utxo_amount INTEGER",
            [],
        )?;
    }
    Ok(())
}

/// Initialize the SNICKER UTXOs database table
fn init_snicker_utxos_table(conn: &mut Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS snicker_utxos (
            txid TEXT NOT NULL,
            vout INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            script_pubkey BLOB NOT NULL,
            tweaked_privkey BLOB NOT NULL,
            snicker_shared_secret BLOB NOT NULL,
            block_height INTEGER,
            status TEXT DEFAULT 'unspent',
            spent_in_txid TEXT,
            PRIMARY KEY (txid, vout)
        )",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_snicker_utxos_status
         ON snicker_utxos(status)",
        [],
    )?;

    // Migration: Convert old 'spent' boolean column to 'status' text column if it exists
    let has_spent_column: Result<bool, _> = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('snicker_utxos') WHERE name='spent'",
        [],
        |row| {
            let count: i64 = row.get(0)?;
            Ok(count > 0)
        },
    );

    if has_spent_column.unwrap_or(false) {
        conn.execute(
            "UPDATE snicker_utxos SET status = CASE WHEN spent = 0 THEN 'unspent' ELSE 'spent' END",
            [],
        )?;
    }

    // Migration: Add pending_since timestamp column if it doesn't exist
    let has_pending_since: Result<bool, _> = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('snicker_utxos') WHERE name='pending_since'",
        [],
        |row| {
            let count: i64 = row.get(0)?;
            Ok(count > 0)
        },
    );

    if !has_pending_since.unwrap_or(false) {
        conn.execute(
            "ALTER TABLE snicker_utxos ADD COLUMN pending_since INTEGER",
            [],
        )?;
        tracing::info!("Added pending_since column to snicker_utxos table");
    }

    Ok(())
}

/// Initialize the automation log database table
fn init_automation_log_table(conn: &mut Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS automation_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            action_type TEXT NOT NULL,
            tag BLOB,
            txid TEXT,
            delta INTEGER,
            success BOOLEAN NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_automation_log_timestamp
         ON automation_log(timestamp)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_automation_log_action
         ON automation_log(action_type, timestamp)",
        [],
    )?;
    Ok(())
}

/// Initialize the pending transactions table for tracking broadcast-but-unconfirmed txs
fn init_pending_transactions_table(conn: &mut Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS pending_transactions (
            txid TEXT PRIMARY KEY,
            broadcast_time INTEGER NOT NULL,
            total_input_sats INTEGER NOT NULL,
            total_output_sats INTEGER NOT NULL,
            fee_sats INTEGER NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS pending_inputs (
            spending_txid TEXT NOT NULL,
            spent_txid TEXT NOT NULL,
            spent_vout INTEGER NOT NULL,
            amount_sats INTEGER NOT NULL,
            is_ours INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (spent_txid, spent_vout),
            FOREIGN KEY (spending_txid) REFERENCES pending_transactions(txid) ON DELETE CASCADE
        )",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pending_inputs_spending_txid
         ON pending_inputs(spending_txid)",
        [],
    )?;
    Ok(())
}

/// Initialize the automation state table for persisting proposer/receiver mode
fn init_automation_state_table(conn: &mut Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS automation_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            mode TEXT NOT NULL DEFAULT 'proposer',
            last_coinjoin_height INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(())
}

/// Initialize the transaction history table for persistent transaction records
fn init_transaction_history_table(conn: &mut Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS transaction_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            txid TEXT UNIQUE NOT NULL,
            tx_hex TEXT NOT NULL,
            balance_change_sats INTEGER NOT NULL,
            tx_type TEXT NOT NULL,
            block_height INTEGER NOT NULL,
            timestamp INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            coinjoin_delta INTEGER
        )",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tx_history_block_height
         ON transaction_history(block_height DESC)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tx_history_type
         ON transaction_history(tx_type)",
        [],
    )?;

    // Migration: Add coinjoin_delta column if it doesn't exist
    let has_coinjoin_delta: Result<bool, _> = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('transaction_history') WHERE name='coinjoin_delta'",
        [],
        |row| {
            let count: i64 = row.get(0)?;
            Ok(count > 0)
        },
    );
    if !has_coinjoin_delta.unwrap_or(true) {
        conn.execute(
            "ALTER TABLE transaction_history ADD COLUMN coinjoin_delta INTEGER",
            [],
        )?;
    }

    Ok(())
}

// ============================================================
// PENDING TRANSACTIONS
// ============================================================

/// Store a pending transaction after broadcast (for tracking unconfirmed state)
pub fn store_pending_transaction(
    conn: &Connection,
    txid: &str,
    inputs: &[(String, u32, u64, bool)], // (txid, vout, amount_sats, is_ours)
    total_output_sats: u64,
) -> Result<()> {
    let broadcast_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let total_input_sats: u64 = inputs.iter().map(|(_, _, amt, _)| amt).sum();
    let fee_sats = total_input_sats.saturating_sub(total_output_sats);

    // Try to insert, but don't fail if table doesn't exist (legacy wallet compatibility)
    match conn.execute(
        "INSERT OR REPLACE INTO pending_transactions (txid, broadcast_time, total_input_sats, total_output_sats, fee_sats)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        (txid, broadcast_time, total_input_sats as i64, total_output_sats as i64, fee_sats as i64),
    ) {
        Ok(_) => {
            for (spent_txid, spent_vout, amount, is_ours) in inputs {
                let _ = conn.execute(
                    "INSERT OR REPLACE INTO pending_inputs (spending_txid, spent_txid, spent_vout, amount_sats, is_ours)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    (txid, spent_txid, spent_vout, *amount as i64, *is_ours as i32),
                );
            }
            tracing::debug!("Stored pending transaction {} with {} inputs", txid, inputs.len());
        }
        Err(e) if e.to_string().contains("no such table") => {
            tracing::warn!("Legacy wallet: pending_transactions table missing, skipping tracking");
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}

/// Check if an outpoint is spent by a pending (unconfirmed) transaction
pub fn is_outpoint_pending_spent(conn: &Connection, txid: &str, vout: u32) -> bool {
    conn.query_row(
        "SELECT 1 FROM pending_inputs WHERE spent_txid = ?1 AND spent_vout = ?2",
        (txid, vout),
        |_| Ok(()),
    ).is_ok()
}

/// Get pending balance info: (pending_outgoing_sats, pending_incoming_snicker_sats)
pub fn get_pending_balance(conn: &Connection) -> (u64, u64) {
    // Pending outgoing: sum of OUR inputs in pending transactions (not other parties' inputs)
    let pending_outgoing: i64 = conn.query_row(
        "SELECT COALESCE(SUM(amount_sats), 0) FROM pending_inputs WHERE is_ours = 1",
        [],
        |row| row.get(0),
    ).unwrap_or(0);

    // Pending incoming SNICKER: UTXOs with block_height IS NULL (broadcast but unconfirmed)
    let pending_incoming_snicker: i64 = conn.query_row(
        "SELECT COALESCE(SUM(amount), 0) FROM snicker_utxos WHERE block_height IS NULL AND status = 'unspent'",
        [],
        |row| row.get(0),
    ).unwrap_or(0);

    (pending_outgoing as u64, pending_incoming_snicker as u64)
}

/// Remove a confirmed transaction from pending tracking
pub fn remove_confirmed_transaction(conn: &Connection, txid: &str) -> Result<()> {
    // Delete from pending_inputs first (due to foreign key)
    conn.execute(
        "DELETE FROM pending_inputs WHERE spending_txid = ?1",
        [txid],
    )?;

    conn.execute(
        "DELETE FROM pending_transactions WHERE txid = ?1",
        [txid],
    )?;

    tracing::debug!("Removed confirmed transaction {} from pending tracking", txid);
    Ok(())
}

/// Check if an outpoint is expected to be spent by one of our pending transactions.
/// Returns Some(spending_txid) if found, None otherwise.
pub fn get_pending_tx_for_input(
    conn: &Connection,
    spent_txid: &str,
    spent_vout: u32,
) -> Option<String> {
    conn.query_row(
        "SELECT spending_txid FROM pending_inputs WHERE spent_txid = ? AND spent_vout = ?",
        (spent_txid, spent_vout),
        |row| row.get::<_, String>(0),
    ).ok()
}

/// Remove a conflicted pending transaction and its associated SNICKER UTXO.
/// Called when we detect that an input we expected to spend was spent by a different tx.
pub fn remove_conflicted_transaction(conn: &Connection, conflicted_txid: &str) -> Result<()> {
    tracing::warn!(
        "Removing conflicted transaction {} (input spent by different tx)",
        conflicted_txid
    );

    // Delete the transaction_history partial record for this conflicted transaction.
    let deleted_history = conn.execute(
        "DELETE FROM transaction_history WHERE txid = ? AND tx_hex = ''",
        [conflicted_txid],
    ).unwrap_or(0);

    if deleted_history > 0 {
        tracing::info!(
            "Deleted transaction_history partial record for conflicted tx {}",
            conflicted_txid
        );
    }

    // Delete the SNICKER UTXO that was created for this conflicted transaction.
    let deleted_utxos = conn.execute(
        "DELETE FROM snicker_utxos WHERE txid = ?",
        [conflicted_txid],
    ).unwrap_or(0);

    if deleted_utxos > 0 {
        tracing::info!(
            "Deleted {} orphaned SNICKER UTXO(s) from conflicted tx {}",
            deleted_utxos, conflicted_txid
        );
    }

    // Delete from pending_inputs first (due to foreign key)
    conn.execute(
        "DELETE FROM pending_inputs WHERE spending_txid = ?",
        [conflicted_txid],
    )?;

    // Delete the pending transaction itself
    conn.execute(
        "DELETE FROM pending_transactions WHERE txid = ?",
        [conflicted_txid],
    )?;

    // Restore any SNICKER UTXOs that were marked "pending" for this conflicted tx.
    let restored_utxos = conn.execute(
        "UPDATE snicker_utxos SET status = 'unspent', spent_in_txid = NULL, pending_since = NULL WHERE spent_in_txid = ?",
        [conflicted_txid],
    ).unwrap_or(0);

    if restored_utxos > 0 {
        tracing::info!(
            "Restored {} SNICKER UTXO(s) from pending to unspent (conflicted tx {})",
            restored_utxos, conflicted_txid
        );
    }

    tracing::info!("Cleaned up conflicted transaction {}", conflicted_txid);
    Ok(())
}

/// Get all pending transaction txids
pub fn get_pending_txids(conn: &Connection) -> Vec<String> {
    let mut stmt = match conn.prepare("SELECT txid FROM pending_transactions") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let mut result = Vec::new();
    let mut rows = match stmt.query([]) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    while let Ok(Some(row)) = rows.next() {
        if let Ok(txid) = row.get::<_, String>(0) {
            result.push(txid);
        }
    }
    result
}

/// Get count of pending transactions
pub fn get_pending_transaction_count(conn: &Connection) -> usize {
    conn.query_row(
        "SELECT COUNT(*) FROM pending_transactions",
        [],
        |row| row.get::<_, i64>(0),
    ).unwrap_or(0) as usize
}

// ============================================================
// PROPOSAL PAIRINGS
// ============================================================

/// Record a proposal pairing (proposer UTXO -> target UTXO)
pub fn record_proposal_pairing(
    _conn: &Connection,
    our_txid: &str,
    our_vout: u32,
    target_txid: &str,
    target_vout: u32,
) -> Result<()> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    // This is now tracked via decrypted_proposals table (no separate pairing table)
    // The pairing info is embedded in our_utxo and counterparty_utxo fields
    tracing::debug!(
        "Proposal pairing: {}:{} -> {}:{} (timestamp: {})",
        our_txid, our_vout, target_txid, target_vout, timestamp
    );

    Ok(())
}

/// Delete pairings where the target UTXO was spent
/// Returns number of deleted pairings
pub fn delete_pairings_for_target(conn: &Connection, target_txid: &str, target_vout: u32) -> usize {
    let target_utxo = format!("{}:{}", target_txid, target_vout);

    // Mark proposals targeting this UTXO as 'target_spent' (for proposer proposals)
    let updated = conn.execute(
        "UPDATE decrypted_proposals SET status = 'target_spent', updated_at = ?1
         WHERE counterparty_utxo = ?2 AND role = 'proposer' AND status = 'pending'",
        (
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            &target_utxo,
        ),
    ).unwrap_or(0);

    if updated > 0 {
        tracing::info!(
            "Marked {} proposals as target_spent (target UTXO {}:{} spent)",
            updated, target_txid, target_vout
        );
    }

    updated
}

/// Delete pairings where our UTXO was spent
/// Returns number of deleted pairings
pub fn delete_pairings_for_our_utxo(conn: &Connection, our_txid: &str, our_vout: u32) -> usize {
    let our_utxo = format!("{}:{}", our_txid, our_vout);

    // Mark proposals using this UTXO as 'our_utxo_spent'
    let updated = conn.execute(
        "UPDATE decrypted_proposals SET status = 'our_utxo_spent', updated_at = ?1
         WHERE our_utxo = ?2 AND status = 'pending'",
        (
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            &our_utxo,
        ),
    ).unwrap_or(0);

    if updated > 0 {
        tracing::info!(
            "Marked {} proposals as our_utxo_spent (our UTXO {}:{} spent)",
            updated, our_txid, our_vout
        );
    }

    updated
}

/// Cleanup stale pairings (older than 24 hours)
pub fn cleanup_stale_pairings(conn: &Connection) -> Result<usize> {
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64 - 86400; // 24 hours

    let deleted = conn.execute(
        "DELETE FROM decrypted_proposals WHERE status = 'pending' AND created_at < ?",
        [cutoff],
    )?;

    if deleted > 0 {
        tracing::info!("Cleaned up {} stale proposal pairings", deleted);
    }

    Ok(deleted)
}

/// Get the number of outstanding proposals (for maintaining N proposals)
pub fn count_outstanding_proposals(conn: &Connection) -> usize {
    conn.query_row(
        "SELECT COUNT(*) FROM decrypted_proposals WHERE role = 'proposer' AND status = 'pending'",
        [],
        |row| row.get::<_, i64>(0),
    ).map(|c| c as usize).unwrap_or(0)
}

// ============================================================
// AUTOMATION STATE
// ============================================================

/// Get the current automation state from database
/// Returns default state (Proposer, height 0) if no state exists
pub fn get_automation_state(conn: &Connection) -> AutomationState {
    conn.query_row(
        "SELECT mode, last_coinjoin_height FROM automation_state WHERE id = 1",
        [],
        |row| {
            let mode_str: String = row.get(0)?;
            let height: u32 = row.get(1)?;
            let role = mode_str.parse::<AutomationRole>().unwrap_or(AutomationRole::Proposer);
            Ok(AutomationState {
                role,
                last_coinjoin_height: height,
            })
        },
    ).unwrap_or_default()
}

/// Set the automation state in database
pub fn set_automation_state(conn: &Connection, state: &AutomationState) -> Result<()> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    conn.execute(
        "INSERT INTO automation_state (id, mode, last_coinjoin_height, updated_at)
         VALUES (1, ?1, ?2, ?3)
         ON CONFLICT(id) DO UPDATE SET
            mode = excluded.mode,
            last_coinjoin_height = excluded.last_coinjoin_height,
            updated_at = excluded.updated_at",
        (state.role.as_str(), state.last_coinjoin_height, timestamp),
    )?;

    tracing::info!(
        "Updated automation state: role={}, last_coinjoin_height={}",
        state.role, state.last_coinjoin_height
    );

    Ok(())
}

// ============================================================
// COINJOIN SPENDING TRACKING (via transaction_history)
// ============================================================

/// Record a completed coinjoin and its delta (sats spent/received)
/// delta_sats > 0 means we paid sats, < 0 means we received sats
pub fn record_coinjoin_spending(
    conn: &Connection,
    delta_sats: i64,
    role: &str,
    txid: &str,
    block_height: u32,
) -> Result<()> {
    let tx_type = format!("coinjoin_{}", role);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    // Check if record already exists
    let exists: bool = conn.query_row(
        "SELECT 1 FROM transaction_history WHERE txid = ?",
        [txid],
        |_| Ok(true),
    ).unwrap_or(false);

    if exists {
        // Update existing record with coinjoin info
        conn.execute(
            "UPDATE transaction_history SET tx_type = ?, coinjoin_delta = ? WHERE txid = ?",
            (&tx_type, delta_sats, txid),
        )?;
        tracing::debug!(
            "Updated transaction_history for coinjoin {}: type={}, delta={}",
            txid, tx_type, delta_sats
        );
    } else {
        // Create partial record (will be completed when tx confirms with full details)
        conn.execute(
            "INSERT INTO transaction_history (txid, tx_hex, balance_change_sats, tx_type, block_height, timestamp, created_at, coinjoin_delta)
             VALUES (?, '', 0, ?, ?, ?, ?, ?)",
            (txid, &tx_type, block_height, timestamp, timestamp, delta_sats),
        )?;
        tracing::debug!(
            "Created partial transaction_history for coinjoin {}: type={}, delta={}",
            txid, tx_type, delta_sats
        );
    }

    Ok(())
}

/// Get the role for a coinjoin transaction (proposer/receiver)
pub fn get_coinjoin_role(conn: &Connection, txid: &str) -> Result<Option<String>> {
    let result: Option<String> = conn.query_row(
        "SELECT tx_type FROM transaction_history WHERE txid = ? AND tx_type LIKE 'coinjoin_%'",
        [txid],
        |row| row.get(0),
    ).ok();

    Ok(result.map(|t| t.replace("coinjoin_", "")))
}

/// Get coinjoin info (role, delta) for a transaction
pub fn get_coinjoin_info(conn: &Connection, txid: &str) -> Result<Option<(String, i64)>> {
    conn.query_row(
        "SELECT tx_type, COALESCE(coinjoin_delta, 0) FROM transaction_history WHERE txid = ? AND tx_type LIKE 'coinjoin_%'",
        [txid],
        |row| {
            let tx_type: String = row.get(0)?;
            let delta: i64 = row.get(1)?;
            let role = tx_type.replace("coinjoin_", "");
            Ok((role, delta))
        },
    ).optional().map_err(|e| e.into())
}

/// Get total spending since a given block height
pub fn get_spending_since_block(conn: &Connection, current_height: u32, blocks_ago: u32) -> Result<u64> {
    let start_height = current_height.saturating_sub(blocks_ago);

    let total: i64 = conn.query_row(
        "SELECT COALESCE(SUM(CASE WHEN coinjoin_delta > 0 THEN coinjoin_delta ELSE 0 END), 0)
         FROM transaction_history
         WHERE tx_type LIKE 'coinjoin_%' AND block_height >= ?",
        [start_height],
        |row| row.get(0),
    )?;

    Ok(total as u64)
}

/// Get spending in the last day (approx 144 blocks)
pub fn get_spending_last_day(conn: &Connection, current_height: u32) -> Result<u64> {
    get_spending_since_block(conn, current_height, BLOCKS_PER_DAY)
}

/// Get spending in the last week (approx 1008 blocks)
pub fn get_spending_last_week(conn: &Connection, current_height: u32) -> Result<u64> {
    get_spending_since_block(conn, current_height, BLOCKS_PER_WEEK)
}

/// Get coinjoin history: (block_height, delta_sats, role, txid)
pub fn get_coinjoin_history(conn: &Connection) -> Result<Vec<(u32, i64, String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT block_height, COALESCE(coinjoin_delta, 0), tx_type, txid
         FROM transaction_history
         WHERE tx_type LIKE 'coinjoin_%'
         ORDER BY block_height DESC"
    )?;

    let mut result = Vec::new();
    let mut rows = stmt.query([])?;

    while let Some(row) = rows.next()? {
        let height: u32 = row.get(0)?;
        let delta: i64 = row.get(1)?;
        let tx_type: String = row.get(2)?;
        let txid: String = row.get(3)?;
        let role = tx_type.replace("coinjoin_", "");
        result.push((height, delta, role, txid));
    }

    Ok(result)
}

/// Check if spending limits would be exceeded
pub fn check_spending_limits(
    conn: &Connection,
    current_height: u32,
    proposed_delta: i64,
    daily_limit: u64,
    weekly_limit: u64,
) -> Result<bool> {
    if proposed_delta <= 0 {
        // Receiving or break-even, no spending limit applies
        return Ok(true);
    }

    let daily_spent = get_spending_last_day(conn, current_height)?;
    let weekly_spent = get_spending_last_week(conn, current_height)?;

    let would_exceed_daily = daily_spent + proposed_delta as u64 > daily_limit;
    let would_exceed_weekly = weekly_spent + proposed_delta as u64 > weekly_limit;

    if would_exceed_daily {
        tracing::warn!(
            "Would exceed daily spending limit: {} + {} > {}",
            daily_spent, proposed_delta, daily_limit
        );
        return Ok(false);
    }

    if would_exceed_weekly {
        tracing::warn!(
            "Would exceed weekly spending limit: {} + {} > {}",
            weekly_spent, proposed_delta, weekly_limit
        );
        return Ok(false);
    }

    Ok(true)
}

// ============================================================
// TRANSACTION HISTORY
// ============================================================

/// Record a transaction in history
/// Returns true if newly recorded, false if already existed
pub fn record_transaction(
    conn: &Connection,
    txid: &str,
    tx_hex: &str,
    balance_change_sats: i64,
    tx_type: &str,
    block_height: u32,
    timestamp: u64,
) -> Result<bool> {
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    // Check if record exists
    let existing: Option<(String, String)> = conn.query_row(
        "SELECT tx_hex, tx_type FROM transaction_history WHERE txid = ?",
        [txid],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).ok();

    match existing {
        Some((existing_hex, existing_type)) => {
            if existing_hex.is_empty() {
                // Partial record exists (from coinjoin_spending), update with full data
                conn.execute(
                    "UPDATE transaction_history SET tx_hex = ?, balance_change_sats = ?, block_height = ?, timestamp = ?
                     WHERE txid = ?",
                    (tx_hex, balance_change_sats, block_height, timestamp as i64, txid),
                )?;
                tracing::debug!(
                    "Updated partial transaction record {}: {} sats, type={}",
                    txid, balance_change_sats, existing_type
                );
                Ok(true)
            } else {
                // Full record already exists
                tracing::debug!("Transaction {} already recorded", txid);
                Ok(false)
            }
        }
        None => {
            // Insert new record
            conn.execute(
                "INSERT INTO transaction_history (txid, tx_hex, balance_change_sats, tx_type, block_height, timestamp, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                (txid, tx_hex, balance_change_sats, tx_type, block_height, timestamp as i64, created_at),
            )?;
            tracing::debug!(
                "Recorded transaction {}: {} sats, type={}",
                txid, balance_change_sats, tx_type
            );
            Ok(true)
        }
    }
}

/// Check if a transaction is already recorded
pub fn is_transaction_recorded(conn: &Connection, txid: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM transaction_history WHERE txid = ? AND tx_hex != ''",
        [txid],
        |_| Ok(()),
    ).is_ok()
}

/// Update the transaction type for an existing record
pub fn update_transaction_type(conn: &Connection, txid: &str, tx_type: &str) -> Result<()> {
    conn.execute(
        "UPDATE transaction_history SET tx_type = ? WHERE txid = ?",
        (tx_type, txid),
    )?;
    tracing::debug!("Updated transaction {} type to {}", txid, tx_type);
    Ok(())
}

/// Get all transaction history entries
pub fn get_transaction_history(conn: &Connection) -> Result<Vec<TransactionHistoryEntry>> {
    let mut stmt = conn.prepare(
        "SELECT txid, tx_hex, balance_change_sats, tx_type, block_height, timestamp
         FROM transaction_history
         WHERE tx_hex != ''
         ORDER BY block_height DESC, timestamp DESC"
    )?;

    let mut result = Vec::new();
    let mut rows = stmt.query([])?;

    while let Some(row) = rows.next()? {
        result.push(TransactionHistoryEntry {
            txid: row.get(0)?,
            tx_hex: row.get(1)?,
            balance_change_sats: row.get(2)?,
            tx_type: row.get(3)?,
            block_height: row.get(4)?,
            timestamp: row.get::<_, i64>(5)? as u64,
        });
    }

    Ok(result)
}

/// Get a specific transaction by txid
pub fn get_transaction_by_txid(conn: &Connection, txid: &str) -> Result<Option<TransactionHistoryEntry>> {
    conn.query_row(
        "SELECT txid, tx_hex, balance_change_sats, tx_type, block_height, timestamp
         FROM transaction_history
         WHERE txid = ?",
        [txid],
        |row| {
            Ok(TransactionHistoryEntry {
                txid: row.get(0)?,
                tx_hex: row.get(1)?,
                balance_change_sats: row.get(2)?,
                tx_type: row.get(3)?,
                block_height: row.get(4)?,
                timestamp: row.get::<_, i64>(5)? as u64,
            })
        },
    ).optional().map_err(|e| e.into())
}

// ============================================================
// AUTOMATION LOG
// ============================================================

/// Log an automation action
pub fn log_automation_action(
    conn: &Connection,
    action_type: &str,
    tag: Option<&[u8]>,
    txid: Option<&str>,
    delta: Option<i64>,
    success: bool,
) -> Result<()> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    conn.execute(
        "INSERT INTO automation_log (timestamp, action_type, tag, txid, delta, success)
         VALUES (?, ?, ?, ?, ?, ?)",
        (timestamp, action_type, tag, txid, delta, success),
    )?;

    Ok(())
}

/// Get count of actions of a specific type since a timestamp
pub fn get_action_count_since(
    conn: &Connection,
    action_type: &str,
    since_timestamp: i64,
) -> Result<usize> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM automation_log WHERE action_type = ? AND timestamp >= ?",
        (action_type, since_timestamp),
        |row| row.get(0),
    )?;
    Ok(count as usize)
}
