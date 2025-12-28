# Encrypted Storage Architecture

This document describes the encrypted storage system used by the wallet, including database schemas and the encryption architecture that protects all persistent data.

## Overview

The wallet uses three encrypted files to store sensitive data:

1. **`mnemonic.enc`** - BIP39 recovery seed (encrypted text file)
2. **`wallet.sqlite.enc`** - BDK wallet database (encrypted SQLite)
3. **`snicker.sqlite.enc`** - SNICKER transaction data (encrypted SQLite)

All three files are encrypted using **ChaCha20-Poly1305** with keys derived from the user's password via **Argon2id**.

## Encryption Architecture

### In-Memory Operation

**Security Model:** Encrypted data is decrypted only in RAM, never written to disk as plaintext.

```
┌─────────────────────┐
│  Encrypted Files    │
│  (.enc on disk)     │
└──────────┬──────────┘
           │ Decrypt on load
           ↓
┌─────────────────────┐
│  In-Memory SQLite   │
│  (:memory:)         │
└──────────┬──────────┘
           │ Flush on shutdown/changes
           ↓
┌─────────────────────┐
│  Encrypted Files    │
│  (.enc on disk)     │
└─────────────────────┘
```

### Flush Strategy

- **`mnemonic.enc`**: Decrypted once on load, never changes
- **`wallet.sqlite.enc`**: Flushed on shutdown only (via Drop trait)
- **`snicker.sqlite.enc`**: Flushed on UTXO changes (accept/broadcast/spend) AND shutdown

### Encryption Details

**Algorithm:** ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data)

**Key Derivation:** Argon2id
- Memory: 64 MB (65536 KB)
- Iterations: 3
- Parallelism: 4 threads
- Output: 32 bytes (256 bits)

**File Format:**
```
[Version(1) | Salt(32) | Nonce(12) | Ciphertext | Tag(16)]
```

**Version:** 0x01 (current)

## File Locations

Default data directory structure:

```
~/.local/share/ambient/
├── mainnet/
│   └── <wallet_name>/
│       ├── mnemonic.enc
│       ├── wallet.sqlite.enc
│       └── snicker.sqlite.enc
├── testnet/
├── signet/
└── regtest/
```

## Database Schemas

### 1. mnemonic.enc

**Type:** Encrypted text file (not a database)

**Contents:** BIP39 mnemonic phrase (12 words)

**Example:**
```
witch collapse practice feed shame open despair creek road again ice least
```

**Security:**
- 128 bits of entropy
- Derivation path: BIP86 (Taproot)
- Used to derive all wallet keys

---

### 2. wallet.sqlite.enc

**Type:** Encrypted SQLite database (managed by BDK)

**Purpose:** Stores blockchain data, transactions, and wallet state

**Schema:** Managed by BDK (Bitcoin Dev Kit). Key tables include:

#### `bdk_blocks`
Block chain data for wallet scanning.

#### `bdk_txs`
Wallet transactions with confirmation status.

#### `bdk_utxos`
Unspent transaction outputs (regular UTXOs, not SNICKER).

#### `bdk_descriptors`
Wallet descriptors for key derivation.

**Note:** The exact BDK schema may vary by version. See [BDK documentation](https://bitcoindevkit.org/) for details.

---

### 3. snicker.sqlite.enc

**Type:** Encrypted SQLite database (custom schema)

**Purpose:** Stores SNICKER-specific transaction data, proposals, and automation state

This database contains three main tables (plus partial_utxo_set managed separately):

**Note:** Candidate scanning has been eliminated - candidates are now queried on-demand from the `partial_utxo_set` database which is maintained separately from the encrypted SNICKER database.

---

#### Table: `decrypted_proposals`

**Purpose:** Stores SNICKER proposals that have been successfully decrypted and validated.

**Schema:**
```sql
CREATE TABLE decrypted_proposals (
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
);

CREATE INDEX idx_decrypted_status ON decrypted_proposals(status);
CREATE INDEX idx_decrypted_delta ON decrypted_proposals(delta_sats);
CREATE INDEX idx_utxo_pair ON decrypted_proposals(our_utxo, counterparty_utxo, role, status);
```

**Columns:**
- `tag` - 16-byte unique identifier (BLAKE3 keyed hash)
- `psbt` - Partially Signed Bitcoin Transaction (serialized)
- `tweak_info` - Cryptographic tweak data for proposal
- `role` - Either "proposer" or "receiver"
- `status` - Current state: "pending", "accepted", "rejected", "broadcast", "confirmed"
- `our_utxo` - Our UTXO in format "txid:vout"
- `counterparty_utxo` - Counterparty UTXO in format "txid:vout"
- `delta_sats` - Net change in satoshis (positive = gain, negative = loss)
- `created_at` - Unix timestamp when proposal was created/received
- `updated_at` - Unix timestamp of last status change

**Status Flow:**
```
pending → accepted → broadcast → confirmed
        ↘ rejected
```

**Indexes:**
- `idx_decrypted_status` - Fast filtering by status
- `idx_decrypted_delta` - Fast filtering by profitability
- `idx_utxo_pair` - Fast lookups by UTXO combination

---

#### Table: `snicker_utxos`

**Purpose:** Tracks UTXOs created from SNICKER transactions with their cryptographic secrets.

**Schema:**
```sql
CREATE TABLE snicker_utxos (
    txid TEXT NOT NULL,
    vout INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    script_pubkey BLOB NOT NULL,
    tweaked_privkey BLOB NOT NULL,
    snicker_shared_secret BLOB NOT NULL,
    block_height INTEGER,
    spent BOOLEAN DEFAULT 0,
    spent_in_txid TEXT,
    PRIMARY KEY (txid, vout)
);

CREATE INDEX idx_snicker_utxos_spent ON snicker_utxos(spent);
```

**Columns:**
- `txid` - Transaction ID
- `vout` - Output index
- `amount` - Amount in satoshis
- `script_pubkey` - Bitcoin script (Taproot P2TR)
- `tweaked_privkey` - Private key after ECDH tweak (32 bytes, encrypted)
- `snicker_shared_secret` - ECDH shared secret (32 bytes, encrypted)
- `block_height` - Block where UTXO was confirmed (NULL if unconfirmed)
- `spent` - Whether UTXO has been spent (0 or 1)
- `spent_in_txid` - Transaction that spent this UTXO (NULL if unspent)

**Critical Security Note:**
- `tweaked_privkey` and `snicker_shared_secret` are **highly sensitive**
- Database encryption is essential
- Required to spend SNICKER UTXOs

**Indexes:**
- `idx_snicker_utxos_spent` - Fast filtering of unspent UTXOs

---

#### Table: `automation_log`

**Purpose:** Audit log for automated SNICKER actions.

**Schema:**
```sql
CREATE TABLE automation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    action_type TEXT NOT NULL,
    tag BLOB,
    txid TEXT,
    delta INTEGER,
    success BOOLEAN NOT NULL
);

CREATE INDEX idx_automation_log_timestamp ON automation_log(timestamp);
CREATE INDEX idx_automation_log_action ON automation_log(action_type, timestamp);
```

**Columns:**
- `id` - Auto-incrementing log entry ID
- `timestamp` - Unix timestamp
- `action_type` - Type of automated action (e.g., "auto_accept", "auto_broadcast")
- `tag` - Proposal tag (16 bytes, NULL if not applicable)
- `txid` - Transaction ID (NULL if action failed before broadcast)
- `delta` - Net satoshi change from action (NULL if not applicable)
- `success` - Whether action completed successfully (0 or 1)

**Action Types:**
- `auto_accept` - Automatically accepted a proposal (Basic mode)
- `auto_create` - Automatically created and published a proposal (Advanced mode)
- `auto_broadcast` - Automatically broadcast a transaction
- `auto_reject` - Automatically rejected a proposal

**Indexes:**
- `idx_automation_log_timestamp` - Chronological queries
- `idx_automation_log_action` - Filter by action type

---

### 4. partial_utxo_set (separate database)

**Type:** Unencrypted SQLite database (stored separately from wallet files)

**Purpose:** Maintains a filtered view of blockchain P2TR UTXOs for trustless proposer validation

**Location:** Stored in wallet directory alongside encrypted files (currently unencrypted)

**Schema:**
```sql
CREATE TABLE partial_utxo_set (
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
);

CREATE INDEX idx_partial_utxo_status ON partial_utxo_set(status);
CREATE INDEX idx_partial_utxo_height ON partial_utxo_set(block_height);
CREATE INDEX idx_partial_utxo_amount ON partial_utxo_set(amount);
CREATE INDEX idx_partial_utxo_tx_type ON partial_utxo_set(transaction_type);
```

**Columns:**
- `txid` - Transaction ID
- `vout` - Output index
- `amount` - Amount in satoshis
- `script_pubkey` - Bitcoin script (P2TR only)
- `block_height` - Block where UTXO was created
- `status` - Either "unspent" or "spent"
- `spent_in_txid` - Transaction that spent this UTXO (NULL if unspent)
- `spent_at_height` - Block height where spent (NULL if unspent)
- `created_at` - Unix timestamp when added to set
- `transaction_type` - "v1" for SNICKER transactions, NULL for regular

**Usage:**
- Automatically populated during blockchain scanning
- Filters: P2TR outputs ≥ 5000 sats
- Tracks spent status in real-time
- Used for SNICKER candidate discovery (on-demand queries)
- Provides trustless validation of proposer UTXOs

**Indexes:**
- `idx_partial_utxo_status` - Fast filtering of unspent UTXOs
- `idx_partial_utxo_height` - Block height range queries
- `idx_partial_utxo_amount` - Amount range filtering
- `idx_partial_utxo_tx_type` - Filter SNICKER vs regular transactions

**Security Note:**
- Currently unencrypted (contains no spending keys)
- May be encrypted in future versions for additional privacy
- Safe to delete - will be rebuilt automatically on next sync

See [`AMBIENT_UTXO_MANAGEMENT.md`](AMBIENT_UTXO_MANAGEMENT.md) for complete design details.

---

## Database Lifecycle

### Wallet Generation

```rust
// 1. Generate mnemonic
let mnemonic = Mnemonic::generate(12 words);

// 2. Encrypt and write mnemonic.enc
encrypt_file(mnemonic.as_bytes(), password) → mnemonic.enc

// 3. Create empty wallet.sqlite in memory
let wallet_db = Connection::open_in_memory()?;
// BDK initializes schema on first use

// 4. Encrypt and write wallet.sqlite.enc
serialize(wallet_db) → encrypt_file(...) → wallet.sqlite.enc

// 5. Create snicker.sqlite with schema
let snicker_db = Connection::open_in_memory()?;
Snicker::init_snicker_db(&mut snicker_db)?;

// 6. Encrypt and write snicker.sqlite.enc
serialize(snicker_db) → encrypt_file(...) → snicker.sqlite.enc
```

### Wallet Loading

```rust
// 1. Decrypt mnemonic
let mnemonic_bytes = decrypt_file(fs::read("mnemonic.enc"), password)?;
let mnemonic = Mnemonic::parse(mnemonic_bytes)?;

// 2. Decrypt wallet.sqlite into :memory:
let (wallet_db_manager, wallet_conn) =
    EncryptedMemoryDb::load("wallet.sqlite.enc", password)?;

// 3. Decrypt snicker.sqlite into :memory:
let (snicker_db_manager, snicker_conn) =
    EncryptedMemoryDb::load("snicker.sqlite.enc", password)?;

// 4. All operations happen in memory
// ...

// 5. On shutdown: Drop trait flushes both databases
impl Drop for WalletNode {
    fn drop(&mut self) {
        wallet_db_manager.flush(&wallet_conn);
        snicker_db_manager.flush(&snicker_conn);
    }
}
```

## Database Access Patterns

### Thread Safety

All database connections use `Arc<Mutex<Connection>>` for thread-safe access:

```rust
// Wallet database: tokio::sync::Mutex (async access)
let conn: Arc<tokio::sync::Mutex<Connection>>;
let guard = conn.lock().await;

// SNICKER database: std::sync::Mutex (sync access)
let snicker_conn: Arc<std::sync::Mutex<Connection>>;
let guard = snicker_conn.lock().unwrap();
```

### Transaction Isolation

- Most operations use auto-commit (immediate mode)
- Complex operations use explicit transactions:

```rust
let tx = conn.transaction()?;
// ... multiple operations ...
tx.commit()?;
```

### Backup and Recovery

**Backup:**
```bash
# All wallet data is in three encrypted files:
cp ~/.local/share/ambient/mainnet/mywallet/*.enc /backup/
```

**Recovery:**
```bash
# Restore encrypted files
cp /backup/*.enc ~/.local/share/ambient/mainnet/mywallet/

# Wallet will decrypt on next load with password
```

**Mnemonic Recovery:**
```bash
# If you have the mnemonic phrase, you can recreate the wallet
# SNICKER UTXOs may be lost (requires snicker.sqlite.enc backup)
```

## Security Considerations

### Password Strength

- **Minimum:** 12+ characters recommended
- **Lost password = lost wallet** - no recovery mechanism
- Argon2id intentionally slow (~2 seconds) to resist brute force

### Database Encryption

- **All sensitive data encrypted at rest**
- Plaintext only exists in RAM
- Memory not zeroed on drop (TODO: use zeroize crate)

### SNICKER-Specific Risks

1. **`snicker_utxos` table contains spending keys**
   - Database encryption is critical
   - Losing `snicker.sqlite.enc` = losing access to SNICKER UTXOs
   - Mnemonic alone cannot recover SNICKER UTXOs

2. **Proposal replay protection**
   - `tag` field ensures unique proposals
   - Prevents double-spending via same proposal

3. **Automation safety**
   - `automation_log` provides audit trail
   - Review logs for unexpected automated actions

## Testing

Test databases use unencrypted file-based SQLite:

```rust
#[cfg(test)]
let conn = Connection::open(&temp_db_path)?;
Snicker::init_snicker_db(&mut conn)?;
```

Production always uses encrypted in-memory databases.

## Future Enhancements (v2)

- [ ] Password change functionality (re-encrypt all three files)
- [ ] Database migration system for schema upgrades
- [ ] Per-spending-event decryption (decrypt only needed SNICKER UTXO keys)
- [ ] Secure memory zeroing with `zeroize` crate
- [ ] Database integrity checks on load
- [ ] Optional cloud backup with client-side encryption
- [ ] Multi-signature support for SNICKER proposals

## References

- **BDK:** https://bitcoindevkit.org/
- **SNICKER Protocol:** See `docs/PROTOCOL.md`
- **Encryption Implementation:** See `src/encryption.rs`
- **Database Initialization:** See `src/snicker/mod.rs` (lines 824-931)
