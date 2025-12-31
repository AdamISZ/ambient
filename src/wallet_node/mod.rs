//! Wallet node implementation
//!
//! This module provides the main wallet functionality including:
//! - Wallet creation and loading with encrypted storage
//! - Blockchain synchronization via Kyoto light client
//! - UTXO management (both regular and SNICKER)
//! - Transaction building and broadcasting (see tx_builder submodule)
//! - Coin selection algorithms (see coin_selection submodule)

pub mod coin_selection;
pub mod tx_builder;

pub(crate) use coin_selection::SelectedUtxos;

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use zeroize::Zeroizing;
use directories::ProjectDirs;
use tokio::select;
use tokio::sync::{Mutex, broadcast};
use tracing::info;

// Import signer module
// Note: Using ambient::signer instead of crate::signer due to Cargo compilation quirk
use crate::signer::{Signer, InMemorySigner};

use bdk_wallet::{
    PersistedWallet,
    bitcoin::{Network, Address, Amount, FeeRate, Transaction, Txid, psbt::Psbt, hashes::Hash},
    keys::{
        bip39::{Language, Mnemonic, WordCount},
        DerivableKey, ExtendedKey, GeneratedKey, GeneratableKey,
    },
    rusqlite::Connection,
    miniscript::Tap,
    KeychainKind, Wallet,
};

use bdk_kyoto::builder::{Builder, BuilderExt};
use bdk_kyoto::{Info, LightClient, Receiver, ScanType, UnboundedReceiver, Warning, TxBroadcast, TxBroadcastPolicy, HeaderCheckpoint};

use crate::encryption::WalletEncryption;
use crate::fee;
use crate::partial_utxo_set::{PartialUtxoSet, UtxoStatus};

const RECOVERY_LOOKAHEAD: u32 = 50;
const NUM_CONNECTIONS: u8 = 1;

/// Event emitted when the wallet state changes due to blockchain updates
#[derive(Debug, Clone)]
pub struct WalletUpdate {
    /// New blockchain height after update
    pub height: u32,
    /// Total balance in sats (regular + SNICKER)
    pub balance_sats: u64,
    /// Optional status message for GUI display (e.g., "Scanning blocks: 50/1000")
    pub status_message: Option<String>,
}

/// Represents a UTXO that can be either from the regular BDK wallet or a SNICKER UTXO
#[derive(Debug, Clone)]
pub enum WalletUtxo {
    /// Regular wallet UTXO with derivation path
    Regular(bdk_wallet::LocalOutput),
    /// SNICKER UTXO (private key fetched on-demand for signing)
    Snicker {
        outpoint: bdk_wallet::bitcoin::OutPoint,
        amount: u64,
        script_pubkey: bdk_wallet::bitcoin::ScriptBuf,
    },
}

impl WalletUtxo {
    /// Get the outpoint for this UTXO
    pub fn outpoint(&self) -> bdk_wallet::bitcoin::OutPoint {
        match self {
            WalletUtxo::Regular(utxo) => utxo.outpoint,
            WalletUtxo::Snicker { outpoint, .. } => *outpoint,
        }
    }

    /// Get the amount for this UTXO in satoshis
    pub fn amount(&self) -> u64 {
        match self {
            WalletUtxo::Regular(utxo) => utxo.txout.value.to_sat(),
            WalletUtxo::Snicker { amount, .. } => *amount,
        }
    }

    /// Get the amount for this UTXO as Amount type
    pub fn value(&self) -> bdk_wallet::bitcoin::Amount {
        match self {
            WalletUtxo::Regular(utxo) => utxo.txout.value,
            WalletUtxo::Snicker { amount, .. } => bdk_wallet::bitcoin::Amount::from_sat(*amount),
        }
    }

    /// Get the script_pubkey for this UTXO
    pub fn script_pubkey(&self) -> &bdk_wallet::bitcoin::ScriptBuf {
        match self {
            WalletUtxo::Regular(utxo) => &utxo.txout.script_pubkey,
            WalletUtxo::Snicker { script_pubkey, .. } => script_pubkey,
        }
    }

    /// Get the TxOut for this UTXO
    pub fn txout(&self) -> bdk_wallet::bitcoin::TxOut {
        match self {
            WalletUtxo::Regular(utxo) => utxo.txout.clone(),
            WalletUtxo::Snicker { amount, script_pubkey, .. } => {
                bdk_wallet::bitcoin::TxOut {
                    value: bdk_wallet::bitcoin::Amount::from_sat(*amount),
                    script_pubkey: script_pubkey.clone(),
                }
            }
        }
    }
}

/// High-level struct encapsulating wallet + node + requester
pub struct WalletNode {
    pub wallet: Arc<Mutex<PersistedWallet<Connection>>>,
    pub conn: Arc<Mutex<Connection>>,
    pub requester: bdk_kyoto::Requester,
    pub network: Network,
    /// Signing abstraction for PSBT signing and SNICKER DH operations
    /// Encapsulates private key access with encryption at rest
    signer: Arc<dyn Signer>,
    /// Optional Bitcoin Core RPC client (required for proposer mode scanning)
    pub(crate) rpc_client: Option<Arc<bdk_bitcoind_rpc::bitcoincore_rpc::Client>>,
    /// Wallet name (for locating correct headers.db)
    wallet_name: String,
    /// Shared in-memory SNICKER database connection (uses std::sync::Mutex for sync access)
    snicker_conn: Arc<std::sync::Mutex<Connection>>,
    /// Broadcast channel for wallet update events
    update_tx: broadcast::Sender<WalletUpdate>,
    /// Encrypted in-memory wallet database (for flush on shutdown)
    wallet_db: crate::encryption::EncryptedMemoryDb,
    /// Fee estimator for real-time fee rate estimates
    pub fee_estimator: fee::FeeEstimator,
    /// Encrypted in-memory SNICKER database (for flush on UTXO changes)
    snicker_db: crate::encryption::EncryptedMemoryDb,
    /// Partial UTXO set for trustless proposer UTXO validation
    pub partial_utxo_set: Arc<Mutex<PartialUtxoSet>>,
}

/// Selected UTXOs for spending (hybrid selection result)

impl WalletNode {
    // ============================================================
    // PUBLIC ENTRY POINTS
    // ============================================================

    /// Get the wallet name
    pub fn name(&self) -> &str {
        &self.wallet_name
    }

    /// Subscribe to wallet update events (balance changes, new blocks, etc.)
    /// Returns a receiver that will receive WalletUpdate events whenever the blockchain state changes
    pub fn subscribe_to_updates(&self) -> broadcast::Receiver<WalletUpdate> {
        self.update_tx.subscribe()
    }

    /// Generate a new wallet (new mnemonic), persist it, and then load it.
    /// Generate a new wallet with encrypted storage
    ///
    /// TODO(v2): Add password strength enforcement
    ///
    /// # Arguments
    /// * `name` - Wallet name
    /// * `network_str` - Network ("mainnet", "signet", "regtest", "testnet")
    /// * `recovery_height` - Blockchain height to start scanning from
    /// * `password` - Password for encrypting wallet files
    ///
    /// # Returns
    /// Tuple of (WalletNode, Mnemonic)
    pub async fn generate(
        name: &str,
        network_str: &str,
        recovery_height: u32,
        password: &str,
    ) -> Result<(Self, Mnemonic)> {
        let (wallet_dir, wallet_db_enc_path, snicker_db_enc_path, mnemonic_path) = Self::wallet_paths(name, network_str)?;
        fs::create_dir_all(&wallet_dir)?;

        let gen: GeneratedKey<_, Tap> =
            Mnemonic::generate((WordCount::Words12, Language::English))
                .map_err(|_| anyhow!("Mnemonic generation failed"))?;
        let mnemonic = Mnemonic::parse_in(Language::English, gen.to_string())?;

        // Encrypt mnemonic before writing to disk
        let mnemonic_plaintext = mnemonic.to_string();
        let encrypted = WalletEncryption::encrypt_file(mnemonic_plaintext.as_bytes(), password)?;
        fs::write(&mnemonic_path, encrypted)?;
        info!("🔑 Generated new mnemonic for wallet '{name}' (encrypted)");

        // Create empty BDK wallet database and encrypt it
        let temp_wallet_db = tempfile::NamedTempFile::new()?;
        let temp_wallet_conn = rusqlite::Connection::open(temp_wallet_db.path())?;
        // BDK will create its tables when we first load the wallet
        drop(temp_wallet_conn);
        let wallet_db_plaintext = fs::read(temp_wallet_db.path())?;
        let wallet_db_encrypted = WalletEncryption::encrypt_file(&wallet_db_plaintext, password)?;
        fs::write(&wallet_db_enc_path, wallet_db_encrypted)?;
        info!("💾 Created encrypted wallet database");

        // Create empty SNICKER database with schema and encrypt it
        let temp_snicker_db = tempfile::NamedTempFile::new()?;
        let mut temp_snicker_conn = rusqlite::Connection::open(temp_snicker_db.path())?;
        crate::snicker::Snicker::init_snicker_db(&mut temp_snicker_conn)?;
        drop(temp_snicker_conn);
        let snicker_db_plaintext = fs::read(temp_snicker_db.path())?;
        let snicker_db_encrypted = WalletEncryption::encrypt_file(&snicker_db_plaintext, password)?;
        fs::write(&snicker_db_enc_path, snicker_db_encrypted)?;
        info!("💾 Created encrypted SNICKER database");

        let node = Self::load(name, network_str, recovery_height, password, None).await?;

        Ok((node, mnemonic))
    }

    /// Load an existing wallet by name and start the Kyoto node for it.
    ///
    /// TODO(v2): Add password change functionality
    /// TODO(v2): Encrypt databases on shutdown, decrypt on load (currently unencrypted)
    ///
    /// # Arguments
    /// * `name` - Wallet name
    /// * `network_str` - Network ("mainnet", "signet", "regtest", "testnet")
    /// * `recovery_height` - Blockchain height to start scanning from
    /// * `password` - Password for decrypting wallet files
    ///
    /// # Returns
    /// WalletNode instance
    pub async fn load(
        name: &str,
        network_str: &str,
        recovery_height: u32,
        password: &str,
        peer: Option<String>,
    ) -> Result<Self> {
        let network = Self::parse_network(network_str)?;
        let (wallet_dir, wallet_db_enc_path, snicker_db_enc_path, mnemonic_path) =
            Self::wallet_paths(name, network_str)?;
        fs::create_dir_all(&wallet_dir)?; // okay if already exists

        // Decrypt mnemonic
        let mnemonic: Mnemonic = if mnemonic_path.exists() {
            let encrypted = fs::read(&mnemonic_path)?;
            let decrypted = WalletEncryption::decrypt_file(&encrypted, password)?;
            let mnemonic_str = std::str::from_utf8(&decrypted)?;
            Mnemonic::parse(mnemonic_str.trim())?
        } else {
            return Err(anyhow!(
                "Mnemonic file not found for wallet '{name}' at {:?}",
                mnemonic_path
            ));
        };

        // Load encrypted wallet database into memory
        let (wallet_db, conn) = if wallet_db_enc_path.exists() {
            crate::encryption::EncryptedMemoryDb::load(&wallet_db_enc_path, password)?
        } else {
            return Err(anyhow!(
                "Encrypted wallet database not found for wallet '{name}' at {:?}",
                wallet_db_enc_path
            ));
        };

        let (wallet, conn) = Self::load_or_create_wallet(&mnemonic, network, conn)?;

        // Flush wallet database to encrypted file after initial load/create
        wallet_db.flush(&conn)?;
        tracing::info!("💾 Flushed wallet database after initial load/create");

        let (requester, update_subscriber) =
            Self::start_node(&wallet, network, recovery_height, name, peer, &wallet_dir).await?;

        // Derive xprv from mnemonic for SNICKER operations
        let xkey: ExtendedKey = mnemonic.into_extended_key()?;
        let xprv = xkey
            .into_xprv(network)
            .ok_or_else(|| anyhow!("Unable to derive xprv from mnemonic"))?;

        // Wrap in Arc<Mutex<>> for shared access
        let wallet = Arc::new(Mutex::new(wallet));
        let conn = Arc::new(Mutex::new(conn));
        let update_subscriber = Arc::new(Mutex::new(update_subscriber));

        // Load encrypted SNICKER database into memory
        let (snicker_db, snicker_conn_raw) = if snicker_db_enc_path.exists() {
            crate::encryption::EncryptedMemoryDb::load(&snicker_db_enc_path, password)?
        } else {
            return Err(anyhow!(
                "Encrypted SNICKER database not found for wallet '{name}' at {:?}",
                snicker_db_enc_path
            ));
        };
        let snicker_conn = Arc::new(std::sync::Mutex::new(snicker_conn_raw));

        // NOTE: We no longer subscribe to SNICKER scripts via Kyoto
        // SNICKER UTXO spends are detected via block scanning (see background_sync)
        // This architectural separation means:
        // - BDK/Kyoto: Handles regular descriptor-based wallet UTXOs
        // - Block scanning: Handles SNICKER UTXO tracking independently
        // As a result, the bdk-kyoto patch (which added arbitrary script subscription) is no longer needed

        // Create InMemorySigner with encrypted xprv
        // This encapsulates private key access with encryption at rest in memory
        let signer = InMemorySigner::new(xprv, password, network)?;
        let signer = Arc::new(signer) as Arc<dyn Signer>;

        // Get account-level xpub from signer for creating public descriptors
        let account_xpub = signer.get_account_xpub()?;

        // Create PUBLIC descriptors using xpub (safe to store/leak)
        // The last two levels (0 or 1 for change, and * for address index) are unhardened,
        // so all addresses can be derived from the account xpub without exposing private keys
        let external_desc = format!("tr({}/0/*)", account_xpub);
        let internal_desc = format!("tr({}/1/*)", account_xpub);

        // Initialize fee estimator with default settings (5 min cache, 10s timeout)
        let fee_estimator = fee::FeeEstimator::new(network, 300, 10);

        // Load config for partial UTXO set settings
        let config = crate::config::Config::load()?;

        // Initialize partial UTXO set database
        let partial_utxo_db_path = wallet_dir.join("partial_utxo_set.db");
        let partial_utxo_set = PartialUtxoSet::new(
            &partial_utxo_db_path,
            config.partial_utxo_set.min_utxo_amount_sats,
            config.partial_utxo_set.scan_window_blocks,
        )?;
        let partial_utxo_set = Arc::new(Mutex::new(partial_utxo_set));

        // Note: Initial scan is deferred to background_sync after node syncs
        // This prevents blocking the GUI and ensures blocks are available
        tracing::info!("📊 Partial UTXO set will be populated after initial sync completes");

        // Create broadcast channel for wallet update events
        // Capacity of 100 means we can buffer up to 100 updates before dropping old ones
        let (update_tx, _update_rx) = broadcast::channel::<WalletUpdate>(100);

        // Spawn background task to auto-sync
        let wallet_clone = wallet.clone();
        let conn_clone = conn.clone();
        let wallet_db_clone = wallet_db.clone();
        let sub_clone = update_subscriber.clone();
        let snicker_conn_clone = snicker_conn.clone();
        let snicker_db_clone = snicker_db.clone();
        let requester_clone = requester.clone();
        let wallet_name_clone = name.to_string();
        let network_clone = network;
        let external_desc_clone = external_desc.clone();
        let internal_desc_clone = internal_desc.clone();
        let update_tx_clone = update_tx.clone();
        let partial_utxo_set_clone = partial_utxo_set.clone();
        tokio::spawn(async move {
            Self::background_sync(
                wallet_clone,
                conn_clone,
                wallet_db_clone,
                sub_clone,
                snicker_conn_clone,
                snicker_db_clone,
                requester_clone,
                wallet_name_clone,
                network_clone,
                external_desc_clone,
                internal_desc_clone,
                update_tx_clone,
                partial_utxo_set_clone,
            )
            .await;
        });

        info!("✅ Wallet loaded. Auto-sync enabled in background.");

        Ok(Self {
            wallet,
            conn,
            requester,
            network,
            signer,
            rpc_client: None,
            wallet_name: name.to_string(),
            snicker_conn,
            update_tx,
            wallet_db,
            snicker_db,
            fee_estimator,
            partial_utxo_set,
        })
    }

    // ============================================================
    // INTERNAL HELPERS
    // ============================================================

    fn parse_network(s: &str) -> Result<Network> {
        Ok(match s {
            "mainnet" => Network::Bitcoin,
            "signet"  => Network::Signet,
            "regtest" => Network::Regtest,
            "testnet" => Network::Testnet,
            _ => return Err(anyhow!("invalid network: {s}")),
        })
    }

    fn wallet_paths(name: &str, network_str: &str) -> Result<(PathBuf, PathBuf, PathBuf, PathBuf)> {
        let project_dirs = ProjectDirs::from("org", "code", "ambient")
            .ok_or_else(|| anyhow!("Cannot determine project dir"))?;

        let wallet_dir = project_dirs.data_local_dir().join(network_str).join(name);
        let wallet_db_path = wallet_dir.join("wallet.sqlite.enc");
        let snicker_db_path = wallet_dir.join("snicker.sqlite.enc");
        let mnemonic_path = wallet_dir.join("mnemonic.enc");

        Ok((wallet_dir, wallet_db_path, snicker_db_path, mnemonic_path))
    }

    fn load_or_create_wallet(
        mnemonic: &Mnemonic,
        network: Network,
        mut conn: Connection,
    ) -> Result<(PersistedWallet<Connection>, Connection)> {
        let xkey: ExtendedKey = mnemonic.clone().into_extended_key()?;
        let xprv = xkey
            .into_xprv(network)
            .ok_or_else(|| anyhow!("Unable to derive xprv from mnemonic"))?;

        // Derive account-level keys for wallet operations
        // BIP86 uses m/86h/cointype/h/0h as the account path
        let coin_type = if network == Network::Bitcoin { 0 } else { 1 };
        let secp = bdk_wallet::bitcoin::secp256k1::Secp256k1::new();
        let account_path = bdk_wallet::bitcoin::bip32::DerivationPath::from_str(
            &format!("m/86h/{}h/0h", coin_type)
        )?;
        let account_xpriv = xprv.derive_priv(&secp, &account_path)?;
        let account_xpub = bdk_wallet::bitcoin::bip32::Xpub::from_priv(&secp, &account_xpriv);

        // Create PUBLIC descriptors using xpub (safe to store/leak)
        // Format: tr(xpub/{change}/*) where change is 0 (external) or 1 (internal)
        let external_desc = format!("tr({}/0/*)", account_xpub);
        let internal_desc = format!("tr({}/1/*)", account_xpub);

        tracing::debug!("Descriptor contains private key: {}", external_desc.contains("prv"));
        tracing::info!("📝 Using PUBLIC descriptors with xpub (private keys not in descriptors)");

        info!("💾 Wallet database: in-memory (encrypted)");

        // Check if wallet already exists by trying to load it
        // NOTE: We do NOT call .extract_keys() because descriptors don't contain private keys
        // Signing will be done manually using account_xpriv
        // Descriptors are public (xpub) so Box::leak is safe (no sensitive data)
        let external_desc_static: &'static str = Box::leak(external_desc.clone().into_boxed_str());
        let internal_desc_static: &'static str = Box::leak(internal_desc.clone().into_boxed_str());

        tracing::debug!("Loading wallet with descriptors and extract_keys()");
        info!("   External: {} chars", external_desc_static.len());
        info!("   Internal: {} chars", internal_desc_static.len());

        // DEBUG: Check what tables exist in the database
        let tables: Vec<String> = conn.prepare("SELECT name FROM sqlite_master WHERE type='table'")?
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        info!("🔍 Database tables: {:?}", tables);

        // DEBUG: Check if there's any chain data (BDK stores chain state in bdk_blocks)
        if tables.contains(&"bdk_blocks".to_string()) {
            let count: i64 = conn.query_row("SELECT COUNT(*) FROM bdk_blocks", [], |row| row.get(0))?;
            info!("🔍 bdk_blocks table has {} rows", count);

            // Also check if there's a tip (highest block)
            if count > 0 {
                let tip_height: Option<u32> = conn.query_row(
                    "SELECT MAX(height) FROM bdk_blocks",
                    [],
                    |row| row.get(0)
                ).ok();
                info!("🔍 Highest block in database: {:?}", tip_height);
            }
        }

        let maybe_wallet = Wallet::load()
            .descriptor(KeychainKind::External, Some(external_desc_static))
            .descriptor(KeychainKind::Internal, Some(internal_desc_static))
            // .extract_keys() NOT called - descriptors are public (xpub), no keys to extract
            // Signing will be done manually using account_xpriv
            .check_network(network)
            .load_wallet(&mut conn)?;

        info!("🔍 Wallet load result: {}", if maybe_wallet.is_some() { "Found existing wallet" } else { "No wallet found - will create new" });

        let wallet = if let Some(mut loaded) = maybe_wallet {
            info!("✅ Loaded existing wallet from database");

            let initial_external_index = loaded.derivation_index(KeychainKind::External).unwrap_or(0);
            let initial_internal_index = loaded.derivation_index(KeychainKind::Internal).unwrap_or(0);
            info!("📊 Initial derivation indices: External={}, Internal={}",
                initial_external_index, initial_internal_index);

            // CRITICAL FIX: After loading, we must ensure the SPK index is populated!
            // When a wallet is loaded from DB, the index might not include all UTXOs
            // that were added in previous sessions. We need to reveal addresses up to
            // the highest index we've used to repopulate the SPK index.

            // Find the highest derivation index used in each keychain
            let mut max_external = 0u32;
            let mut max_internal = 0u32;
            for utxo in loaded.list_unspent() {
                match utxo.keychain {
                    KeychainKind::External => max_external = max_external.max(utxo.derivation_index),
                    KeychainKind::Internal => max_internal = max_internal.max(utxo.derivation_index),
                }
            }

            // tracing::debug!("Ensuring SPK index includes lookahead: External up to {}, Internal up to {}",
            //     max_external + RECOVERY_LOOKAHEAD, max_internal + RECOVERY_LOOKAHEAD);

            // Use peek_address() to ensure scripts are in SPK index WITHOUT advancing derivation index
            // This allows the light client to scan for these addresses while keeping
            // the next user-facing address at the first unused one
            for index in 0..=(max_external + RECOVERY_LOOKAHEAD) {
                let _ = loaded.peek_address(KeychainKind::External, index);
            }
            for index in 0..=(max_internal + RECOVERY_LOOKAHEAD) {
                let _ = loaded.peek_address(KeychainKind::Internal, index);
            }

            // No need to persist - peek doesn't change derivation index
            let final_external_index = loaded.derivation_index(KeychainKind::External).unwrap_or(0);
            let final_internal_index = loaded.derivation_index(KeychainKind::Internal).unwrap_or(0);

            // tracing::debug!("SPK index populated with {} external and {} internal scripts",
            //     max_external + RECOVERY_LOOKAHEAD + 1, max_internal + RECOVERY_LOOKAHEAD + 1);
            info!("📊 Final derivation indices: External={}, Internal={} (should be unchanged)",
                final_external_index, final_internal_index);
            loaded
        } else {
            info!("✅ Creating new wallet with descriptors");
            let mut new_wallet = Wallet::create(external_desc.clone(), internal_desc.clone())
                .network(network)
                .lookahead(RECOVERY_LOOKAHEAD)
                .create_wallet(&mut conn)?;

            // Force derivation of lookahead scripts for new wallet
            for index in 0..RECOVERY_LOOKAHEAD {
                let _ = new_wallet.peek_address(KeychainKind::External, index);
                let _ = new_wallet.peek_address(KeychainKind::Internal, index);
            }
            new_wallet.persist(&mut conn)?;
            // tracing::debug!("Derived and persisted {} lookahead scripts", RECOVERY_LOOKAHEAD);

            let external_index = new_wallet.derivation_index(KeychainKind::External).unwrap_or(0);
            let internal_index = new_wallet.derivation_index(KeychainKind::Internal).unwrap_or(0);
            info!("📊 New wallet derivation indices: External={}, Internal={}", external_index, internal_index);

            new_wallet
        };

        // NOTE: Wallet::create() with xprv-containing descriptors should automatically
        // extract and add signers for both External and Internal keychains.
        // However, Wallet::load() does NOT restore signers (private keys aren't in DB).
        //
        // For now, we'll trust that Wallet::create() sets up signers correctly.
        // If signing issues persist after wallet reload, we'll need to re-add signers
        // by re-parsing the descriptor strings (which requires storing them encrypted).

        info!("🔑 Wallet created/loaded - signers should be present for both keychains");

        Ok((wallet, conn))
    }

    async fn start_node(
        wallet: &PersistedWallet<Connection>,
        network: Network,
        from_height: u32,
        wallet_name: &str,
        peer: Option<String>,
        wallet_dir: &std::path::Path,
    ) -> Result<(bdk_kyoto::Requester, bdk_kyoto::UpdateSubscriber)> {
        use super::blockchain_data::{BlockchainDataProvider, MempoolSpaceApi};

        // Get checkpoint from wallet's local chain if it exists, otherwise use genesis or requested height
        let wallet_tip = wallet.local_chain().tip();

        // Load config to get scan window for partial UTXO set
        let config = crate::config::Config::load().ok();
        let scan_window = config
            .as_ref()
            .map(|c| c.partial_utxo_set.scan_window_blocks)
            .unwrap_or(1000);

        let (checkpoint_height, checkpoint_hash) = if wallet_tip.height() > 0 {
            // EXISTING WALLET - distinguish between normal reload and first-time partial UTXO set
            let partial_utxo_db_path = wallet_dir.join("partial_utxo_set.db");
            let needs_initial_scan = !partial_utxo_db_path.exists();

            if needs_initial_scan {
                // Existing wallet but partial UTXO set is new - need to scan last scan_window blocks
                // Set checkpoint back to allow Kyoto to have headers for those blocks
                let lookback_height = wallet_tip.height().saturating_sub(scan_window);

                if let Some(checkpoint) = wallet.local_chain().range(lookback_height..=lookback_height).next() {
                    info!("📍 Existing wallet at height {} but partial UTXO set is new - checkpoint at {} (scan_window: {})",
                          wallet_tip.height(), lookback_height, scan_window);
                    (checkpoint.height(), checkpoint.hash())
                } else {
                    // Fallback to tip if we can't get the lookback block
                    tracing::warn!("⚠️  Could not set checkpoint back {} blocks, using tip", scan_window);
                    (wallet_tip.height(), wallet_tip.hash())
                }
            } else {
                // Normal reload - partial UTXO set exists, just catch up from tip
                info!("📍 Wallet already synced to height {}, resuming from tip", wallet_tip.height());
                (wallet_tip.height(), wallet_tip.hash())
            }
        } else if from_height == 0 {
            // New wallet starting from genesis
            use bdk_wallet::bitcoin::blockdata::constants::genesis_block;
            info!("📍 New wallet starting from genesis (height 0)");
            (0, genesis_block(network).block_hash())
        } else {
            // New wallet with requested recovery height - fetch block hash from API
            info!("📍 New wallet requesting recovery from height {}, fetching block hash...", from_height);

            let api = MempoolSpaceApi::new(network).with_timeout(15);
            match api.get_block_hash(from_height).await {
                Ok(block_hash) => {
                    info!("✅ Successfully fetched block hash for height {}: {}", from_height, block_hash);
                    (from_height, block_hash)
                }
                Err(e) => {
                    // Fallback to genesis if API fails
                    use bdk_wallet::bitcoin::blockdata::constants::genesis_block;
                    tracing::warn!(
                        "⚠️  Failed to fetch block hash for height {} ({}), falling back to genesis",
                        from_height, e
                    );
                    (0, genesis_block(network).block_hash())
                }
            }
        };

        let checkpoint = HeaderCheckpoint::new(checkpoint_height, checkpoint_hash);
        let scan_type = ScanType::Recovery {
            used_script_index: RECOVERY_LOOKAHEAD,
            checkpoint,
        };
        info!("🔍 ========== KYOTO SYNC STARTING ==========");
        info!("🔍 Checkpoint height: {}", checkpoint_height);
        info!("🔍 Checkpoint hash: {}", checkpoint_hash);
        info!("🔍 Scan type: Recovery with lookahead {}", RECOVERY_LOOKAHEAD);
        info!("🔍 ==========================================");

        // Select peer: use configured peer if provided, otherwise use network default
        let peer_addr = if let Some(peer_str) = peer {
            // Parse configured peer
            peer_str.parse::<SocketAddr>()
                .with_context(|| format!("Invalid peer address: {}", peer_str))?
        } else {
            // Use network default
            match network {
                Network::Regtest => {
                    // Connect to local regtest node
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18444)
                }
                Network::Signet => {
                    // Public signet node (hardcoded fallback from Bitcoin Core)
                    // Source: https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(178, 128, 221, 177)), 38333)
                }
                Network::Bitcoin | Network::Testnet => {
                    // TODO: Add mainnet/testnet peers
                    return Err(anyhow!("Mainnet/Testnet peers not configured yet"));
                }
                _ => {
                    return Err(anyhow!("Unsupported network: {:?}", network));
                }
            }
        };
        info!("🔗 Connecting to peer: {}", peer_addr);

        // Create Kyoto peer database directory (unique per wallet to avoid conflicts)
        let project_dirs = ProjectDirs::from("org", "code", "ambient")
            .ok_or_else(|| anyhow!("Cannot determine project dir"))?;

        // WORKAROUND: bip157 crate ignores the data_dir parameter and always uses "./light_client_data/{network}/"
        // relative to the current working directory. This is a known issue.
        // For now, we'll just use the default path and document this limitation.
        // TODO: File an issue upstream or patch bip157 to respect data_dir

        let kyoto_db_path_intended = project_dirs
            .data_local_dir()
            .join(format!("{:?}", network).to_lowercase())
            .join(wallet_name)
            .join("kyoto_peers");

        // Create the directory anyway for future use
        std::fs::create_dir_all(&kyoto_db_path_intended)?;

        // Use the actual path that bip157 will use (./light_client_data/{network}/)
        let kyoto_db_path_actual = std::path::PathBuf::from("light_client_data");
        std::fs::create_dir_all(&kyoto_db_path_actual)?;

        tracing::warn!(
            "⚠️  Kyoto database location: {} (bip157 ignores our configured path: {})",
            kyoto_db_path_actual.display(),
            kyoto_db_path_intended.display()
        );

        let LightClient {
            requester,
            info_subscriber,
            warning_subscriber,
            update_subscriber,
            node,
        } = Builder::new(network)
            .add_peer(peer_addr)
            .required_peers(NUM_CONNECTIONS)
            .data_dir(kyoto_db_path_actual)  // This will be ignored anyway, but pass it for API compatibility
            .build_with_wallet(wallet, scan_type)
            .unwrap();

        tracing::debug!("Node built - bdk_kyoto 0.15.3 will auto-register wallet scripts");

        tokio::spawn(async move {
            if let Err(e) = node.run().await {
                tracing::error!("Kyoto node terminated with error: {e:?}");
            } else {
                tracing::info!("Kyoto node exited cleanly.");
            }
        });

        tokio::spawn(async move {
            trace_logs(info_subscriber, warning_subscriber).await;
        });

        Ok((requester, update_subscriber))
    }

    async fn background_sync(
        wallet: Arc<Mutex<PersistedWallet<Connection>>>,
        conn: Arc<Mutex<Connection>>,
        wallet_db: crate::encryption::EncryptedMemoryDb,
        update_subscriber: Arc<Mutex<bdk_kyoto::UpdateSubscriber>>,
        snicker_conn: Arc<std::sync::Mutex<Connection>>,
        snicker_db: crate::encryption::EncryptedMemoryDb,
        requester: bdk_kyoto::Requester,
        wallet_name: String,
        network: Network,
        external_descriptor: String,
        internal_descriptor: String,
        update_tx: broadcast::Sender<WalletUpdate>,
        partial_utxo_set: Arc<Mutex<PartialUtxoSet>>,
    ) {
        loop {
            let mut sub = update_subscriber.lock().await;
            let update_result = sub.update().await;
            drop(sub); // Release lock before processing

            match update_result {
                Ok(update) => {
                    let mut wallet_guard = wallet.lock().await;
                    let mut conn_guard = conn.lock().await;

                    info!("📦 Auto-sync: received update");
                    if let Err(e) = wallet_guard.apply_update(update) {
                        tracing::error!("Failed to apply update: {e}");
                        continue;
                    }

                    // CRITICAL: After applying blockchain updates, repopulate SPK index
                    // This ensures newly discovered UTXOs can be signed
                    let mut max_external = 0u32;
                    let mut max_internal = 0u32;
                    for utxo in wallet_guard.list_unspent() {
                        match utxo.keychain {
                            KeychainKind::External => max_external = max_external.max(utxo.derivation_index),
                            KeychainKind::Internal => max_internal = max_internal.max(utxo.derivation_index),
                        }
                    }
                    if max_external > 0 || max_internal > 0 {
                        // tracing::debug!("🔧 Repopulating SPK index after scan: External up to {}, Internal up to {}",
                        //     max_external, max_internal);
                        // Use peek_address() to add scripts to SPK index WITHOUT advancing derivation index
                        // This allows the light client to scan for these addresses while keeping
                        // the next user-facing address at the first unused one
                        for index in 0..=(max_external + RECOVERY_LOOKAHEAD) {
                            let _ = wallet_guard.peek_address(KeychainKind::External, index);
                        }
                        for index in 0..=(max_internal + RECOVERY_LOOKAHEAD) {
                            let _ = wallet_guard.peek_address(KeychainKind::Internal, index);
                        }
                    }

                    if let Err(e) = wallet_guard.persist(&mut conn_guard) {
                        tracing::error!("Failed to persist wallet: {e}");
                    }

                    // Flush in-memory database to encrypted file immediately
                    if let Err(e) = wallet_db.flush(&*conn_guard) {
                        tracing::error!("Failed to flush wallet database: {e}");
                    }

                    let height = wallet_guard.local_chain().tip().height();
                    let regular_balance = wallet_guard.balance().total().to_sat();
                    info!("✅ Auto-sync: updated to height {height}");

                    // Release wallet lock before checking SNICKER UTXOs
                    drop(wallet_guard);
                    drop(conn_guard);

                    // Real-time partial UTXO set update - scan new blocks
                    {
                        let mut utxo_set = partial_utxo_set.lock().await;
                        let last_scanned = match utxo_set.get_last_scanned_height() {
                            Ok(h) => h,
                            Err(e) => {
                                tracing::error!("Failed to get last scanned height: {e}");
                                0
                            }
                        };

                        // Skip if already scanned to this height (prevent re-entry during ongoing scan)
                        if height > last_scanned {
                            // Determine scan range
                            let (start_height, end_height) = if last_scanned == 0 {
                                // First run: only scan last scan_window blocks
                                let scan_window = utxo_set.scan_window;
                                let start = height.saturating_sub(scan_window - 1);
                                tracing::info!(
                                    "🔧 First run: building partial UTXO set from last {} blocks (heights {}-{})",
                                    scan_window, start, height
                                );
                                println!(
                                    "🔧 Building partial UTXO set from last {} blocks...",
                                    scan_window
                                );
                                (start, height)
                            } else {
                                // Normal: scan blocks since last scan
                                let num_new = height - last_scanned;
                                tracing::debug!(
                                    "📊 Partial UTXO set: scanning {} new blocks ({}-{})",
                                    num_new, last_scanned + 1, height
                                );
                                (last_scanned + 1, height)
                            };

                            // Download and scan blocks in range
                            let is_first_run = last_scanned == 0;
                            let mut blocks_scanned = 0;
                            let mut consecutive_failures = 0;
                            let max_consecutive_failures = 20; // Stop if 20 blocks in a row fail

                            // On first run, check if the first block hash matches the wallet's chain
                            if is_first_run && start_height > 0 {
                                let wallet_lock = wallet.lock().await;
                                let wallet_chain = wallet_lock.local_chain();

                                // Try to get the block hash at start_height from wallet's chain view
                                if let Some(checkpoint) = wallet_chain.range(start_height..=start_height).next() {
                                    tracing::debug!(
                                        "Wallet's chain view at height {}: {}",
                                        start_height, checkpoint.hash()
                                    );
                                }
                                drop(wallet_lock);
                            }

                            for scan_height in start_height..=end_height {
                                // Get block hash from wallet database
                                let block_hash = {
                                    let conn_guard = conn.lock().await;
                                    let hash_hex: Option<String> = match conn_guard.query_row(
                                        "SELECT block_hash FROM bdk_blocks WHERE block_height = ?",
                                        [scan_height],
                                        |row| row.get(0),
                                    ) {
                                        Ok(h) => Some(h),
                                        Err(_) => None,
                                    };
                                    drop(conn_guard);

                                    if let Some(hex) = hash_hex {
                                        match hex.parse() {
                                            Ok(hash) => hash,
                                            Err(e) => {
                                                tracing::debug!("Invalid block hash at height {}: {}", scan_height, e);
                                                consecutive_failures += 1;
                                                if is_first_run && consecutive_failures >= max_consecutive_failures {
                                                    tracing::info!("⚠️  Stopping initial scan: too many unavailable blocks");
                                                    break;
                                                }
                                                continue;
                                            }
                                        }
                                    } else {
                                        tracing::debug!("No block hash found for height {}", scan_height);
                                        consecutive_failures += 1;
                                        if is_first_run && consecutive_failures >= max_consecutive_failures {
                                            tracing::info!("⚠️  Stopping initial scan: too many unavailable blocks");
                                            break;
                                        }
                                        continue;
                                    }
                                };

                                // Download block
                                tracing::trace!("Requesting block at height {}: {}", scan_height, block_hash);
                                let indexed_block = match requester.get_block(block_hash).await {
                                    Ok(b) => b,
                                    Err(e) => {
                                        // Check if this is a "not in chain" error vs other errors
                                        let err_msg = e.to_string();
                                        let is_chain_error = err_msg.contains("not a member of the chain");

                                        if is_chain_error && scan_height == start_height {
                                            // First block in range failed with chain error - likely reorg or stale hashes
                                            tracing::warn!(
                                                "⚠️  Block hash {} at height {} is not in current chain (possible reorg or stale database)",
                                                block_hash, scan_height
                                            );
                                        }

                                        // On first run, blocks may not be available - this is expected
                                        if is_first_run {
                                            tracing::debug!("Block {} at height {} not available: {}",
                                                           block_hash, scan_height, e);
                                            consecutive_failures += 1;
                                            if consecutive_failures >= max_consecutive_failures {
                                                tracing::info!("⚠️  Stopping initial scan at height {}: Kyoto doesn't have older blocks", scan_height);
                                                break;
                                            }
                                        } else {
                                            tracing::error!("Failed to download block {} at height {}: {}",
                                                           block_hash, scan_height, e);
                                        }
                                        continue;
                                    }
                                };

                                // Check if any inputs in this block spend our SNICKER UTXOs
                                // Do this BEFORE updating partial UTXO set for efficiency
                                for tx in &indexed_block.block.txdata {
                                    let spending_txid = tx.compute_txid();

                                    for input in &tx.input {
                                        let outpoint = input.previous_output;

                                        // Check if this input spends a SNICKER UTXO
                                        let is_snicker_spend: bool = {
                                            let conn = snicker_conn.lock().unwrap();
                                            conn.query_row(
                                                "SELECT 1 FROM snicker_utxos WHERE txid = ?1 AND vout = ?2 AND status IN ('unspent', 'pending')",
                                                (&outpoint.txid.to_string(), outpoint.vout),
                                                |_| Ok(true),
                                            ).is_ok()
                                        };

                                        if is_snicker_spend {
                                            tracing::info!("🔍 SNICKER UTXO {}:{} spent in {} at height {}",
                                                outpoint.txid, outpoint.vout, spending_txid, scan_height);

                                            // Mark as spent in SNICKER database
                                            {
                                                let conn = snicker_conn.lock().unwrap();
                                                if let Err(e) = conn.execute(
                                                    "UPDATE snicker_utxos SET status = 'spent', spent_in_txid = ? WHERE txid = ? AND vout = ?",
                                                    (spending_txid.to_string(), outpoint.txid.to_string(), outpoint.vout),
                                                ) {
                                                    tracing::error!("Failed to mark SNICKER UTXO as spent: {}", e);
                                                } else {
                                                    tracing::info!("✅ Marked SNICKER UTXO {}:{} as SPENT in {}",
                                                        outpoint.txid, outpoint.vout, spending_txid);

                                                    // Flush to encrypted file after UTXO status change
                                                    if let Err(e) = snicker_db.flush(&*conn) {
                                                        tracing::error!("Failed to flush SNICKER database: {}", e);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                // Scan block for partial UTXO set
                                if let Err(e) = utxo_set.scan_block(scan_height, &indexed_block.block) {
                                    tracing::error!("Failed to scan block {} for partial UTXO set: {}",
                                                   scan_height, e);
                                    continue;
                                }

                                blocks_scanned += 1;
                                consecutive_failures = 0; // Reset on success

                                // CRITICAL: Update last_scanned incrementally after each block
                                // This prevents scan restarts when new blocks arrive AND
                                // ensures we can resume correctly if wallet is closed mid-scan
                                if let Err(e) = utxo_set.set_last_scanned_height(scan_height) {
                                    tracing::error!("Failed to update last scanned height: {}", e);
                                }

                                // Report progress periodically during initial scan
                                if is_first_run && blocks_scanned % 50 == 0 {
                                    let total = end_height - start_height + 1;
                                    let percent = (blocks_scanned * 100) / total.max(1);
                                    tracing::info!("📥 Progress: {}/{} blocks scanned ({}%)", blocks_scanned, total, percent);
                                    println!("📥 Scanning blocks: {}/{} ({}%)", blocks_scanned, total, percent);

                                    // Broadcast status update to GUI
                                    let status_msg = format!("Building partial UTXO set: {}/{} blocks ({}%)", blocks_scanned, total, percent);
                                    let update_event = WalletUpdate {
                                        height,
                                        balance_sats: 0, // Balance not relevant during initial scan
                                        status_message: Some(status_msg),
                                    };
                                    let _ = update_tx.send(update_event);
                                }
                            }

                            // Prune old UTXOs
                            let scan_window = utxo_set.scan_window;
                            let window_start = height.saturating_sub(scan_window);
                            if let Err(e) = utxo_set.prune_older_than(window_start) {
                                tracing::error!("Failed to prune partial UTXO set: {}", e);
                            }

                            // Report completion (last_scanned is already updated incrementally)
                            let count = utxo_set.count().unwrap_or(0);
                            if is_first_run {
                                // First run completion message with coverage info
                                let requested_blocks = end_height - start_height + 1;
                                tracing::info!(
                                    "✅ Partial UTXO set initialized: {} UTXOs from {} blocks ({}% coverage)",
                                    count, blocks_scanned, (blocks_scanned * 100) / requested_blocks.max(1)
                                );
                                println!(
                                    "✅ Partial UTXO set initialized: {} UTXOs from {} blocks",
                                    count, blocks_scanned
                                );
                                if blocks_scanned < requested_blocks {
                                    tracing::info!(
                                        "ℹ️  Partial coverage: {}/{} blocks scanned (Kyoto light client has limited history)",
                                        blocks_scanned, requested_blocks
                                    );
                                    println!(
                                        "ℹ️  Limited coverage: {}/{} blocks (will expand as new blocks arrive)",
                                        blocks_scanned, requested_blocks
                                    );
                                }
                            } else {
                                tracing::debug!(
                                    "✅ Partial UTXO set updated to height {} ({} UTXOs)",
                                    height, count
                                );
                            }

                            // Broadcast completion update to clear status bar
                            if is_first_run {
                                let update_event = WalletUpdate {
                                    height,
                                    balance_sats: 0, // Balance will be updated by next blockchain update
                                    status_message: None, // Clear status message
                                };
                                let _ = update_tx.send(update_event);
                            }
                        }

                        // Log detailed stats every 10 blocks
                        if height % 10 == 0 {
                            if let Ok(stats) = utxo_set.stats() {
                                tracing::info!(
                                    "📊 Partial UTXO Set | Height: {} | Total: {} | Unspent: {} | <0.001₿: {} | 0.001-0.01₿: {} | ≥0.01₿: {}",
                                    stats.last_scanned_height,
                                    stats.total_utxos,
                                    stats.unspent_utxos,
                                    stats.small_utxos,
                                    stats.medium_utxos,
                                    stats.large_utxos
                                );
                            }
                        }
                        drop(utxo_set);
                    }

                    // Check for pending SNICKER UTXOs and insert them if confirmed
                    if let Err(e) = Self::check_pending_snicker_utxos(
                        snicker_conn.clone(),
                        Some(&snicker_db),
                        conn.clone(),
                        &requester,
                        &wallet_name,
                        network,
                        &external_descriptor,
                        &internal_descriptor,
                    )
                    .await
                    {
                        tracing::error!("Failed to process pending SNICKER UTXOs: {e}");
                    }

                    // NOTE: SNICKER UTXO spend detection now happens during block scanning
                    // (see SNICKER spend check in partial UTXO set scan loop above)
                    // The old check_spent_snicker_utxos() method is no longer used.

                    // Check for long-pending SNICKER UTXOs and warn
                    if let Err(e) = Self::check_long_pending_snicker_utxos(
                        snicker_conn.clone(),
                    )
                    .await
                    {
                        tracing::error!("Failed to check long-pending SNICKER UTXOs: {e}");
                    }

                    // Calculate total balance and broadcast update event

                    // Get SNICKER balance directly from in-memory database
                    let snicker_balance = {
                        let snicker_conn_guard = snicker_conn.lock().unwrap();
                        let balance: Option<i64> = snicker_conn_guard.query_row(
                            "SELECT SUM(amount) FROM snicker_utxos WHERE block_height IS NOT NULL AND status = 'unspent'",
                            [],
                            |row| row.get(0),
                        ).unwrap_or(None);
                        balance.unwrap_or(0) as u64
                    };

                    let total_balance = regular_balance + snicker_balance;

                    // Generate status message based on current state
                    let status_message = {
                        let utxo_set = partial_utxo_set.lock().await;
                        let last_scanned = utxo_set.get_last_scanned_height().unwrap_or(0);
                        drop(utxo_set);

                        if last_scanned == 0 {
                            Some("Initializing partial UTXO set...".to_string())
                        } else if last_scanned < height {
                            Some(format!("Scanning blocks: {}/{}", last_scanned, height))
                        } else {
                            None // All caught up
                        }
                    };

                    // Broadcast update event to subscribers
                    let update_event = WalletUpdate {
                        height,
                        balance_sats: total_balance,
                        status_message,
                    };

                    // send() returns the number of subscribers; we don't care if there are none
                    let _ = update_tx.send(update_event);
                    tracing::debug!("📡 Broadcasted wallet update: height={}, balance={} sats", height, total_balance);
                }
                Err(e) => {
                    tracing::error!("Auto-sync stopped: {e:?}");
                    break;
                }
            }
        }
    }

    // ============================================================
    pub async fn validate_proposer_utxo(
        &self,
        proposer_outpoint: &bdk_wallet::bitcoin::OutPoint,
        proposer_amount: u64,
    ) -> Result<()> {
        let utxo_set = self.partial_utxo_set.lock().await;

        match utxo_set.get(proposer_outpoint)? {
            Some(utxo) if utxo.status == UtxoStatus::Unspent => {
                // ✅ TRUSTLESS validation (we saw it in our scan)
                tracing::info!("✅ Proposer UTXO validated via partial UTXO set: {}:{}",
                              proposer_outpoint.txid, proposer_outpoint.vout);

                // Verify amount matches
                if utxo.amount != proposer_amount {
                    return Err(anyhow::anyhow!(
                        "Proposer UTXO amount mismatch: expected {}, got {}",
                        proposer_amount, utxo.amount
                    ));
                }

                Ok(())
            }

            Some(utxo) if utxo.status == UtxoStatus::Spent => {
                // ❌ We saw this UTXO spent in our scans
                tracing::warn!(
                    "❌ Proposer UTXO already spent at height {}: {}:{}",
                    utxo.spent_at_height.unwrap_or(0),
                    proposer_outpoint.txid, proposer_outpoint.vout
                );
                Err(anyhow::anyhow!(
                    "Proposer UTXO already spent at height {}",
                    utxo.spent_at_height.unwrap_or(0)
                ))
            }

            None => {
                // ⚠️ UTXO not in our partial set
                tracing::warn!(
                    "⚠️  Proposer UTXO not found in partial UTXO set: {}:{}",
                    proposer_outpoint.txid, proposer_outpoint.vout
                );
                tracing::warn!("    This could mean:");
                tracing::warn!("    • UTXO older than our scan window");
                tracing::warn!("    • UTXO doesn't exist (fake)");
                tracing::warn!("    • UTXO < 5000 sats (below our filter)");

                let config = crate::config::Config::load()?;
                match config.partial_utxo_set.validation_mode {
                    crate::config::ValidationMode::Strict => {
                        // Reject anything outside scan window
                        Err(anyhow::anyhow!(
                            "Proposer UTXO not in partial set (strict mode) - outside scan window or doesn't exist"
                        ))
                    }
                    crate::config::ValidationMode::Fallback => {
                        // TODO: Implement Tor API fallback validation
                        tracing::warn!("⚠️  Fallback validation not yet implemented - rejecting");
                        Err(anyhow::anyhow!(
                            "Proposer UTXO not in partial set and fallback not implemented"
                        ))
                    }
                }
            }

            _ => {
                // Shouldn't happen (covered all enum cases)
                Err(anyhow::anyhow!("Unexpected UTXO status"))
            }
        }
    }

    // PUBLIC WALLET/STATE HELPERS (used by UI)
    // ============================================================


    pub async fn debug_transactions(&self) -> Result<String> {
      let wallet = self.wallet.lock().await;
      let mut output = String::new();
      output.push_str(&format!("Total transactions: {}\n", wallet.transactions().count()));

      for tx_info in wallet.transactions() {
          output.push_str(&format!("\nTxid: {}\n", tx_info.tx_node.txid));
          output.push_str(&format!("  Confirmation: {:?}\n", tx_info.chain_position));

          // Check outputs
          for (vout, txout) in tx_info.tx_node.tx.output.iter().enumerate() {
              output.push_str(&format!("  Output {}: {} sats\n", vout, txout.value.to_sat()));
              output.push_str(&format!("    Script: {}\n", txout.script_pubkey));
          }
      }

      Ok(output)
  }

    pub async fn print_summary(&self) {
        let wallet = self.wallet.lock().await;
        println!("💰 Balance: {}", wallet.balance().total());
        println!("📦 Chain tip: {}", wallet.local_chain().tip().height());
        println!("🧾 Tx count: {}", wallet.transactions().count());
    }

    pub async fn get_balance(&self) -> Result<String> {
        let wallet = self.wallet.lock().await;
        let regular_balance = wallet.balance().total().to_sat();
        drop(wallet);

        let snicker_balance = self.get_snicker_balance_sats().await?;

        let total = regular_balance + snicker_balance;
        Ok(format!("{} sats", total))
    }

    /// Get SNICKER balance in satoshis (helper for coin selection)
    async fn get_snicker_balance_sats(&self) -> Result<u64> {
        let conn = self.snicker_conn.lock().unwrap();
        let balance: Option<i64> = conn.query_row(
            "SELECT SUM(amount) FROM snicker_utxos WHERE block_height IS NOT NULL AND status = 'unspent'",
            [],
            |row| row.get(0),
        ).unwrap_or(None);
        Ok(balance.unwrap_or(0) as u64)
    }

    /// Get next address and persist derivation index.
    /// Note: In bdk_kyoto 0.15+, scripts are automatically registered from the wallet.
    pub async fn get_next_address(&mut self) -> Result<String> {
        let mut wallet = self.wallet.lock().await;
        let mut conn = self.conn.lock().await;

        let before_index = wallet.derivation_index(KeychainKind::External).unwrap_or(0);
        let info = wallet.reveal_next_address(KeychainKind::External);
        let after_index = wallet.derivation_index(KeychainKind::External).unwrap_or(0);

        info!("📍 Address revealed: {} (derivation index: {} -> {}, address index: {})",
            info.address, before_index, after_index, info.index);

        // persist updated derivation index
        wallet.persist(&mut conn)?;

        Ok(info.address.to_string())
    }

    /// Show the next N unrevealed addresses without actually revealing them
  /// Show the first N addresses and their revealed status
  pub async fn peek_addresses(&self, count: u32) -> Result<Vec<String>> {
      let wallet = self.wallet.lock().await;
      let mut addresses = vec![];
      let last_revealed = wallet.derivation_index(KeychainKind::External).unwrap_or(0);

      for i in 0..count {
          let addr = wallet.peek_address(KeychainKind::External, i);
          let status = if i < last_revealed { " ✓ revealed" } else { "" };
          addresses.push(format!("Index {}: {}{}", i, addr, status));
      }
      Ok(addresses)
  }

  /// Note: In bdk_kyoto 0.15+, scripts are automatically registered from the wallet.
  /// This function is kept for compatibility but no longer does anything.
  pub async fn reregister_revealed(&mut self) -> Result<String> {
      let wallet = self.wallet.lock().await;
      let last_revealed = wallet.derivation_index(KeychainKind::External).unwrap_or(0);

      if last_revealed == 0 {
          return Ok("No addresses revealed yet".to_string());
      }

      Ok(format!("Note: {} address(es) revealed (auto-registered by Kyoto)", last_revealed))
  }

  /// Reveal addresses up to a specific index.
  /// Note: In bdk_kyoto 0.15+, scripts are automatically registered from the wallet.
  pub async fn reveal_up_to(&mut self, index: u32) -> Result<String> {
      let mut wallet = self.wallet.lock().await;
      let mut conn = self.conn.lock().await;
      let current = wallet.derivation_index(KeychainKind::External).unwrap_or(0);

      if index < current {
          return Ok(format!("Already revealed up to index {}", current.saturating_sub(1)));
      }

      let mut last_addr = String::new();
      for _ in current..=index {
          let info = wallet.reveal_next_address(KeychainKind::External);
          last_addr = info.address.to_string();
      }

      wallet.persist(&mut conn)?;
      Ok(format!("Revealed addresses up to index {}, last: {}", index, last_addr))
  }

    /// Get all unspent UTXOs including SNICKER UTXOs
    /// Returns Vec of (txid_string, vout, amount, is_snicker)
    pub async fn get_all_unspent_outpoints(&self) -> Result<Vec<(String, u32, u64, bool)>> {
        let mut result = Vec::new();

        // Regular wallet UTXOs
        let wallet = self.wallet.lock().await;
        for utxo in wallet.list_unspent() {
            result.push((
                utxo.outpoint.txid.to_string(),
                utxo.outpoint.vout,
                utxo.txout.value.to_sat(),
                false, // not a SNICKER UTXO
            ));
        }
        drop(wallet);

        // SNICKER UTXOs - reuse get_snicker_utxos_with_keys and discard privkeys
        let snicker_utxos = self.get_snicker_utxos_with_keys().await?;
        for (outpoint, amount, _privkey) in snicker_utxos {
            result.push((
                outpoint.txid.to_string(),
                outpoint.vout,
                amount,
                true, // is a SNICKER UTXO
            ));
        }

        Ok(result)
    }

    /// Get all SNICKER UTXOs with their tweaked private keys (for decryption)
    /// Returns Vec of (outpoint, amount, tweaked_privkey)
    ///
    /// # Security Note
    /// The intermediate Vec<u8> bytes are wrapped in Zeroizing for secure cleanup.
    pub async fn get_snicker_utxos_with_keys(&self) -> Result<Vec<(bdk_wallet::bitcoin::OutPoint, u64, bdk_wallet::bitcoin::secp256k1::SecretKey)>> {
        use bdk_wallet::bitcoin::OutPoint;
        use bdk_wallet::bitcoin::secp256k1::SecretKey;
        use std::str::FromStr;

        let mut result = Vec::new();

        let conn = self.snicker_conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT txid, vout, amount, tweaked_privkey FROM snicker_utxos WHERE block_height IS NOT NULL AND status = 'unspent'"
        )?;
        let mut rows = stmt.query([])?;

        while let Some(row) = rows.next()? {
            let txid_str: String = row.get(0)?;
            let vout: u32 = row.get(1)?;
            let amount: u64 = row.get(2)?;
            // Wrap in Zeroizing so bytes are zeroed after SecretKey is created
            let privkey_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(row.get(3)?);

            let txid = bdk_wallet::bitcoin::Txid::from_str(&txid_str)?;
            let outpoint = OutPoint { txid, vout };
            let privkey = SecretKey::from_slice(&privkey_bytes)?;

            result.push((outpoint, amount, privkey));
        }

        Ok(result)
    }

    /// Fetch a single SNICKER private key on-demand for signing
    /// Returns the tweaked private key for the given outpoint
    ///
    /// # Security Note
    /// This function loads private key material from the encrypted database.
    /// The returned SecretKey implements secure drop (zeroization) automatically.
    /// The intermediate Vec<u8> is wrapped in Zeroizing for secure cleanup.
    /// Callers should ensure the key is used in a tight scope and dropped ASAP.
    pub async fn fetch_snicker_key(&self, outpoint: bdk_wallet::bitcoin::OutPoint) -> Result<bdk_wallet::bitcoin::secp256k1::SecretKey> {
        use bdk_wallet::bitcoin::secp256k1::SecretKey;

        let conn = self.snicker_conn.lock().unwrap();
        let privkey_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(conn.query_row(
            "SELECT tweaked_privkey FROM snicker_utxos WHERE txid = ? AND vout = ?",
            [outpoint.txid.to_string(), outpoint.vout.to_string()],
            |row| row.get(0),
        )?);

        SecretKey::from_slice(&privkey_bytes).map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))
    }

    /// Get all wallet UTXOs (regular + SNICKER) as unified WalletUtxo enum
    /// This is the single source of truth for all UTXOs in the wallet
    ///
    /// # Security Note
    /// This function does NOT load private keys into memory. SNICKER private keys
    /// are fetched on-demand when needed for signing using fetch_snicker_key().
    pub async fn get_all_wallet_utxos(&self) -> Result<Vec<WalletUtxo>> {
        use std::str::FromStr;

        let mut result = Vec::new();

        // Regular wallet UTXOs
        let wallet = self.wallet.lock().await;
        for utxo in wallet.list_unspent() {
            result.push(WalletUtxo::Regular(utxo.clone()));
        }
        drop(wallet);

        // SNICKER UTXOs (without loading private keys)
        let conn = self.snicker_conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT txid, vout, amount, script_pubkey FROM snicker_utxos WHERE block_height IS NOT NULL AND status = 'unspent'"
        )?;
        let mut rows = stmt.query([])?;

        while let Some(row) = rows.next()? {
            let txid_str: String = row.get(0)?;
            let vout: u32 = row.get(1)?;
            let amount: u64 = row.get(2)?;
            let script_bytes: Vec<u8> = row.get(3)?;

            let txid = bdk_wallet::bitcoin::Txid::from_str(&txid_str)?;
            let outpoint = bdk_wallet::bitcoin::OutPoint { txid, vout };
            let script_pubkey = bdk_wallet::bitcoin::ScriptBuf::from_bytes(script_bytes);

            result.push(WalletUtxo::Snicker {
                outpoint,
                amount,
                script_pubkey,
            });
        }

        Ok(result)
    }

    pub async fn list_unspent(&self) -> Result<Vec<String>> {
        let all_utxos = self.get_all_unspent_outpoints().await?;
        let mut out = Vec::new();

        for (txid, vout, amount, is_snicker) in all_utxos {
            if is_snicker {
                out.push(format!("{}:{} ({} sats) [SNICKER]", txid, vout, amount));
            } else {
                out.push(format!("{}:{} ({} sats)", txid, vout, amount));
            }
        }

        Ok(out)
    }

    // ============================================================
    // SNICKER DATABASE ACCESS (for Manager to share with Snicker)
    // ============================================================

    /// Get shared SNICKER database connection (for Snicker initialization)
    pub fn get_snicker_conn(&self) -> Arc<std::sync::Mutex<Connection>> {
        self.snicker_conn.clone()
    }

    /// Get SNICKER database manager (for Snicker initialization)
    pub fn get_snicker_db_manager(&self) -> crate::encryption::EncryptedMemoryDb {
        // Clone the manager so Snicker can flush independently
        // This is safe because both will flush to the same encrypted file
        self.snicker_db.clone()
    }

    // ============================================================
    // FEE ESTIMATION
    // ============================================================

    /// Get the current fee rate for transaction construction
    ///
    /// Uses the FeeEstimator to get real-time fee estimates from mempool.space.
    /// Falls back to 10 sat/vB if estimation fails.
    pub async fn get_fee_rate(&self) -> bdk_wallet::bitcoin::FeeRate {
        // Estimate for 6 block confirmation (~1 hour)
        match self.fee_estimator.estimate(6).await {
            Ok(rate) => {
                tracing::info!("📊 Using estimated fee rate: {:.2} sat/vB for ~6 blocks", rate);
                // Convert f64 to u64, handling edge cases
                let rate_sat_vb = if rate < 1.0 {
                    tracing::warn!("Fee rate {:.2} sat/vB too low, using minimum 1 sat/vB", rate);
                    1
                } else {
                    rate.ceil() as u64  // Round up to ensure confirmation
                };
                bdk_wallet::bitcoin::FeeRate::from_sat_per_vb(rate_sat_vb).unwrap()
            }
            Err(e) => {
                tracing::warn!("Fee estimation failed: {}. Using fallback 10 sat/vB", e);
                bdk_wallet::bitcoin::FeeRate::from_sat_per_vb(10).unwrap()
            }
        }
    }

    // ============================================================
    // BITCOIN CORE RPC (optional feature)
    // ============================================================

    /// Set the Bitcoin Core RPC client
    ///
    /// # Arguments
    /// * `url` - RPC URL (e.g., "http://127.0.0.1:18443")
    /// * `auth` - Authentication (username, password)
    pub fn set_rpc_client(&mut self, url: &str, auth: (String, String)) -> Result<()> {
        use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client};

        let rpc_auth = Auth::UserPass(auth.0, auth.1);
        let client = Client::new(url, rpc_auth)?;
        self.rpc_client = Some(Arc::new(client));

        info!("✅ Bitcoin Core RPC client connected: {}", url);
        Ok(())
    }

    /// Get block hashes from Kyoto's headers database for a height range
    ///
    /// Queries the headers.db that Kyoto maintains with all block headers.
    ///
    /// # Arguments
    /// * `start_height` - Starting block height (inclusive)
    /// * `end_height` - Ending block height (inclusive)
    ///
    /// # Returns
    /// Vector of (height, block_hash) tuples
    pub async fn get_block_hashes_from_headers_db(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> Result<Vec<(u32, bdk_wallet::bitcoin::BlockHash)>> {
        use bdk_wallet::bitcoin::BlockHash;
        use std::str::FromStr;

        // Use the in-memory wallet database connection
        let conn = self.conn.lock().await;

        // Query for block hashes in the height range from bdk_blocks table
        let mut stmt = conn.prepare(
            "SELECT block_height, block_hash FROM bdk_blocks WHERE block_height >= ? AND block_height <= ? ORDER BY block_height"
        )?;

        let mut block_hashes = Vec::new();
        let rows = stmt.query_map([start_height, end_height], |row| {
            let height: u32 = row.get(0)?;
            let hash_hex: String = row.get(1)?;
            Ok((height, hash_hex))
        })?;

        for row in rows {
            let (height, hash_hex) = row?;
            // Parse hex string to BlockHash
            let hash = BlockHash::from_str(&hash_hex)
                .map_err(|e| anyhow::anyhow!("Invalid block hash hex: {}", e))?;
            block_hashes.push((height, hash));
        }

        Ok(block_hashes)
    }

    /// Scan recent blocks for taproot UTXOs within a value range (for SNICKER proposals)
    ///
    /// Queries the partial UTXO set database (already populated by background_sync)
    /// instead of re-scanning blocks. This is much faster and works regardless of
    /// Kyoto's checkpoint position.
    ///
    /// # Arguments
    /// * `num_blocks` - Number of recent blocks to scan
    /// * `size_min` - Minimum output value in sats
    /// * `size_max` - Maximum output value in sats
    /// * `snicker_only` - If true, only return UTXOs from SNICKER v1 transactions
    ///
    /// # Returns
    /// Vector of (txid, vout, block_height, amount, script_pubkey) for matching UTXOs
    // Removed: scan_blocks_for_taproot_utxos
    // Candidates are now queried directly via Manager.get_snicker_candidates()
    // which queries partial_utxo_set. No separate scanning needed.

    // ============================================================
    // PRIVATE KEY DERIVATION (for SNICKER DH operations)
    // ============================================================

    /// Check for pending SNICKER UTXOs and insert confirmed ones into the wallet (static helper)
    async fn check_pending_snicker_utxos(
        snicker_conn: Arc<std::sync::Mutex<Connection>>,
        snicker_db: Option<&crate::encryption::EncryptedMemoryDb>,
        wallet_conn: Arc<Mutex<Connection>>,
        requester: &bdk_kyoto::Requester,
        wallet_name: &str,
        network: Network,
        external_descriptor: &str,
        internal_descriptor: &str,
    ) -> Result<()> {
        use std::str::FromStr;

        // Query SNICKER database for pending UTXOs
        let pending: Vec<(String, u32)> = {
            let conn = snicker_conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT txid, vout FROM snicker_utxos WHERE block_height IS NULL AND status = 'unspent'"
            )?;
            let mut rows = stmt.query([])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                result.push((row.get(0)?, row.get(1)?));
            }
            result
        }; // All rusqlite objects dropped here before any async code

        if pending.is_empty() {
            return Ok(());
        }

        tracing::debug!("🔍 Checking {} pending SNICKER UTXOs", pending.len());

        // Query in-memory wallet database for tip height and block hashes
        let (tip_height, block_hashes) = {
            let wallet_conn_guard = wallet_conn.lock().await;

            let tip_height: u32 = wallet_conn_guard.query_row(
                "SELECT MAX(block_height) FROM bdk_blocks",
                [],
                |row| row.get(0),
            )?;

            // Scan recent blocks (last 10) for pending transactions
            let start_height = tip_height.saturating_sub(10);

            let block_hashes: Vec<(u32, String)> = {
                let mut stmt = wallet_conn_guard.prepare(
                    "SELECT block_height, block_hash FROM bdk_blocks WHERE block_height >= ? AND block_height <= ? ORDER BY block_height"
                )?;
                let mut rows = stmt.query([start_height, tip_height])?;
                let mut result = Vec::new();
                while let Some(row) = rows.next()? {
                    result.push((row.get(0)?, row.get(1)?));
                }
                result
            };

            (tip_height, block_hashes)
        };

        for (height, block_hash_hex) in block_hashes {
            // Parse block hash
            let block_hash = bdk_wallet::bitcoin::BlockHash::from_str(&block_hash_hex)?;

            // Fetch the block from Kyoto
            if let Ok(indexed_block) = requester.get_block(block_hash).await {
                let block = &indexed_block.block;

                // Check if any pending transactions are in this block
                for tx in &block.txdata {
                    let txid = tx.compute_txid();
                    let txid_str = txid.to_string();

                    // Is this one of our pending SNICKER transactions?
                    if pending.iter().any(|(pending_txid, _)| pending_txid == &txid_str) {
                        // Insert transaction into wallet database
                        use bdk_wallet::chain::{BlockId, ConfirmationBlockTime};
                        use std::sync::Arc;

                        // Update in-memory wallet database (scoped to avoid holding lock across awaits)
                        {
                            let mut wallet_write_conn = wallet_conn.lock().await;

                            // Create TxUpdate with the transaction
                            let mut tx_update = bdk_wallet::chain::TxUpdate::default();
                            tx_update.txs.push(Arc::new(tx.clone()));
                            tx_update.anchors.insert((
                                ConfirmationBlockTime {
                                    block_id: BlockId {
                                        height,
                                        hash: block_hash,
                                    },
                                    confirmation_time: 0,
                                },
                                txid,
                            ));

                            // Load wallet, apply update, and commit
                            // Use Box::leak to convert &str to &'static str (required by BDK API)
                            let external_desc_static: &'static str = Box::leak(external_descriptor.to_string().into_boxed_str());
                            let internal_desc_static: &'static str = Box::leak(internal_descriptor.to_string().into_boxed_str());

                            let mut wallet = bdk_wallet::Wallet::load()
                                .descriptor(bdk_wallet::KeychainKind::External, Some(external_desc_static))
                                .descriptor(bdk_wallet::KeychainKind::Internal, Some(internal_desc_static))
                                // .extract_keys() NOT called - descriptors are public (xpub)
                                .check_network(network)
                                .load_wallet(&mut *wallet_write_conn)?
                                .ok_or_else(|| anyhow::anyhow!("Wallet not found"))?;

                            let update = bdk_wallet::Update {
                                tx_update,
                                chain: None,
                                last_active_indices: Default::default(),
                            };
                            wallet.apply_update(update)?;
                            wallet.persist(&mut *wallet_write_conn)?;
                        }

                        // Update block_height in SNICKER database (scoped)
                        {
                            let snicker_update_conn = snicker_conn.lock().unwrap();
                            snicker_update_conn.execute(
                                "UPDATE snicker_utxos SET block_height = ? WHERE txid = ?",
                                (height, &txid_str),
                            )?;
                        }

                        info!("✅ SNICKER UTXO confirmed and inserted into wallet: {} at height {}", txid, height);
                    }
                }
            }
        }

        // Flush to encrypted file after any UTXO changes
        if let Some(db) = snicker_db {
            db.flush(&*snicker_conn.lock().unwrap())?;
        }

        Ok(())
    }

    /// Check for spent SNICKER UTXOs and mark them as spent (static helper)
    async fn check_spent_snicker_utxos(
        snicker_conn: Arc<std::sync::Mutex<Connection>>,
        snicker_db: Option<&crate::encryption::EncryptedMemoryDb>,
        wallet_conn: Arc<Mutex<Connection>>,
    ) -> Result<()> {
        // Get all unspent SNICKER UTXOs from database
        // Check both confirmed (block_height IS NOT NULL) and unconfirmed (block_height IS NULL)
        // because a UTXO can be spent even before it confirms (if used in a new SNICKER proposal)
        let unspent: Vec<(String, u32)> = {
            let conn = snicker_conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT txid, vout FROM snicker_utxos WHERE status IN ('unspent', 'pending')"
            )?;
            let mut rows = stmt.query([])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                result.push((row.get(0)?, row.get(1)?));
            }
            result
        };

        if unspent.is_empty() {
            return Ok(());
        }

        tracing::debug!("🔍 Checking {} unspent SNICKER UTXOs for spending", unspent.len());

        // Query in-memory wallet database to check for spending transactions
        let wallet_conn_guard = wallet_conn.lock().await;

        // Check each UTXO to see if it's been spent by scanning wallet transactions
        for (txid_str, vout) in unspent {
            // Query wallet database for any transaction that spends this outpoint
            let spending_txid: Result<String, _> = wallet_conn_guard.query_row(
                "SELECT DISTINCT tx.txid FROM bdk_tx tx
                 INNER JOIN bdk_txin txin ON tx.id = txin.tx_id
                 WHERE txin.prev_tx = ?1 AND txin.prev_vout = ?2",
                (&txid_str, vout),
                |row| row.get(0),
            );

            if let Ok(spending_txid_str) = spending_txid {
                tracing::info!("🔍 SNICKER UTXO {}:{} has been spent in {}", txid_str, vout, spending_txid_str);

                // Mark as SPENT in SNICKER database (confirmed in a block)
                let snicker_update_conn = snicker_conn.lock().unwrap();
                snicker_update_conn.execute(
                    "UPDATE snicker_utxos SET status = 'spent', spent_in_txid = ? WHERE txid = ? AND vout = ?",
                    (spending_txid_str, &txid_str, vout),
                )?;
                drop(snicker_update_conn);
                tracing::info!("✅ Marked SNICKER UTXO {}:{} as SPENT (confirmed)", txid_str, vout);
            }
        }

        drop(wallet_conn_guard);

        // Flush to encrypted file after any UTXO changes
        if let Some(db) = snicker_db {
            db.flush(&*snicker_conn.lock().unwrap())?;
        }

        Ok(())
    }

    /// Check for SNICKER UTXOs that have been pending for >24 hours and log warnings
    ///
    /// This only applies to UTXOs we broadcast ourselves (receiver role or manual sends).
    /// Proposer UTXOs never go to 'pending' status from the proposer's perspective.
    async fn check_long_pending_snicker_utxos(
        snicker_conn: Arc<std::sync::Mutex<Connection>>,
    ) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        let threshold = 24 * 60 * 60; // 24 hours in seconds

        // Get all pending UTXOs that have been pending for >24 hours
        let long_pending: Vec<(String, u32, String, i64)> = {
            let conn = snicker_conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT txid, vout, spent_in_txid, pending_since
                 FROM snicker_utxos
                 WHERE status = 'pending'
                   AND pending_since IS NOT NULL
                   AND ? - pending_since > ?"
            )?;
            let mut rows = stmt.query([now, threshold])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                result.push((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?));
            }
            result
        };

        if !long_pending.is_empty() {
            tracing::warn!(
                "⚠️  {} SNICKER UTXO(s) have been pending for >24 hours without confirmation:",
                long_pending.len()
            );
            for (txid, vout, spent_in_txid, pending_since) in long_pending {
                let hours_pending = (now - pending_since) / 3600;
                tracing::warn!(
                    "   - {}:{} (spending tx: {}, pending for {} hours)",
                    txid, vout, spent_in_txid, hours_pending
                );
                tracing::warn!(
                    "     This may indicate the transaction was rejected or not propagated."
                );
                tracing::warn!(
                    "     Check mempool.space or consider manual recovery if needed."
                );
            }
        }

        Ok(())
    }

    /// Mark a SNICKER UTXO as pending (broadcast but not confirmed)
    ///
    /// Spend detection happens via block scanning in background_sync, which checks
    /// every transaction input against our SNICKER UTXO database.
    pub async fn mark_snicker_utxo_pending(
        &self,
        txid: &str,
        vout: u32,
        spent_in_txid: &str,
    ) -> Result<()> {
        // First, get the script_pubkey from database
        let script_bytes: Vec<u8> = {
            let conn = self.snicker_conn.lock().unwrap();
            conn.query_row(
                "SELECT script_pubkey FROM snicker_utxos WHERE txid = ? AND vout = ?",
                [txid, &vout.to_string()],
                |row| row.get(0),
            )?
        };
        let script_pubkey = bdk_wallet::bitcoin::ScriptBuf::from_bytes(script_bytes);

        // NOTE: SNICKER UTXOs are NOT tracked via Kyoto subscriptions.
        // Spend detection happens via block scanning in background_sync, which checks
        // every transaction input against our SNICKER UTXO database.
        tracing::debug!("Marking SNICKER UTXO pending (spend detection via block scanning): {}:{}", txid, vout);

        // Now mark as pending in database with timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        let conn = self.snicker_conn.lock().unwrap();
        conn.execute(
            "UPDATE snicker_utxos SET status = 'pending', spent_in_txid = ?, pending_since = ? WHERE txid = ? AND vout = ?",
            (spent_in_txid, now, txid, vout),
        )?;
        drop(conn);

        tracing::info!("✅ Marked SNICKER UTXO {}:{} as PENDING in {} at timestamp {}", txid, vout, spent_in_txid, now);

        // Flush to encrypted file after UTXO change
        self.snicker_db.flush(&*self.snicker_conn.lock().unwrap())?;

        Ok(())
    }

    /// Mark a SNICKER UTXO as spent (confirmed)
    ///
    /// This is called by background_sync when a pending UTXO is detected as spent.
    pub async fn mark_snicker_utxo_spent(
        &self,
        txid: &str,
        vout: u32,
        spent_in_txid: &str,
    ) -> Result<()> {
        let conn = self.snicker_conn.lock().unwrap();

        conn.execute(
            "UPDATE snicker_utxos SET status = 'spent', spent_in_txid = ? WHERE txid = ? AND vout = ?",
            (spent_in_txid, txid, vout),
        )?;
        drop(conn);

        tracing::info!("✅ Marked SNICKER UTXO {}:{} as SPENT (confirmed) in {}", txid, vout, spent_in_txid);

        // Flush to encrypted file after UTXO change
        self.snicker_db.flush(&*self.snicker_conn.lock().unwrap())?;

        Ok(())
    }

    /// Manually insert a transaction into the wallet
    ///
    /// This is used for SNICKER transactions where the output script is not derived
    /// from the wallet's descriptor. The transaction will be inserted as confirmed
    /// at the specified block height, making it appear in balance/listunspent.
    ///
    /// # Arguments
    /// * `tx` - The transaction to insert
    /// * `block_height` - Block height where the transaction was confirmed
    pub async fn insert_tx_at_height(
        &mut self,
        tx: &Transaction,
        block_height: u32,
    ) -> Result<()> {
        use bdk_wallet::chain::{BlockId, ConfirmationBlockTime};
        use std::sync::Arc;

        let mut wallet = self.wallet.lock().await;
        let mut conn = self.conn.lock().await;

        // Get the block hash at this height from the wallet's chain
        let block_hash = wallet
            .local_chain()
            .iter_checkpoints()
            .find(|cp| cp.height() == block_height)
            .map(|cp| cp.hash())
            .ok_or_else(|| anyhow::anyhow!("Block height {} not in wallet's chain", block_height))?;

        // Create a TxUpdate with the transaction anchored at this block
        let mut tx_update = bdk_wallet::chain::TxUpdate::default();
        tx_update.txs.push(Arc::new(tx.clone()));
        tx_update.anchors.insert((
            ConfirmationBlockTime {
                block_id: BlockId {
                    height: block_height,
                    hash: block_hash,
                },
                confirmation_time: 0, // We don't have the actual timestamp
            },
            tx.compute_txid(),
        ));

        // Apply the update to the wallet
        let update = bdk_wallet::Update {
            tx_update,
            chain: None,
            last_active_indices: Default::default(),
        };
        wallet.apply_update(update)?;

        // Commit changes to persist to database
        wallet.persist(&mut conn)?;

        info!("✅ Manually inserted transaction {} at height {}", tx.compute_txid(), block_height);
        Ok(())
    }

    /// Derive the private key for a specific UTXO
    ///
    /// # Arguments
    /// * `keychain` - External or Internal (change)
    /// * `derivation_index` - The derivation index for this key
    ///
    /// # Returns
    /// The secp256k1 private key for this UTXO
    pub async fn derive_utxo_privkey(
        &self,
        utxo: &WalletUtxo,
    ) -> Result<bdk_wallet::bitcoin::secp256k1::SecretKey> {
        match utxo {
            WalletUtxo::Regular(local_utxo) => {
                // Extract keychain and derivation index from the regular UTXO
                let keychain = local_utxo.keychain;
                let derivation_index = local_utxo.derivation_index;

                use bdk_wallet::bitcoin::bip32::DerivationPath;
                use std::str::FromStr;

                // Derive from account level (m/86h/<cointype>h/0h) using unhardened path: change/index
                let change = match keychain {
                    KeychainKind::External => 0,
                    KeychainKind::Internal => 1,
                };

                // Build full derivation path from account level: m/86h/<cointype>h/0h/<change>/<index>
                let coin_type = if self.network == Network::Bitcoin { 0 } else { 1 };
                let full_path_str = format!("m/86h/{}h/0h/{}/{}", coin_type, change, derivation_index);
                let full_path = DerivationPath::from_str(&full_path_str)?;

                // Derive the internal private key from signer
                let secp = bdk_wallet::bitcoin::secp256k1::Secp256k1::new();
                let mut internal_key = self.signer.derive_key(&full_path).await?;

                // For BIP86 Taproot, we need to return the TWEAKED private key
                // This matches the output key that appears in the P2TR script
                use bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey;
                use bdk_wallet::bitcoin::taproot::TapTweakHash;
                use bdk_wallet::bitcoin::hashes::Hash;

                // CRITICAL: BIP341 requires the internal key to have even parity before computing the tweak
                // If the internal pubkey has odd parity, negate the internal private key
                let internal_pubkey_full = internal_key.public_key(&secp);
                let has_odd_y = internal_pubkey_full.serialize()[0] == 0x03;
                if has_odd_y {
                    internal_key = internal_key.negate();
                }

                // Get the even-parity x-only internal public key
                let internal_pubkey = internal_key.public_key(&secp);
                let internal_xonly = XOnlyPublicKey::from(internal_pubkey);

                // Calculate BIP341 taproot tweak: t = hash_TapTweak(internal_key || merkle_root)
                // For BIP86 (no script tree), merkle_root is None
                let tweak_hash = TapTweakHash::from_key_and_tweak(internal_xonly, None);

                // Convert the tweak hash to a scalar
                let tweak_scalar = bdk_wallet::bitcoin::secp256k1::Scalar::from_be_bytes(
                    *tweak_hash.as_byte_array()
                ).map_err(|_| anyhow::anyhow!("Invalid tweak scalar"))?;

                // Apply tweak: tweaked_privkey = internal_privkey + tweak
                let mut tweaked_seckey = internal_key.add_tweak(&tweak_scalar)?;

                // BIP341: Check if the tweaked public key has odd parity
                // If so, negate the private key to match the even-parity output key
                let tweaked_pubkey = tweaked_seckey.public_key(&secp);
                let tweaked_xonly = XOnlyPublicKey::from(tweaked_pubkey);

                // Get the parity from the full public key
                let parity = tweaked_pubkey.serialize()[0];

                // If odd parity (0x03), negate the private key
                if parity == 0x03 {
                    tweaked_seckey = tweaked_seckey.negate();
                }

                Ok(tweaked_seckey)
            }
            WalletUtxo::Snicker { outpoint, .. } => {
                // Fetch tweaked privkey from database on-demand for SNICKER UTXOs
                // Wrapped in Zeroizing for secure cleanup of intermediate bytes
                use bdk_wallet::bitcoin::secp256k1::SecretKey;
                let conn = self.snicker_conn.lock().unwrap();
                let privkey_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(conn.query_row(
                    "SELECT tweaked_privkey FROM snicker_utxos WHERE txid = ? AND vout = ?",
                    [outpoint.txid.to_string(), outpoint.vout.to_string()],
                    |row| row.get(0),
                )?);
                SecretKey::from_slice(&privkey_bytes).map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))
            }
        }
    }
}

/// Implement Drop to flush encrypted database on shutdown
impl Drop for WalletNode {
    fn drop(&mut self) {
        // Flush wallet.sqlite to encrypted file
        // Use try_lock() since Drop can be called from async context
        match self.conn.try_lock() {
            Ok(conn_guard) => {
                if let Err(e) = self.wallet_db.flush(&*conn_guard) {
                    eprintln!("⚠️  Failed to flush wallet database on shutdown: {}", e);
                } else {
                    tracing::info!("💾 Flushed wallet.sqlite.enc on shutdown");
                }
            }
            Err(_) => {
                eprintln!("⚠️  Could not acquire wallet DB lock for flush on shutdown - data may not be saved");
            }
        }

        // Flush snicker.sqlite to encrypted file
        match self.snicker_conn.lock() {
            Ok(snicker_conn_guard) => {
                if let Err(e) = self.snicker_db.flush(&*snicker_conn_guard) {
                    eprintln!("⚠️  Failed to flush SNICKER database on shutdown: {}", e);
                } else {
                    tracing::info!("💾 Flushed snicker.sqlite.enc on shutdown");
                }
            }
            Err(e) => {
                eprintln!("⚠️  Could not acquire SNICKER DB lock for flush on shutdown: {} - data may not be saved", e);
            }
        }
    }
}

async fn trace_logs(
    mut info_rx: Receiver<Info>,
    mut warn_rx: UnboundedReceiver<Warning>,
) {
    loop {
        select! {
            warn = warn_rx.recv() => {
                if let Some(warn) = warn {
                    tracing::warn!("{warn}");
                } else {
                    // Channel closed, exit loop
                    break;
                }
            },
            // Suppress info messages from Kyoto to reduce log spam
            _info = info_rx.recv() => {
                // If channel closed, exit loop
                if _info.is_none() {
                    break;
                }
            },
        }
    }
    tracing::debug!("trace_logs task exiting");
}
