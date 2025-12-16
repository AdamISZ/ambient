use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use directories::ProjectDirs;
use tokio::select;
use tokio::sync::{Mutex, broadcast};
use tracing::info;

use bdk_wallet::{
    PersistedWallet,
    bitcoin::{Network, Address, Amount, FeeRate, Transaction, Txid, psbt::Psbt, hashes::Hash},
    keys::{
        bip39::{Language, Mnemonic, WordCount},
        DerivableKey, ExtendedKey, GeneratedKey, GeneratableKey,
    },
    rusqlite::Connection,
    miniscript::Tap,
    KeychainKind, Wallet, SignOptions,
};

use bdk_kyoto::builder::{Builder, BuilderExt};
use bdk_kyoto::{Info, LightClient, Receiver, ScanType, UnboundedReceiver, Warning, TxBroadcast, TxBroadcastPolicy, HeaderCheckpoint};

use crate::encryption::WalletEncryption;

const RECOVERY_LOOKAHEAD: u32 = 50;
const NUM_CONNECTIONS: u8 = 1;
const SYNC_LOOKBACK: u32 = 5_000; // blocks to rescan on `sync`

/// Event emitted when the wallet state changes due to blockchain updates
#[derive(Debug, Clone)]
pub struct WalletUpdate {
    /// New blockchain height after update
    pub height: u32,
    /// Total balance in sats (regular + SNICKER)
    pub balance_sats: u64,
}

/// Represents a UTXO that can be either from the regular BDK wallet or a SNICKER UTXO
#[derive(Debug, Clone)]
pub enum WalletUtxo {
    /// Regular wallet UTXO with derivation path
    Regular(bdk_wallet::LocalOutput),
    /// SNICKER UTXO with tweaked private key
    Snicker {
        outpoint: bdk_wallet::bitcoin::OutPoint,
        amount: u64,
        script_pubkey: bdk_wallet::bitcoin::ScriptBuf,
        tweaked_privkey: bdk_wallet::bitcoin::secp256k1::SecretKey,
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
    pub(crate) update_subscriber: Arc<Mutex<bdk_kyoto::UpdateSubscriber>>,
    pub network: Network,
    /// Master extended private key (needed for SNICKER DH operations)
    pub(crate) xprv: bdk_wallet::bitcoin::bip32::Xpriv,
    /// Optional Bitcoin Core RPC client (required for proposer mode scanning)
    pub(crate) rpc_client: Option<Arc<bdk_bitcoind_rpc::bitcoincore_rpc::Client>>,
    /// Wallet name (for locating correct headers.db)
    wallet_name: String,
    /// Shared in-memory SNICKER database connection (uses std::sync::Mutex for sync access)
    snicker_conn: Arc<std::sync::Mutex<Connection>>,
    /// Path to SNICKER database for checking pending UTXOs (DEPRECATED - using in-memory)
    snicker_db_path: std::path::PathBuf,
    /// Broadcast channel for wallet update events
    update_tx: broadcast::Sender<WalletUpdate>,
    /// Encrypted in-memory wallet database (for flush on shutdown)
    wallet_db: crate::encryption::EncryptedMemoryDb,
    /// Encrypted in-memory SNICKER database (for flush on UTXO changes)
    snicker_db: crate::encryption::EncryptedMemoryDb,
}

/// Selected UTXOs for spending (hybrid selection result)
struct SelectedUtxos {
    snicker_utxos: Vec<(String, u32, u64, Vec<u8>, Vec<u8>)>, // (txid, vout, amount, script_pubkey, tweaked_privkey)
    regular_utxos: Vec<bdk_wallet::LocalOutput>,
    total_snicker: u64,
    total_regular: u64,
}

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

        let node = Self::load(name, network_str, recovery_height, password).await?;

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

        let (requester, update_subscriber) =
            Self::start_node(&wallet, network, recovery_height, name)?;

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

        // Keep path for compatibility (DEPRECATED - now using in-memory)
        let snicker_db_path = snicker_db_enc_path.clone();

        // Derive descriptors for SNICKER UTXO detection
        let coin_type = if network == Network::Bitcoin { 0 } else { 1 };
        let external_desc = format!("tr({}/86h/{}h/0h/0/*)", xprv, coin_type);
        let internal_desc = format!("tr({}/86h/{}h/0h/1/*)", xprv, coin_type);

        // Create broadcast channel for wallet update events
        // Capacity of 100 means we can buffer up to 100 updates before dropping old ones
        let (update_tx, _update_rx) = broadcast::channel::<WalletUpdate>(100);

        // Spawn background task to auto-sync
        let wallet_clone = wallet.clone();
        let conn_clone = conn.clone();
        let sub_clone = update_subscriber.clone();
        let snicker_conn_clone = snicker_conn.clone();
        let snicker_db_clone = snicker_db.clone();
        let requester_clone = requester.clone();
        let wallet_name_clone = name.to_string();
        let network_clone = network;
        let external_desc_clone = external_desc.clone();
        let internal_desc_clone = internal_desc.clone();
        let update_tx_clone = update_tx.clone();
        tokio::spawn(async move {
            Self::background_sync(
                wallet_clone,
                conn_clone,
                sub_clone,
                snicker_conn_clone,
                snicker_db_clone,
                requester_clone,
                wallet_name_clone,
                network_clone,
                external_desc_clone,
                internal_desc_clone,
                update_tx_clone,
            )
            .await;
        });

        info!("✅ Wallet loaded. Auto-sync enabled in background.");

        Ok(Self {
            wallet,
            conn,
            requester,
            update_subscriber,
            network,
            xprv,
            rpc_client: None,
            wallet_name: name.to_string(),
            snicker_conn,
            snicker_db_path,
            update_tx,
            wallet_db,
            snicker_db,
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

    /// Decrypt an encrypted database file to a temporary file
    ///
    /// TODO(v2): Decrypt to in-memory database instead of temp files
    ///
    /// # Arguments
    /// * `encrypted_path` - Path to the .enc file
    /// * `password` - Decryption password
    ///
    /// # Returns
    /// Temporary file containing decrypted database (auto-deleted on drop)
    fn decrypt_to_temp(
        encrypted_path: &Path,
        password: &str,
    ) -> Result<tempfile::NamedTempFile> {
        // Read encrypted file
        let encrypted_data = fs::read(encrypted_path)?;

        // Decrypt
        let decrypted = WalletEncryption::decrypt_file(&encrypted_data, password)?;

        // Write to temp file
        let mut temp = tempfile::NamedTempFile::new()?;
        use std::io::Write;
        temp.write_all(&decrypted)?;
        temp.flush()?;

        tracing::debug!(
            "Decrypted {} → {} bytes (temp: {:?})",
            encrypted_path.display(),
            decrypted.len(),
            temp.path()
        );

        Ok(temp)
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

        // Create BIP86 descriptors manually
        // BIP86 uses m/86'/cointype'/0' as the account path
        let coin_type = if network == Network::Bitcoin { 0 } else { 1 };

        // Format: tr(xprv/86h/{cointype}h/0h/{change}/*)
        let external_desc = format!("tr({}/86h/{}h/0h/0/*)", xprv, coin_type);
        let internal_desc = format!("tr({}/86h/{}h/0h/1/*)", xprv, coin_type);

        tracing::debug!("Descriptor contains private key: {}", external_desc.contains("prv"));

        info!("💾 Wallet database: in-memory (encrypted)");

        // Check if wallet already exists by trying to load it
        // CRITICAL: When loading from DB, we must call .descriptor().extract_keys() to restore signers
        // Use Box::leak to convert String to &'static str (acceptable for descriptor strings)
        let external_desc_static: &'static str = Box::leak(external_desc.clone().into_boxed_str());
        let internal_desc_static: &'static str = Box::leak(internal_desc.clone().into_boxed_str());

        tracing::debug!("Loading wallet with descriptors and extract_keys()");
        info!("   External: {} chars", external_desc_static.len());
        info!("   Internal: {} chars", internal_desc_static.len());

        let maybe_wallet = Wallet::load()
            .descriptor(KeychainKind::External, Some(external_desc_static))
            .descriptor(KeychainKind::Internal, Some(internal_desc_static))
            .extract_keys()  // Re-extract private keys from descriptors to create signers!
            .check_network(network)
            .load_wallet(&mut conn)?;

        info!("🔍 Wallet load completed");

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

    fn start_node(
        wallet: &PersistedWallet<Connection>,
        network: Network,
        from_height: u32,
        wallet_name: &str,
    ) -> Result<(bdk_kyoto::Requester, bdk_kyoto::UpdateSubscriber)> {
        // Get checkpoint from wallet's local chain if it exists, otherwise use genesis or requested height
        let wallet_tip = wallet.local_chain().tip();
        let (checkpoint_height, checkpoint_hash) = if wallet_tip.height() > 0 {
            // Wallet has synced before, use its current tip
            (wallet_tip.height(), wallet_tip.hash())
        } else if from_height == 0 {
            // New wallet starting from genesis
            use bdk_wallet::bitcoin::blockdata::constants::genesis_block;
            (0, genesis_block(network).block_hash())
        } else {
            // New wallet but requested non-zero height - use genesis anyway to avoid hash mismatch
            // The wallet will sync from genesis to the current tip
            use bdk_wallet::bitcoin::blockdata::constants::genesis_block;
            tracing::warn!("Requested start from height {}, but using genesis to avoid checkpoint hash issues", from_height);
            (0, genesis_block(network).block_hash())
        };

        let checkpoint = HeaderCheckpoint::new(checkpoint_height, checkpoint_hash);
        let scan_type = ScanType::Recovery {
            used_script_index: RECOVERY_LOOKAHEAD,
            checkpoint,
        };
        info!("🔍 Recovery starting from height {} with hash {}", checkpoint_height, checkpoint_hash);

        // Select peer based on network
        let peer = match network {
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
        };
        info!("🔗 Connecting to peer: {}", peer);

        // Create Kyoto peer database directory (unique per wallet to avoid conflicts)
        let project_dirs = ProjectDirs::from("org", "code", "ambient")
            .ok_or_else(|| anyhow!("Cannot determine project dir"))?;

        let kyoto_db_path = project_dirs
            .data_local_dir()
            .join(format!("{:?}", network).to_lowercase())
            .join(wallet_name)
            .join("kyoto_peers");

        std::fs::create_dir_all(&kyoto_db_path)?;
        info!("📁 Kyoto peer database: {:?}", kyoto_db_path);

        let LightClient {
            requester,
            info_subscriber,
            warning_subscriber,
            update_subscriber,
            node,
        } = Builder::new(network)
            .add_peer(peer)
            .required_peers(NUM_CONNECTIONS)
            .data_dir(kyoto_db_path)
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
        update_subscriber: Arc<Mutex<bdk_kyoto::UpdateSubscriber>>,
        snicker_conn: Arc<std::sync::Mutex<Connection>>,
        snicker_db: crate::encryption::EncryptedMemoryDb,
        requester: bdk_kyoto::Requester,
        wallet_name: String,
        network: Network,
        external_descriptor: String,
        internal_descriptor: String,
        update_tx: broadcast::Sender<WalletUpdate>,
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

                    let height = wallet_guard.local_chain().tip().height();
                    let regular_balance = wallet_guard.balance().total().to_sat();
                    info!("✅ Auto-sync: updated to height {height}");

                    // Release wallet lock before checking SNICKER UTXOs
                    drop(wallet_guard);
                    drop(conn_guard);

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

                    // Check for spent SNICKER UTXOs and mark them as spent
                    if let Err(e) = Self::check_spent_snicker_utxos(
                        snicker_conn.clone(),
                        Some(&snicker_db),
                        conn.clone(),
                    )
                    .await
                    {
                        tracing::error!("Failed to check spent SNICKER UTXOs: {e}");
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

                    // Broadcast update event to subscribers
                    let update_event = WalletUpdate {
                        height,
                        balance_sats: total_balance,
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
    // PSBT DEBUGGING
    // ============================================================

    /// Dump complete PSBT state for debugging
    fn dump_psbt_state(psbt: &Psbt, label: &str) {
        info!("========== PSBT STATE: {} ==========", label);
        info!("Transaction inputs: {}", psbt.unsigned_tx.input.len());
        info!("Transaction outputs: {}", psbt.unsigned_tx.output.len());

        for (i, input) in psbt.inputs.iter().enumerate() {
            info!("--- Input {} ---", i);
            info!("  witness_utxo: {}", input.witness_utxo.is_some());
            if let Some(ref utxo) = input.witness_utxo {
                info!("    value: {} sats", utxo.value.to_sat());
                tracing::debug!("    script: {}", utxo.script_pubkey);
            }
            info!("  non_witness_utxo: {}", input.non_witness_utxo.is_some());
            info!("  sighash_type: {:?}", input.sighash_type);
            info!("  tap_internal_key: {:?}", input.tap_internal_key);
            info!("  tap_merkle_root: {:?}", input.tap_merkle_root);
            info!("  tap_key_sig: {:?}", input.tap_key_sig);
            tracing::debug!("  tap_script_sigs: {}", input.tap_script_sigs.len());
            info!("  tap_key_origins: {}", input.tap_key_origins.len());
            for (xonly, (leaf_hashes, (fingerprint, path))) in &input.tap_key_origins {
                info!("    xonly: {}", xonly);
                info!("    fingerprint: {}", fingerprint);
                info!("    path: {}", path);
                info!("    leaf_hashes: {} entries", leaf_hashes.len());
            }
            info!("  bip32_derivation: {}", input.bip32_derivation.len());
            info!("  partial_sigs: {}", input.partial_sigs.len());
            tracing::debug!("  final_script_witness: {}", input.final_script_witness.is_some());
        }

        for (i, output) in psbt.outputs.iter().enumerate() {
            info!("--- Output {} ---", i);
            info!("  tap_internal_key: {:?}", output.tap_internal_key);
            info!("  tap_key_origins: {}", output.tap_key_origins.len());
        }
        info!("========================================");
    }

    // ============================================================
    // TRANSACTION BUILDING & SENDING (Modular Architecture)
    // ============================================================

    /// Build a transaction with specified recipients and fee rate.
    /// Returns an unsigned PSBT that can be signed, exported, or modified.
    pub async fn build_transaction(
        &mut self,
        recipients: Vec<(Address, Amount)>,
        fee_rate: FeeRate,
    ) -> Result<Psbt> {
        let mut wallet = self.wallet.lock().await;

        info!("🔨 Building transaction with {} recipients", recipients.len());

        let mut tx_builder = wallet.build_tx();

        // Add all recipients
        for (address, amount) in recipients {
            tx_builder.add_recipient(address.script_pubkey(), amount);
        }

        // Set fee rate
        tx_builder.fee_rate(fee_rate);

        // Build the PSBT
        let mut psbt = tx_builder.finish()?;

        // Fix missing witness_utxo: BDK only sets it if the full previous transaction
        // is in the wallet's graph. With Kyoto, we might not have the full tx, but we
        // do have the TxOut from list_unspent(). Manually populate it here.
        let utxos: Vec<_> = wallet.list_unspent().collect();
        for (i, psbt_input) in psbt.inputs.iter_mut().enumerate() {
            if psbt_input.witness_utxo.is_none() {
                let outpoint = psbt.unsigned_tx.input[i].previous_output;
                if let Some(utxo) = utxos.iter().find(|u| u.outpoint == outpoint) {
                    psbt_input.witness_utxo = Some(utxo.txout.clone());
                }
            }
        }

        info!("✅ PSBT created: {} inputs, {} outputs", psbt.inputs.len(), psbt.outputs.len());

        Ok(psbt)
    }

    /// Sign a PSBT with the wallet's keys.
    /// Returns true if the PSBT is fully signed after this operation.
    pub async fn sign_psbt(&mut self, psbt: &mut Psbt) -> Result<bool> {
        info!("✍️  Signing PSBT with {} inputs", psbt.inputs.len());

        // Get all our UTXOs (including SNICKER UTXOs)
        let all_utxos = self.get_all_wallet_utxos().await?;

        // First, populate witness_utxo for SNICKER inputs and collect prevouts for signing
        let mut prevouts = Vec::new();
        for (input_idx, input) in psbt.inputs.iter_mut().enumerate() {
            let outpoint = psbt.unsigned_tx.input.get(input_idx)
                .ok_or_else(|| anyhow::anyhow!("PSBT input mismatch"))?
                .previous_output;

            // Check if this input is a SNICKER UTXO
            if let Some(utxo) = all_utxos.iter().find(|u| u.outpoint() == outpoint) {
                if let WalletUtxo::Snicker { .. } = utxo {
                    // Populate witness_utxo if missing
                    if input.witness_utxo.is_none() {
                        input.witness_utxo = Some(utxo.txout());
                        info!("    Added witness_utxo for SNICKER input {}", input_idx);
                    }
                }
            }

            // Collect prevouts for sighash calculation
            if let Some(witness_utxo) = &input.witness_utxo {
                prevouts.push(witness_utxo.clone());
            } else {
                return Err(anyhow::anyhow!("Missing witness_utxo for input {}", input_idx));
            }
        }

        // Now sign SNICKER UTXO inputs with their tweaked keys
        for (input_idx, input) in psbt.inputs.iter_mut().enumerate() {
            let outpoint = psbt.unsigned_tx.input.get(input_idx).unwrap().previous_output;

            // Check if this input is a SNICKER UTXO
            if let Some(utxo) = all_utxos.iter().find(|u| u.outpoint() == outpoint) {
                if let WalletUtxo::Snicker { tweaked_privkey, .. } = utxo {
                    // Sign manually with the tweaked private key
                    if input.tap_key_sig.is_none() {
                        use bdk_wallet::bitcoin::sighash::{SighashCache, TapSighashType};
                        use bdk_wallet::bitcoin::secp256k1::{Message, Secp256k1};

                        let secp = Secp256k1::new();
                        let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

                        // Compute taproot key-path sighash
                        let sighash = sighash_cache.taproot_key_spend_signature_hash(
                            input_idx,
                            &bdk_wallet::bitcoin::sighash::Prevouts::All(&prevouts),
                            TapSighashType::Default,
                        )?;

                        let msg = Message::from_digest_slice(sighash.as_byte_array())?;
                        let sig = secp.sign_schnorr(&msg, &tweaked_privkey.keypair(&secp));

                        // Store signature in PSBT
                        input.tap_key_sig = Some(bdk_wallet::bitcoin::taproot::Signature {
                            signature: sig,
                            sighash_type: TapSighashType::Default,
                        });

                        info!("    Signed SNICKER input {} with tweaked key", input_idx);
                    }
                }
            }
        }

        // Check if there are any regular wallet inputs that need signing
        let mut has_regular_wallet_inputs = false;
        for (input_idx, _input) in psbt.inputs.iter().enumerate() {
            let outpoint = psbt.unsigned_tx.input.get(input_idx).unwrap().previous_output;

            // Check if this input is a regular wallet UTXO (not a SNICKER UTXO)
            if let Some(utxo) = all_utxos.iter().find(|u| u.outpoint() == outpoint) {
                if matches!(utxo, WalletUtxo::Regular(_)) {
                    has_regular_wallet_inputs = true;
                    break;
                }
            }
        }

        // Only call wallet.sign() if there are regular wallet inputs to sign
        let finalized = if has_regular_wallet_inputs {
            let wallet = self.wallet.lock().await;
            // Use trust_witness_utxo to avoid errors on inputs not in our wallet (e.g., proposer's SNICKER input)
            let sign_options = SignOptions {
                trust_witness_utxo: true,
                ..Default::default()
            };
            wallet.sign(psbt, sign_options)?
        } else {
            // All our inputs are SNICKER UTXOs, already signed manually
            false
        };

        let signed_count = psbt.inputs.iter().filter(|i| i.tap_key_sig.is_some()).count();
        info!("✅ Signed {} of {} inputs (finalized: {})", signed_count, psbt.inputs.len(), finalized);

        Ok(finalized)
    }

    /// Finalize a fully-signed PSBT into a transaction ready for broadcast.
    /// Returns an error if the PSBT is not fully signed.
    pub async fn finalize_psbt(&mut self, mut psbt: Psbt) -> Result<Transaction> {
        use bdk_wallet::bitcoin::Witness;

        info!("🔍 Finalizing PSBT with {} inputs", psbt.inputs.len());

        // For each input, finalize if it has all required signatures
        // This is a generic finalizer that works for multi-party PSBTs (like SNICKER)
        for (i, input) in psbt.inputs.iter_mut().enumerate() {
            // Skip if already finalized
            if input.final_script_witness.is_some() {
                info!("    Input {}: already finalized", i);
                continue;
            }

            // For taproot key-path spends: finalize if we have tap_key_sig
            if let Some(sig) = input.tap_key_sig {
                info!("    Input {}: finalizing taproot key-path spend", i);
                // Taproot key-path witness is just the signature
                input.final_script_witness = Some(Witness::from_slice(&[sig.to_vec()]));
                // Clear all non-final fields per BIP 174
                input.partial_sigs.clear();
                input.sighash_type = None;
                input.redeem_script = None;
                input.witness_script = None;
                input.bip32_derivation.clear();
                input.tap_key_sig = None;
                input.tap_script_sigs.clear();
                input.tap_scripts.clear();
                input.tap_key_origins.clear();
                input.tap_internal_key = None;
                input.tap_merkle_root = None;
            } else {
                return Err(anyhow::anyhow!("Input {} missing signature - cannot finalize", i));
            }
        }

        info!("✅ All inputs finalized");

        // Extract the final transaction
        let tx = psbt.extract_tx()?;

        Ok(tx)
    }

    /// Broadcast a transaction to the network.
    /// Note: In bdk_kyoto 0.13.1, we need to implement broadcasting.
    /// For now, this returns the txid and prints the hex for manual broadcast.
    pub async fn broadcast_transaction(&mut self, tx: Transaction) -> Result<Txid> {
        use bdk_wallet::bitcoin::consensus::encode::serialize_hex;

        let txid = tx.compute_txid();
        let tx_hex = serialize_hex(&tx);

        info!("📡 Broadcasting transaction");
        info!("   Txid: {}", txid);
        info!("   Hex: {}", tx_hex);

        // Broadcast via Kyoto requester to all connected peers
        let tx_broadcast = TxBroadcast::new(tx, TxBroadcastPolicy::AllPeers);
        self.requester.broadcast_tx(tx_broadcast).await
            .map_err(|e| anyhow!("Broadcast failed: {}", e))?;

        info!("✅ Transaction broadcast successful");

        Ok(txid)
    }

    /// Convenience method: Build, sign, finalize, and broadcast a transaction in one step.
    /// This is the simple "send" interface for basic usage.
    ///
    /// HYBRID VERSION: Uses SNICKER UTXOs up to available amount, then fills remainder with regular UTXOs
    pub async fn send_to_address(
        &mut self,
        address_str: &str,
        amount_sats: u64,
        fee_rate_sat_vb: f32,
    ) -> Result<Txid> {
        // Use hybrid approach: SNICKER UTXOs first, then regular UTXOs as needed
        info!("💰 Using hybrid UTXO selection (SNICKER + regular as needed)");

        // Build and sign transaction
        let (tx, selected) = self.build_and_sign_hybrid_tx(address_str, amount_sats, fee_rate_sat_vb).await?;
        let txid = tx.compute_txid();

        // Broadcast transaction
        info!("📡 Broadcasting transaction...");
        self.broadcast_transaction(tx).await?;

        // Update database state after successful broadcast
        // Mark SNICKER UTXOs as PENDING (not spent yet - waiting for confirmation)
        if !selected.snicker_utxos.is_empty() {
            let conn = self.snicker_conn.lock().unwrap();
            for (txid_str, vout, _, _, _) in &selected.snicker_utxos {
                conn.execute(
                    "UPDATE snicker_utxos SET status = 'pending', spent_in_txid = ? WHERE txid = ? AND vout = ?",
                    (txid.to_string(), txid_str, vout),
                )?;
            }
            drop(conn);

            // Flush to encrypted file after UTXO change
            self.snicker_db.flush(&*self.snicker_conn.lock().unwrap())?;
            info!("📝 Marked {} SNICKER UTXOs as pending (awaiting confirmation)", selected.snicker_utxos.len());
        }

        // Persist wallet state (for regular UTXO tracking)
        if !selected.regular_utxos.is_empty() {
            let mut wallet = self.wallet.lock().await;
            let mut conn = self.conn.lock().await;
            wallet.persist(&mut conn)?;
            drop(conn);
            drop(wallet);
        }

        info!("✅ Transaction broadcast successful");
        Ok(txid)
    }

    /// Build a transaction using SNICKER UTXOs WITHOUT broadcasting it.
    /// Returns the signed transaction for external verification/broadcasting.
    ///
    /// This is useful for testing transaction validity with `testmempoolaccept`
    /// before actual broadcast.
    pub async fn build_snicker_spend_tx(
        &mut self,
        address_str: &str,
        amount_sats: u64,
        fee_rate_sat_vb: f32,
    ) -> Result<Transaction> {
        use bdk_wallet::bitcoin::{
            psbt::Psbt, transaction::Version, ScriptBuf, Sequence, TxIn, TxOut,
            OutPoint, Witness, absolute::LockTime,
        };
        use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey, Message};
        use bdk_wallet::bitcoin::sighash::{SighashCache, TapSighashType, Prevouts};
        use std::str::FromStr;

        // Parse address
        let address = Address::from_str(address_str)?
            .require_network(self.network)?;

        // Get available SNICKER UTXOs
        let snicker_utxos: Vec<(String, u32, u64, Vec<u8>, Vec<u8>)> = {
            let conn = self.snicker_conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT txid, vout, amount, script_pubkey, tweaked_privkey FROM snicker_utxos WHERE block_height IS NOT NULL AND status = 'unspent'"
            )?;
            let mut rows = stmt.query([])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                result.push((
                    row.get(0)?, row.get(1)?, row.get(2)?,
                    row.get(3)?, row.get(4)?,
                ));
            }
            result
        };

        if snicker_utxos.is_empty() {
            return Err(anyhow!("No SNICKER UTXOs available"));
        }

        info!("💰 Found {} SNICKER UTXOs available", snicker_utxos.len());

        // Simple coin selection: use SNICKER UTXOs until we have enough
        let mut selected_utxos = Vec::new();
        let mut total_input = 0u64;

        // Estimate fee (rough estimate for initial selection)
        let estimated_fee_per_input = (150.0 * fee_rate_sat_vb) as u64;

        for utxo in &snicker_utxos {
            selected_utxos.push(utxo);
            total_input += utxo.2;
            let estimated_total_fee = estimated_fee_per_input * selected_utxos.len() as u64;
            if total_input >= amount_sats + estimated_total_fee {
                break;
            }
        }

        if total_input < amount_sats {
            return Err(anyhow!("Insufficient funds: have {}, need {}", total_input, amount_sats));
        }

        info!("✅ Selected {} SNICKER UTXOs (total {} sats)", selected_utxos.len(), total_input);

        // Build transaction manually
        let mut tx_inputs = Vec::new();
        let mut prevouts_for_sighash = Vec::new();

        for (txid_str, vout, amount, script_pubkey, _) in &selected_utxos {
            let txid = Txid::from_str(txid_str)?;
            tx_inputs.push(TxIn {
                previous_output: OutPoint::new(txid, *vout),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });
            prevouts_for_sighash.push(TxOut {
                value: Amount::from_sat(*amount),
                script_pubkey: ScriptBuf::from_bytes(script_pubkey.clone()),
            });
        }

        // Calculate change
        let num_inputs = selected_utxos.len() as u64;
        let num_outputs = 2; // payment + change (we'll adjust if no change later)
        let estimated_vsize = 11 + (num_inputs * 57) + (num_outputs * 43);
        let estimated_fee = estimated_vsize * fee_rate_sat_vb as u64;
        let change_amount = total_input.saturating_sub(amount_sats + estimated_fee);

        let mut tx_outputs = vec![TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: address.script_pubkey(),
        }];

        // Add change output if any
        if change_amount > 0 {
            let mut wallet = self.wallet.lock().await;
            let mut conn = self.conn.lock().await;
            let change_addr = wallet.reveal_next_address(KeychainKind::Internal);
            wallet.persist(&mut conn)?; // Persist the revealed address
            drop(conn);
            drop(wallet);
            tx_outputs.push(TxOut {
                value: Amount::from_sat(change_amount),
                script_pubkey: change_addr.script_pubkey(),
            });
            info!("💸 Change output: {} sats to {}", change_amount, change_addr.address);
        }

        let unsigned_tx = bdk_wallet::bitcoin::Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_inputs,
            output: tx_outputs,
        };

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

        // Fill in witness_utxo for each input
        for (i, (_, _, amount, script_pubkey, _)) in selected_utxos.iter().enumerate() {
            psbt.inputs[i].witness_utxo = Some(TxOut {
                value: Amount::from_sat(*amount),
                script_pubkey: ScriptBuf::from_bytes(script_pubkey.clone()),
            });
        }

        // Sign each SNICKER input with its tweaked private key
        let secp = Secp256k1::new();
        let prevouts = Prevouts::All(&prevouts_for_sighash);
        let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

        for (i, (_, _, _, script_pubkey, tweaked_privkey_bytes)) in selected_utxos.iter().enumerate() {
            // Deserialize tweaked private key
            let tweaked_seckey = SecretKey::from_slice(tweaked_privkey_bytes)?;
            let tweaked_keypair = bdk_wallet::bitcoin::secp256k1::Keypair::from_secret_key(&secp, &tweaked_seckey);

            // SANITY CHECK: Verify that tweaked_seckey * G = expected_pubkey
            use bdk_wallet::bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
            let derived_pubkey = PublicKey::from_secret_key(&secp, &tweaked_seckey);
            let derived_xonly = XOnlyPublicKey::from(derived_pubkey);

            // Extract expected pubkey from scriptPubkey (P2TR format: OP_1 <32-byte-xonly>)
            let script_bytes = script_pubkey;
            if script_bytes.len() != 34 || script_bytes[0] != 0x51 || script_bytes[1] != 0x20 {
                return Err(anyhow!("Invalid P2TR script format for input {}", i));
            }
            let expected_xonly_bytes = &script_bytes[2..34];
            let expected_xonly = XOnlyPublicKey::from_slice(expected_xonly_bytes)?;

            if derived_xonly != expected_xonly {
                return Err(anyhow!(
                    "SANITY CHECK FAILED for input {}:\n\
                     Tweaked private key does not match expected public key!\n\
                     Expected: {}\n\
                     Derived:  {}\n\
                     This means the SNICKER tweak derivation is incorrect.",
                    i,
                    hex::encode(expected_xonly.serialize()),
                    hex::encode(derived_xonly.serialize())
                ));
            }

            info!("✅ Input {}: Sanity check passed (privkey * G = pubkey)", i);

            // Compute sighash
            let sighash = sighash_cache.taproot_key_spend_signature_hash(
                i,
                &prevouts,
                TapSighashType::Default,
            )?;

            // Sign
            let msg = Message::from_digest_slice(sighash.as_byte_array())?;
            let sig = secp.sign_schnorr(&msg, &tweaked_keypair);

            // Add signature to PSBT
            psbt.inputs[i].tap_key_sig = Some(bdk_wallet::bitcoin::taproot::Signature {
                signature: sig,
                sighash_type: TapSighashType::Default,
            });

            info!("✍️  Signed SNICKER input {}", i);
        }

        // Finalize all inputs
        for i in 0..psbt.inputs.len() {
            if let Some(sig) = &psbt.inputs[i].tap_key_sig {
                psbt.inputs[i].final_script_witness = Some(Witness::from_slice(&[sig.to_vec()]));
                psbt.inputs[i].tap_key_sig = None; // Clear after finalizing
            }
        }

        // Extract transaction
        let tx = psbt.extract_tx()?;
        let txid = tx.compute_txid();
        info!("✅ Transaction built with SNICKER UTXOs, txid: {}", txid);

        Ok(tx)
    }

    /// Select UTXOs using hybrid approach: SNICKER first, then regular as needed
    /// This implements the core selection algorithm: to spend X, use SNICKER UTXOs up to Y,
    /// then add regular UTXOs to cover X-Y+fee
    async fn select_utxos_hybrid(
        &mut self,
        amount_sats: u64,
        fee_rate_sat_vb: f32,
    ) -> Result<SelectedUtxos> {
        // Get available SNICKER UTXOs
        let snicker_utxos: Vec<(String, u32, u64, Vec<u8>, Vec<u8>)> = {
            let conn = self.snicker_conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT txid, vout, amount, script_pubkey, tweaked_privkey FROM snicker_utxos WHERE block_height IS NOT NULL AND status = 'unspent'"
            )?;
            let mut rows = stmt.query([])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                result.push((
                    row.get(0)?, row.get(1)?, row.get(2)?,
                    row.get(3)?, row.get(4)?,
                ));
            }
            result
        };

        let total_snicker_available: u64 = snicker_utxos.iter().map(|u| u.2).sum();
        info!("💰 SNICKER UTXOs available: {} sats in {} UTXOs", total_snicker_available, snicker_utxos.len());

        // Select all available SNICKER UTXOs (we want to use them for privacy)
        let selected_snicker = snicker_utxos;
        let snicker_contribution = total_snicker_available;

        // Rough estimate for fee calculation
        let estimated_fee_per_input = (150.0 * fee_rate_sat_vb) as u64;
        let total_needed = amount_sats + estimated_fee_per_input;

        // Determine if we need regular UTXOs
        let (regular_utxos, regular_contribution) = if snicker_contribution < total_needed {
            let shortage = total_needed - snicker_contribution;
            info!("💰 SNICKER UTXOs cover {} sats, need {} more from regular UTXOs",
                  snicker_contribution, shortage);

            // Get regular UTXOs from BDK
            let wallet = self.wallet.lock().await;
            let all_regular: Vec<_> = wallet.list_unspent().collect();
            drop(wallet);

            // Sort by value descending (prefer larger UTXOs)
            let mut sorted_regular = all_regular;
            sorted_regular.sort_by(|a, b| b.txout.value.cmp(&a.txout.value));

            // Select regular UTXOs until we have enough
            let mut selected_regular = Vec::new();
            let mut regular_total = 0u64;

            for utxo in sorted_regular {
                selected_regular.push(utxo);
                regular_total += selected_regular.last().unwrap().txout.value.to_sat();

                // Recalculate fee with current input count
                let total_inputs = selected_snicker.len() + selected_regular.len();
                let estimated_fee = estimated_fee_per_input * total_inputs as u64;

                if snicker_contribution + regular_total >= amount_sats + estimated_fee {
                    break;
                }
            }

            if snicker_contribution + regular_total < amount_sats {
                return Err(anyhow!("Insufficient funds: have {} sats (SNICKER: {}, regular: {}), need {} + fees",
                    snicker_contribution + regular_total, snicker_contribution, regular_total, amount_sats));
            }

            info!("✅ Selected {} regular UTXOs contributing {} sats",
                  selected_regular.len(), regular_total);

            (selected_regular, regular_total)
        } else {
            info!("✅ SNICKER UTXOs alone cover the payment");
            (Vec::new(), 0)
        };

        Ok(SelectedUtxos {
            snicker_utxos: selected_snicker,
            regular_utxos,
            total_snicker: snicker_contribution,
            total_regular: regular_contribution,
        })
    }

    /// Sign SNICKER inputs in a PSBT using their tweaked private keys
    /// Assumes SNICKER inputs are at indices [start_idx..start_idx+snicker_utxos.len())
    pub(crate) fn sign_snicker_inputs(
        psbt: &mut bdk_wallet::bitcoin::psbt::Psbt,
        snicker_utxos: &[(String, u32, u64, Vec<u8>, Vec<u8>)],
        prevouts: &[bdk_wallet::bitcoin::TxOut],
        start_idx: usize,
    ) -> Result<()> {
        use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey, Message};
        use bdk_wallet::bitcoin::sighash::{SighashCache, TapSighashType, Prevouts};

        let secp = Secp256k1::new();
        let prevouts_all = Prevouts::All(prevouts);
        let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

        for (i, (_, _, _, _script_pubkey, tweaked_privkey_bytes)) in snicker_utxos.iter().enumerate() {
            let input_idx = start_idx + i;

            // Deserialize tweaked private key
            let tweaked_seckey = SecretKey::from_slice(tweaked_privkey_bytes)?;
            let tweaked_keypair = bdk_wallet::bitcoin::secp256k1::Keypair::from_secret_key(&secp, &tweaked_seckey);

            // Compute sighash
            let sighash = sighash_cache.taproot_key_spend_signature_hash(
                input_idx,
                &prevouts_all,
                TapSighashType::Default,
            )?;

            // Sign
            let msg = Message::from_digest_slice(sighash.as_byte_array())?;
            let sig = secp.sign_schnorr(&msg, &tweaked_keypair);

            // Add signature to PSBT
            psbt.inputs[input_idx].tap_key_sig = Some(bdk_wallet::bitcoin::taproot::Signature {
                signature: sig,
                sighash_type: TapSighashType::Default,
            });

            info!("✍️  Signed SNICKER input {}", input_idx);
        }

        Ok(())
    }

    /// Build and sign a transaction using hybrid UTXO selection
    /// Uses SNICKER UTXOs up to available amount, then fills remainder with regular UTXOs
    /// Returns the signed transaction ready for broadcast (does not broadcast)
    async fn build_and_sign_hybrid_tx(
        &mut self,
        address_str: &str,
        amount_sats: u64,
        fee_rate_sat_vb: f32,
    ) -> Result<(bdk_wallet::bitcoin::Transaction, SelectedUtxos)> {
        use bdk_wallet::bitcoin::{
            psbt::Psbt, transaction::Version, ScriptBuf, Sequence, TxIn, TxOut,
            OutPoint, Witness, absolute::LockTime,
        };
        use std::str::FromStr;

        // Parse address
        let address = Address::from_str(address_str)?
            .require_network(self.network)?;

        // Step 1: Select UTXOs using hybrid selection algorithm
        let selected = self.select_utxos_hybrid(amount_sats, fee_rate_sat_vb).await?;
        let total_input = selected.total_snicker + selected.total_regular;

        // Step 2: Build transaction inputs
        let mut tx_inputs = Vec::new();
        let mut prevouts_for_sighash = Vec::new();

        // Add SNICKER inputs
        for (txid_str, vout, amount, script_pubkey, _) in &selected.snicker_utxos {
            let txid = Txid::from_str(txid_str)?;
            tx_inputs.push(TxIn {
                previous_output: OutPoint::new(txid, *vout),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });
            prevouts_for_sighash.push(TxOut {
                value: Amount::from_sat(*amount),
                script_pubkey: ScriptBuf::from_bytes(script_pubkey.clone()),
            });
        }

        // Add regular inputs
        for utxo in &selected.regular_utxos {
            tx_inputs.push(TxIn {
                previous_output: utxo.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });
            prevouts_for_sighash.push(utxo.txout.clone());
        }

        // Calculate fee and change
        let num_inputs = tx_inputs.len() as u64;
        let num_outputs = 2; // payment + change
        let estimated_vsize = 11 + (num_inputs * 57) + (num_outputs * 43);
        let estimated_fee = estimated_vsize * fee_rate_sat_vb as u64;
        let change_amount = total_input.saturating_sub(amount_sats + estimated_fee);

        info!("📊 Transaction: {} inputs ({} SNICKER + {} regular), total input {} sats, amount {} sats, fee {} sats, change {} sats",
              num_inputs, selected.snicker_utxos.len(), selected.regular_utxos.len(),
              total_input, amount_sats, estimated_fee, change_amount);

        // Build outputs
        let mut tx_outputs = vec![TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: address.script_pubkey(),
        }];

        // Add change output if any
        if change_amount > 0 {
            let mut wallet = self.wallet.lock().await;
            let mut conn = self.conn.lock().await;
            let change_addr = wallet.reveal_next_address(KeychainKind::Internal);
            wallet.persist(&mut conn)?;
            drop(conn);
            drop(wallet);
            tx_outputs.push(TxOut {
                value: Amount::from_sat(change_amount),
                script_pubkey: change_addr.script_pubkey(),
            });
            info!("💸 Change output: {} sats to {}", change_amount, change_addr.address);
        }

        // Create unsigned transaction
        let unsigned_tx = bdk_wallet::bitcoin::Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_inputs,
            output: tx_outputs,
        };

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

        // Step 3: Fill in witness_utxo for all inputs
        for (i, prevout) in prevouts_for_sighash.iter().enumerate() {
            psbt.inputs[i].witness_utxo = Some(prevout.clone());
        }

        // Step 4: Sign SNICKER inputs using helper function
        if !selected.snicker_utxos.is_empty() {
            Self::sign_snicker_inputs(&mut psbt, &selected.snicker_utxos, &prevouts_for_sighash, 0)?;
        }

        // Step 5: Sign regular inputs with BDK's wallet (if any)
        if !selected.regular_utxos.is_empty() {
            let mut wallet = self.wallet.lock().await;
            info!("✍️  Signing {} regular inputs with BDK...", selected.regular_utxos.len());
            let sign_options = SignOptions::default();
            wallet.sign(&mut psbt, sign_options)?;
            drop(wallet);
            info!("✅ Regular inputs signed");
        }

        // Finalize all inputs
        for i in 0..psbt.inputs.len() {
            if let Some(sig) = &psbt.inputs[i].tap_key_sig {
                psbt.inputs[i].final_script_witness = Some(Witness::from_slice(&[sig.to_vec()]));
                psbt.inputs[i].tap_key_sig = None;
            }
        }

        // Step 6: Finalize PSBT
        if !selected.regular_utxos.is_empty() {
            let mut wallet = self.wallet.lock().await;
            let finalize_result = wallet.finalize_psbt(&mut psbt, SignOptions::default())?;
            drop(wallet);
            if !finalize_result {
                return Err(anyhow!("Failed to finalize PSBT - some inputs not fully signed"));
            }
        }

        // Extract transaction
        let tx = psbt.extract_tx()?;
        let txid = tx.compute_txid();
        info!("✅ Hybrid transaction built and signed, txid: {}", txid);
        info!("   {} SNICKER + {} regular UTXOs",
              selected.snicker_utxos.len(), selected.regular_utxos.len());

        Ok((tx, selected))
    }

    // ============================================================
    // PUBLIC WALLET/STATE HELPERS (used by UI)
    // ============================================================

    pub async fn sync_recent(&mut self) -> Result<()> {
      // Auto-sync is always running in background, just report current state
      let wallet = self.wallet.lock().await;
      let height = wallet.local_chain().tip().height();
      info!("ℹ️  Auto-sync is running in background. Current tip: {height}");
      Ok(())
  }
    /*
    pub async fn sync_recent(&mut self) -> Result<()> {
        // shut down current node
        self.requester.shutdown()?;

        let tip = self.wallet.local_chain().tip().height();
        let from_height = tip.saturating_sub(SYNC_LOOKBACK);

        let (requester, update_subscriber) =
            Self::start_node(&self.wallet, self.network, from_height)?;

        self.requester = requester;
        self.update_subscriber = update_subscriber;

        self.apply_one_update().await
    }*/

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
            let privkey_bytes: Vec<u8> = row.get(3)?;

            let txid = bdk_wallet::bitcoin::Txid::from_str(&txid_str)?;
            let outpoint = OutPoint { txid, vout };
            let privkey = SecretKey::from_slice(&privkey_bytes)?;

            result.push((outpoint, amount, privkey));
        }

        Ok(result)
    }

    /// Get all wallet UTXOs (regular + SNICKER) as unified WalletUtxo enum
    /// This is the single source of truth for all UTXOs in the wallet
    pub async fn get_all_wallet_utxos(&self) -> Result<Vec<WalletUtxo>> {
        let mut result = Vec::new();

        // Regular wallet UTXOs
        let wallet = self.wallet.lock().await;
        for utxo in wallet.list_unspent() {
            result.push(WalletUtxo::Regular(utxo.clone()));
        }
        drop(wallet);

        // SNICKER UTXOs with their tweaked keys
        let snicker_utxos = self.get_snicker_utxos_with_keys().await?;
        for (outpoint, amount, tweaked_privkey) in snicker_utxos {
            // Get script_pubkey from database
            let conn = self.snicker_conn.lock().unwrap();
            let script_bytes: Vec<u8> = conn.query_row(
                "SELECT script_pubkey FROM snicker_utxos WHERE txid = ? AND vout = ?",
                [outpoint.txid.to_string(), outpoint.vout.to_string()],
                |row| row.get(0),
            )?;
            let script_pubkey = bdk_wallet::bitcoin::ScriptBuf::from_bytes(script_bytes);

            result.push(WalletUtxo::Snicker {
                outpoint,
                amount,
                script_pubkey,
                tweaked_privkey,
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
    /// TODO: Implement proper fee estimation by querying mempool or fee estimation service
    pub fn get_fee_rate(&self) -> bdk_wallet::bitcoin::FeeRate {
        // For now, return a conservative default
        // In production, this should query:
        // - Mempool.space API
        // - Bitcoin Core estimatesmartfee
        // - Electrum server fee estimation
        // - Or allow user configuration
        bdk_wallet::bitcoin::FeeRate::from_sat_per_vb(10)
            .expect("valid default fee rate")
    }

    // ============================================================
    // BITCOIN CORE RPC (for proposer mode)
    // ============================================================

    /// Set the Bitcoin Core RPC client (required for proposer mode scanning)
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

    /// Scan blocks for taproot UTXOs matching size criteria
    ///
    /// Gets block hashes from wallet's bdk_blocks table, fetches blocks via P2P,
    /// and scans for taproot outputs matching the size range.
    ///
    /// # Arguments
    /// * `num_blocks` - Number of recent blocks to scan
    /// * `size_min` - Minimum output value in sats
    /// * `size_max` - Maximum output value in sats
    ///
    /// # Returns
    /// Vector of (block_height, txid, full_transaction) for transactions with matching outputs
    pub async fn scan_blocks_for_taproot_utxos(
        &self,
        num_blocks: u32,
        size_min: u64,
        size_max: u64,
    ) -> Result<Vec<(u32, Txid, Transaction)>> {
        // Get current tip height from wallet
        let wallet = self.wallet.lock().await;
        let tip_height = wallet.local_chain().tip().height();
        drop(wallet);

        let start_height = tip_height.saturating_sub(num_blocks - 1);

        info!("🔍 Scanning {} blocks via Kyoto P2P (heights {}-{})", num_blocks, start_height, tip_height);

        // Get block hashes from wallet database (bdk_blocks table)
        let block_hashes = self.get_block_hashes_from_headers_db(start_height, tip_height).await?;
        info!("📊 Retrieved {} block hashes from wallet database", block_hashes.len());

        let mut results = Vec::new();

        // Fetch and scan each block
        for (height, block_hash) in block_hashes {
            match self.requester.get_block(block_hash).await {
                Ok(indexed_block) => {
                    let block = &indexed_block.block;
                    tracing::debug!("📦 Block {} at height {}: {} transactions",
                                   block_hash, height, block.txdata.len());

                    // Scan each transaction in the block
                    for tx in &block.txdata {
                        let txid = tx.compute_txid();
                        let mut has_match = false;

                        // Check each output for taproot + size match
                        for (vout, output) in tx.output.iter().enumerate() {
                            if output.script_pubkey.is_p2tr() {
                                let amount = output.value.to_sat();
                                if amount >= size_min && amount <= size_max {
                                    tracing::info!("✅ Found taproot UTXO: {}:{} ({} sats)",
                                                 txid, vout, amount);
                                    has_match = true;
                                }
                            }
                        }

                        if has_match {
                            results.push((height, txid, tx.clone()));
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("⚠️  Failed to fetch block {} at height {}: {}",
                                 block_hash, height, e);
                }
            }
        }

        info!("📦 Scanned {} blocks via P2P, found {} transactions with matching taproot outputs",
              num_blocks, results.len());
        Ok(results)
    }

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
                                .extract_keys()
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
        let unspent: Vec<(String, u32)> = {
            let conn = snicker_conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT txid, vout FROM snicker_utxos WHERE block_height IS NOT NULL AND status IN ('unspent', 'pending')"
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

    /// Mark a SNICKER UTXO as spent
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
    pub fn derive_utxo_privkey(
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

                // Derive using BIP86 path: m/86'/cointype'/0'/change/index
                let coin_type = if self.network == Network::Bitcoin { 0 } else { 1 };
                let change = match keychain {
                    KeychainKind::External => 0,
                    KeychainKind::Internal => 1,
                };

                let path_str = format!("m/86h/{}h/0h/{}/{}", coin_type, change, derivation_index);
                let derivation_path = DerivationPath::from_str(&path_str)?;

                // Derive the internal private key
                let secp = bdk_wallet::bitcoin::secp256k1::Secp256k1::new();
                let derived = self.xprv.derive_priv(&secp, &derivation_path)?;
                let mut internal_key = derived.private_key;

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
            WalletUtxo::Snicker { tweaked_privkey, .. } => {
                // Return the stored tweaked privkey directly for SNICKER UTXOs
                Ok(*tweaked_privkey)
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
            warn = warn_rx.recv() => if let Some(warn) = warn { tracing::warn!("{warn}") },
            // Suppress info messages from Kyoto to reduce log spam
            _info = info_rx.recv() => { /* Silently consume Kyoto info messages */ },
        }
    }
}
