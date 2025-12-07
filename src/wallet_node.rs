use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use directories::ProjectDirs;
use tokio::select;
use tokio::sync::Mutex;
use tracing::info;

use bdk_wallet::{
    PersistedWallet,
    bitcoin::{Network, Address, Amount, FeeRate, Transaction, Txid, psbt::Psbt, hashes::Hash, BlockHash},
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

const RECOVERY_LOOKAHEAD: u32 = 50;
const NUM_CONNECTIONS: u8 = 1;
const SYNC_LOOKBACK: u32 = 5_000; // blocks to rescan on `sync`

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
    /// Path to SNICKER database for checking pending UTXOs
    snicker_db_path: std::path::PathBuf,
}

impl WalletNode {
    // ============================================================
    // PUBLIC ENTRY POINTS
    // ============================================================

    /// Get the wallet name
    pub fn name(&self) -> &str {
        &self.wallet_name
    }

    /// Generate a new wallet (new mnemonic), persist it, and then load it.
    pub async fn generate(
        name: &str,
        network_str: &str,
        recovery_height: u32,
    ) -> Result<(Self, Mnemonic)> {
        let (wallet_dir, _, mnemonic_path) = Self::wallet_paths(name, network_str)?;
        fs::create_dir_all(&wallet_dir)?;

        let gen: GeneratedKey<_, Tap> =
            Mnemonic::generate((WordCount::Words12, Language::English))
                .map_err(|_| anyhow!("Mnemonic generation failed"))?;
        let mnemonic = Mnemonic::parse_in(Language::English, gen.to_string())?;

        fs::write(&mnemonic_path, mnemonic.to_string())?;
        info!("🔑 Generated new mnemonic for wallet '{name}'");

        let node = Self::load(name, network_str, recovery_height).await?;

        Ok((node, mnemonic))
    }

    /// Load an existing wallet by name and start the Kyoto node for it.
    pub async fn load(
        name: &str,
        network_str: &str,
        recovery_height: u32,
    ) -> Result<Self> {
        let network = Self::parse_network(network_str)?;
        let (wallet_dir, db_path, mnemonic_path) = Self::wallet_paths(name, network_str)?;
        fs::create_dir_all(&wallet_dir)?; // okay if already exists

        let mnemonic: Mnemonic = if mnemonic_path.exists() {
            let existing = fs::read_to_string(&mnemonic_path)?;
            Mnemonic::parse(existing.trim())?
        } else {
            return Err(anyhow!(
                "Mnemonic file not found for wallet '{name}' at {:?}",
                mnemonic_path
            ));
        };

        let (wallet, conn) = Self::load_or_create_wallet(&mnemonic, network, &db_path)?;

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

        // Construct path to SNICKER database (before spawning background task)
        let project_dirs = directories::ProjectDirs::from("org", "code", "ambient")
            .ok_or_else(|| anyhow::anyhow!("Could not determine data directory"))?;
        let snicker_db_path = project_dirs
            .data_local_dir()
            .join(network_str)
            .join(name)
            .join("snicker.sqlite");

        let wallet_db_path_for_bg = project_dirs
            .data_local_dir()
            .join(network_str)
            .join(name)
            .join("wallet.sqlite");

        // Derive descriptors for SNICKER UTXO detection
        let coin_type = if network == Network::Bitcoin { 0 } else { 1 };
        let external_desc = format!("tr({}/86h/{}h/0h/0/*)", xprv, coin_type);
        let internal_desc = format!("tr({}/86h/{}h/0h/1/*)", xprv, coin_type);

        // Spawn background task to auto-sync
        let wallet_clone = wallet.clone();
        let conn_clone = conn.clone();
        let sub_clone = update_subscriber.clone();
        let snicker_db_clone = snicker_db_path.clone();
        let wallet_db_clone = wallet_db_path_for_bg.clone();
        let requester_clone = requester.clone();
        let wallet_name_clone = name.to_string();
        let network_clone = network;
        let external_desc_clone = external_desc.clone();
        let internal_desc_clone = internal_desc.clone();
        tokio::spawn(async move {
            Self::background_sync(
                wallet_clone,
                conn_clone,
                sub_clone,
                snicker_db_clone,
                wallet_db_clone,
                requester_clone,
                wallet_name_clone,
                network_clone,
                external_desc_clone,
                internal_desc_clone,
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
            snicker_db_path,
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

    fn wallet_paths(name: &str, network_str: &str) -> Result<(PathBuf, PathBuf, PathBuf)> {
        let project_dirs = ProjectDirs::from("org", "code", "ambient")
            .ok_or_else(|| anyhow!("Cannot determine project dir"))?;

        let wallet_dir = project_dirs.data_local_dir().join(network_str).join(name);
        let db_path = wallet_dir.join("wallet.sqlite");
        let mnemonic_path = wallet_dir.join("mnemonic.txt");

        Ok((wallet_dir, db_path, mnemonic_path))
    }

    fn load_or_create_wallet(
        mnemonic: &Mnemonic,
        network: Network,
        db_path: &Path,
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

        let mut conn = Connection::open(db_path)?;
        info!("💾 Wallet database path: {:?}", db_path);

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

            tracing::debug!("Ensuring SPK index includes lookahead: External up to {}, Internal up to {}",
                max_external + RECOVERY_LOOKAHEAD, max_internal + RECOVERY_LOOKAHEAD);

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

            tracing::debug!("SPK index populated with {} external and {} internal scripts",
                max_external + RECOVERY_LOOKAHEAD + 1, max_internal + RECOVERY_LOOKAHEAD + 1);
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
            tracing::debug!("Derived and persisted {} lookahead scripts", RECOVERY_LOOKAHEAD);

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
        // Use actual genesis block hash for height 0, otherwise all_zeros as placeholder
        let checkpoint_hash = if from_height == 0 {
            use bdk_wallet::bitcoin::blockdata::constants::genesis_block;
            genesis_block(network).block_hash()
        } else {
            BlockHash::all_zeros()
        };

        let checkpoint = HeaderCheckpoint::new(from_height, checkpoint_hash);
        let scan_type = ScanType::Recovery {
            used_script_index: RECOVERY_LOOKAHEAD,
            checkpoint,
        };
        info!("🔍 Recovery starting from height {} with hash {}", from_height, checkpoint_hash);

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
        snicker_db_path: std::path::PathBuf,
        wallet_db_path: std::path::PathBuf,
        requester: bdk_kyoto::Requester,
        wallet_name: String,
        network: Network,
        external_descriptor: String,
        internal_descriptor: String,
    ) {
        loop {
            let mut sub = update_subscriber.lock().await;
            let update_result = sub.update().await;
            drop(sub); // Release lock before processing

            match update_result {
                Ok(update) => {
                    let mut wallet = wallet.lock().await;
                    let mut conn = conn.lock().await;

                    info!("📦 Auto-sync: received update");
                    if let Err(e) = wallet.apply_update(update) {
                        tracing::error!("Failed to apply update: {e}");
                        continue;
                    }

                    // CRITICAL: After applying blockchain updates, repopulate SPK index
                    // This ensures newly discovered UTXOs can be signed
                    let mut max_external = 0u32;
                    let mut max_internal = 0u32;
                    for utxo in wallet.list_unspent() {
                        match utxo.keychain {
                            KeychainKind::External => max_external = max_external.max(utxo.derivation_index),
                            KeychainKind::Internal => max_internal = max_internal.max(utxo.derivation_index),
                        }
                    }
                    if max_external > 0 || max_internal > 0 {
                        tracing::debug!("🔧 Repopulating SPK index after scan: External up to {}, Internal up to {}",
                            max_external, max_internal);
                        // Use peek_address() to add scripts to SPK index WITHOUT advancing derivation index
                        // This allows the light client to scan for these addresses while keeping
                        // the next user-facing address at the first unused one
                        for index in 0..=(max_external + RECOVERY_LOOKAHEAD) {
                            let _ = wallet.peek_address(KeychainKind::External, index);
                        }
                        for index in 0..=(max_internal + RECOVERY_LOOKAHEAD) {
                            let _ = wallet.peek_address(KeychainKind::Internal, index);
                        }
                    }

                    if let Err(e) = wallet.persist(&mut conn) {
                        tracing::error!("Failed to persist wallet: {e}");
                    }

                    let height = wallet.local_chain().tip().height();
                    info!("✅ Auto-sync: updated to height {height}");

                    // Release wallet lock before checking SNICKER UTXOs
                    drop(wallet);
                    drop(conn);

                    // Check for pending SNICKER UTXOs and insert them if confirmed
                    if let Err(e) = Self::check_pending_snicker_utxos(
                        &snicker_db_path,
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
                        &snicker_db_path,
                        &wallet_db_path,
                    )
                    .await
                    {
                        tracing::error!("Failed to check spent SNICKER UTXOs: {e}");
                    }
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
        let wallet = self.wallet.lock().await;

        info!("✍️  Signing PSBT with {} inputs", psbt.inputs.len());

        let finalized = wallet.sign(psbt, SignOptions::default())?;

        let signed_count = psbt.inputs.iter().filter(|i| i.tap_key_sig.is_some()).count();
        info!("✅ Signed {} inputs (finalized: {})", signed_count, finalized);

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
    /// SIMPLIFIED VERSION: Uses BDK's integrated approach without manual PSBT manipulation
    pub async fn send_to_address(
        &mut self,
        address_str: &str,
        amount_sats: u64,
        fee_rate_sat_vb: f32,
    ) -> Result<Txid> {
        // Check if we have SNICKER UTXOs available
        let snicker_balance = self.get_snicker_balance_sats().await?;

        if snicker_balance > 0 {
            // Prefer SNICKER UTXOs (coinjoined funds have better privacy & reduces recovery burden)
            info!("💰 SNICKER balance available ({} sats), preferring coinjoined UTXOs", snicker_balance);
            self.send_with_snicker_utxos(address_str, amount_sats, fee_rate_sat_vb).await
        } else {
            // Fall back to regular descriptor-derived UTXOs
            info!("💰 Using regular UTXOs (no SNICKER funds available)");
            self.try_send_regular_only(address_str, amount_sats, fee_rate_sat_vb).await
        }
    }

    /// Try to send using only regular descriptor-derived UTXOs
    async fn try_send_regular_only(
        &mut self,
        address_str: &str,
        amount_sats: u64,
        fee_rate_sat_vb: f32,
    ) -> Result<Txid> {
        // Parse address
        let address = Address::from_str(address_str)
            .map_err(|e| anyhow!("Invalid address: {}", e))?
            .require_network(self.network)
            .map_err(|e| anyhow!("Address network mismatch: {}", e))?;

        let mut wallet = self.wallet.lock().await;

        info!("🔨 Building transaction with regular UTXOs...");
        let mut tx_builder = wallet.build_tx();
        tx_builder.add_recipient(address.script_pubkey(), Amount::from_sat(amount_sats));
        tx_builder.fee_rate(FeeRate::from_sat_per_vb_unchecked(fee_rate_sat_vb as u64));

        let mut psbt = tx_builder.finish()?;
        info!("✅ PSBT created with {} inputs, {} outputs", psbt.inputs.len(), psbt.outputs.len());

        // Sign
        info!("✍️  Signing transaction...");
        let sign_options = SignOptions::default();
        let finalized = wallet.sign(&mut psbt, sign_options)?;
        info!("🔍 Sign result - finalized: {}", finalized);

        // Finalize
        info!("🔐 Finalizing transaction...");
        let finalize_result = wallet.finalize_psbt(&mut psbt, SignOptions::default())?;
        info!("🔍 Finalize result: {}", finalize_result);

        if !finalize_result {
            return Err(anyhow!("PSBT could not be finalized - missing signatures"));
        }

        // Extract transaction
        let tx = psbt.extract_tx()?;
        info!("✅ Transaction extracted, txid: {}", tx.compute_txid());

        // Persist wallet state
        let mut conn = self.conn.lock().await;
        wallet.persist(&mut conn)?;
        drop(conn);
        drop(wallet);

        // Broadcast
        info!("📡 Broadcasting transaction...");
        let txid = self.broadcast_transaction(tx).await?;

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
        use bdk_wallet::rusqlite::Connection;
        use std::str::FromStr;

        // Parse address
        let address = Address::from_str(address_str)?
            .require_network(self.network)?;

        // Get available SNICKER UTXOs
        let snicker_utxos: Vec<(String, u32, u64, Vec<u8>, Vec<u8>)> = {
            let conn = Connection::open(&self.snicker_db_path)?;
            let mut stmt = conn.prepare(
                "SELECT txid, vout, amount, script_pubkey, tweaked_privkey FROM snicker_utxos WHERE block_height IS NOT NULL AND spent = 0"
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

    /// Send transaction using SNICKER UTXOs (fallback when regular UTXOs insufficient)
    async fn send_with_snicker_utxos(
        &mut self,
        address_str: &str,
        amount_sats: u64,
        fee_rate_sat_vb: f32,
    ) -> Result<Txid> {
        use bdk_wallet::bitcoin::{
            psbt::Psbt, transaction::Version, ScriptBuf, Sequence, TxIn, TxOut,
            OutPoint, Witness, absolute::LockTime,
        };
        use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey, Message};
        use bdk_wallet::bitcoin::sighash::{SighashCache, TapSighashType, Prevouts};
        use bdk_wallet::rusqlite::Connection;
        use std::str::FromStr;

        // Parse address
        let address = Address::from_str(address_str)?
            .require_network(self.network)?;

        // Get available SNICKER UTXOs
        let snicker_utxos: Vec<(String, u32, u64, Vec<u8>, Vec<u8>)> = {
            let conn = Connection::open(&self.snicker_db_path)?;
            let mut stmt = conn.prepare(
                "SELECT txid, vout, amount, script_pubkey, tweaked_privkey FROM snicker_utxos WHERE block_height IS NOT NULL AND spent = 0"
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
        // TODO: Smarter selection, include regular UTXOs too
        let mut selected_utxos = Vec::new();
        let mut total_input = 0u64;

        // Estimate fee (rough estimate: 1 input + 1 output + overhead = ~150 vbytes per input)
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
            return Err(anyhow!("Insufficient funds even with SNICKER UTXOs: have {}, need {}", total_input, amount_sats));
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
        // Estimate transaction size in vbytes (weight / 4):
        // Non-witness (1 vbyte per byte): base(10) + per_input(40) + per_output(43)
        // Witness (0.25 vbytes per byte): overhead(2) + per_input_sig(~66)
        // Formula: 10.5 + (num_inputs * 56.5) + (num_outputs * 43)
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

        // Don't manually insert - let auto-sync discover it via the change output
        // The change output uses a descriptor-derived script, so Kyoto will detect it

        // Mark SNICKER UTXOs as spent in SNICKER database
        {
            let conn = Connection::open(&self.snicker_db_path)?;
            for (txid_str, vout, _, _, _) in &selected_utxos {
                conn.execute(
                    "UPDATE snicker_utxos SET spent = 1 WHERE txid = ? AND vout = ?",
                    (txid_str, vout),
                )?;
            }
        }

        // Broadcast
        info!("📡 Broadcasting transaction...");
        self.broadcast_transaction(tx).await?;
        info!("✅ Transaction sent using SNICKER UTXOs");

        Ok(txid)
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
        use bdk_wallet::rusqlite::Connection;

        let conn = Connection::open(&self.snicker_db_path)?;
        let balance: Option<i64> = conn.query_row(
            "SELECT SUM(amount) FROM snicker_utxos WHERE block_height IS NOT NULL AND spent = 0",
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

    pub async fn list_unspent(&self) -> Result<Vec<String>> {
        use bdk_wallet::rusqlite::Connection;

        let wallet = self.wallet.lock().await;
        let mut out = vec![];

        // Regular wallet UTXOs
        for utxo in wallet.list_unspent() {
            out.push(format!(
                "{}:{} ({} sats)",
                utxo.outpoint.txid,
                utxo.outpoint.vout,
                utxo.txout.value.to_sat()
            ));
        }
        drop(wallet);

        // SNICKER UTXOs from separate database
        let snicker_utxos: Vec<(String, u32, u64)> = {
            let conn = Connection::open(&self.snicker_db_path)?;
            let mut stmt = conn.prepare(
                "SELECT txid, vout, amount FROM snicker_utxos WHERE block_height IS NOT NULL AND spent = 0"
            )?;
            let mut rows = stmt.query([])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                result.push((row.get(0)?, row.get(1)?, row.get(2)?));
            }
            result
        };

        for (txid, vout, amount) in snicker_utxos {
            out.push(format!("{}:{} ({} sats) [SNICKER]", txid, vout, amount));
        }

        Ok(out)
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
    pub fn get_block_hashes_from_headers_db(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> Result<Vec<(u32, bdk_wallet::bitcoin::BlockHash)>> {
        use bdk_wallet::bitcoin::BlockHash;
        use bdk_wallet::rusqlite::Connection;
        use std::str::FromStr;

        // Construct path to wallet database (headers are stored in bdk_blocks table)
        let project_dirs = directories::ProjectDirs::from("org", "code", "ambient")
            .ok_or_else(|| anyhow::anyhow!("Could not determine data directory"))?;

        let network_str = match self.network {
            bdk_wallet::bitcoin::Network::Bitcoin => "mainnet",
            bdk_wallet::bitcoin::Network::Testnet => "testnet",
            bdk_wallet::bitcoin::Network::Signet => "signet",
            bdk_wallet::bitcoin::Network::Regtest => "regtest",
            _ => return Err(anyhow::anyhow!("Unsupported network")),
        };

        // Construct path to wallet database
        let wallet_db_path = project_dirs.data_local_dir()
            .join(network_str)
            .join(&self.wallet_name)
            .join("wallet.sqlite");

        if !wallet_db_path.exists() {
            return Err(anyhow::anyhow!("Wallet database not found at {:?}", wallet_db_path));
        }

        // Open wallet database (read-only)
        let conn = Connection::open_with_flags(
            &wallet_db_path,
            bdk_wallet::rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;

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
        let block_hashes = self.get_block_hashes_from_headers_db(start_height, tip_height)?;
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
        snicker_db_path: &std::path::Path,
        requester: &bdk_kyoto::Requester,
        wallet_name: &str,
        network: Network,
        external_descriptor: &str,
        internal_descriptor: &str,
    ) -> Result<()> {
        use bdk_wallet::rusqlite::Connection;
        use std::str::FromStr;

        // Open SNICKER database and query for pending UTXOs (all synchronous, before any async)
        let pending: Vec<(String, u32)> = {
            let conn = Connection::open(snicker_db_path)?;
            let mut stmt = conn.prepare(
                "SELECT txid, vout FROM snicker_utxos WHERE block_height IS NULL AND spent = 0"
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

        // Get wallet database path
        let project_dirs = directories::ProjectDirs::from("org", "code", "ambient")
            .ok_or_else(|| anyhow::anyhow!("Could not determine data directory"))?;
        let network_str = match network {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
            _ => return Err(anyhow::anyhow!("Unsupported network")),
        };
        let wallet_db_path = project_dirs
            .data_local_dir()
            .join(network_str)
            .join(wallet_name)
            .join("wallet.sqlite");

        // Open wallet database to get tip height and block hashes
        let wallet_conn_read = Connection::open_with_flags(
            &wallet_db_path,
            bdk_wallet::rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;

        let tip_height: u32 = wallet_conn_read.query_row(
            "SELECT MAX(block_height) FROM bdk_blocks",
            [],
            |row| row.get(0),
        )?;

        // Scan recent blocks (last 10) for pending transactions
        let start_height = tip_height.saturating_sub(10);

        let block_hashes: Vec<(u32, String)> = {
            let mut stmt = wallet_conn_read.prepare(
                "SELECT block_height, block_hash FROM bdk_blocks WHERE block_height >= ? AND block_height <= ? ORDER BY block_height"
            )?;
            let mut rows = stmt.query([start_height, tip_height])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                result.push((row.get(0)?, row.get(1)?));
            }
            result
        };

        // Close read connection before async operations
        drop(wallet_conn_read);

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

                        // Open wallet database for writing (scoped to avoid holding across awaits)
                        {
                            let mut wallet_write_conn = Connection::open(&wallet_db_path)?;

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
                                .load_wallet(&mut wallet_write_conn)?
                                .ok_or_else(|| anyhow::anyhow!("Wallet not found"))?;

                            let update = bdk_wallet::Update {
                                tx_update,
                                chain: None,
                                last_active_indices: Default::default(),
                            };
                            wallet.apply_update(update)?;
                            wallet.persist(&mut wallet_write_conn)?;
                            drop(wallet);
                            drop(wallet_write_conn);
                        }

                        // Update block_height in SNICKER database (scoped)
                        {
                            let snicker_update_conn = Connection::open(snicker_db_path)?;
                            snicker_update_conn.execute(
                                "UPDATE snicker_utxos SET block_height = ? WHERE txid = ?",
                                (height, &txid_str),
                            )?;
                            drop(snicker_update_conn);
                        }

                        info!("✅ SNICKER UTXO confirmed and inserted into wallet: {} at height {}", txid, height);
                    }
                }
            }
        }

        Ok(())
    }

    /// Check for spent SNICKER UTXOs and mark them as spent (static helper)
    async fn check_spent_snicker_utxos(
        snicker_db_path: &std::path::Path,
        wallet_db_path: &std::path::Path,
    ) -> Result<()> {
        use bdk_wallet::rusqlite::Connection;

        // Get all unspent SNICKER UTXOs from database
        let unspent: Vec<(String, u32)> = {
            let conn = Connection::open(snicker_db_path)?;
            let mut stmt = conn.prepare(
                "SELECT txid, vout FROM snicker_utxos WHERE block_height IS NOT NULL AND spent = 0"
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

        // Open wallet database to check for spending transactions
        let wallet_conn = Connection::open_with_flags(
            wallet_db_path,
            bdk_wallet::rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;

        // Check each UTXO to see if it's been spent by scanning wallet transactions
        for (txid_str, vout) in unspent {
            // Query wallet database for any transaction that spends this outpoint
            let spending_txid: Result<String, _> = wallet_conn.query_row(
                "SELECT DISTINCT tx.txid FROM bdk_tx tx
                 INNER JOIN bdk_txin txin ON tx.id = txin.tx_id
                 WHERE txin.prev_tx = ?1 AND txin.prev_vout = ?2",
                (&txid_str, vout),
                |row| row.get(0),
            );

            if let Ok(spending_txid_str) = spending_txid {
                tracing::info!("🔍 SNICKER UTXO {}:{} has been spent in {}", txid_str, vout, spending_txid_str);

                // Mark as spent in SNICKER database
                let snicker_conn = Connection::open(snicker_db_path)?;
                snicker_conn.execute(
                    "UPDATE snicker_utxos SET spent = 1, spent_in_txid = ? WHERE txid = ? AND vout = ?",
                    (spending_txid_str, &txid_str, vout),
                )?;
                tracing::info!("✅ Marked SNICKER UTXO {}:{} as spent", txid_str, vout);
            }
        }

        drop(wallet_conn);
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
        keychain: KeychainKind,
        derivation_index: u32,
    ) -> Result<bdk_wallet::bitcoin::secp256k1::SecretKey> {
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
}

async fn trace_logs(
    mut info_rx: Receiver<Info>,
    mut warn_rx: UnboundedReceiver<Warning>,
) {
    loop {
        select! {
            warn = warn_rx.recv() => if let Some(warn) = warn { tracing::warn!("{warn}") },
            info = info_rx.recv() => if let Some(info) = info { tracing::info!("{info}") },
        }
    }
}
