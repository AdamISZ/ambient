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
    bitcoin::{Network, Address, Amount, FeeRate, Transaction, Txid, psbt::Psbt},
    keys::{
        bip39::{Language, Mnemonic, WordCount},
        DerivableKey, ExtendedKey, GeneratedKey, GeneratableKey,
    },
    rusqlite::Connection,
    miniscript::Tap,
    KeychainKind, Wallet, SignOptions,
};

use bdk_kyoto::builder::{NodeBuilder, NodeBuilderExt};
use bdk_kyoto::{Info, LightClient, Receiver, ScanType, UnboundedReceiver, Warning, TxBroadcast, TxBroadcastPolicy};

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
}

impl WalletNode {
    // ============================================================
    // PUBLIC ENTRY POINTS
    // ============================================================

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

        // Spawn background task to auto-sync
        let wallet_clone = wallet.clone();
        let conn_clone = conn.clone();
        let sub_clone = update_subscriber.clone();
        tokio::spawn(async move {
            Self::background_sync(wallet_clone, conn_clone, sub_clone).await;
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

        info!("🔍 Descriptor contains private key: {}", external_desc.contains("prv"));

        let mut conn = Connection::open(db_path)?;
        info!("💾 Wallet database path: {:?}", db_path);

        // Check if wallet already exists by trying to load it
        // CRITICAL: When loading from DB, we must call .descriptor().extract_keys() to restore signers
        // Use Box::leak to convert String to &'static str (acceptable for descriptor strings)
        let external_desc_static: &'static str = Box::leak(external_desc.clone().into_boxed_str());
        let internal_desc_static: &'static str = Box::leak(internal_desc.clone().into_boxed_str());

        info!("🔍 Loading wallet with descriptors and extract_keys():");
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

            info!("🔧 Repopulating SPK index: External up to {}, Internal up to {}",
                max_external, max_internal);

            // Use reveal_addresses_to() which actually updates the SPK index
            // (peek_address() only reads, doesn't update!)
            let _ = loaded.reveal_addresses_to(KeychainKind::External, max_external + RECOVERY_LOOKAHEAD).collect::<Vec<_>>();
            let _ = loaded.reveal_addresses_to(KeychainKind::Internal, max_internal + RECOVERY_LOOKAHEAD).collect::<Vec<_>>();

            // Persist the index changes to database
            loaded.persist(&mut conn)?;

            info!("✅ SPK index repopulated and persisted");
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
            info!("🔧 Derived and persisted {} lookahead scripts", RECOVERY_LOOKAHEAD);

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
        let scan_type = ScanType::Recovery {
            from_height,
        };
        info!("🔍 Recovery starting height: {}", from_height);

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
            log_subscriber,
            info_subscriber,
            warning_subscriber,
            update_subscriber,
            node,
        } = NodeBuilder::new(network)
            .add_peer(peer)
            .required_peers(NUM_CONNECTIONS)
            .data_dir(kyoto_db_path)
            .build_with_wallet(wallet, scan_type)
            .unwrap();

        info!("🔧 Node built - bdk_kyoto 0.13.1 will auto-register wallet scripts");

        tokio::spawn(async move {
            if let Err(e) = node.run().await {
                tracing::error!("Kyoto node terminated with error: {e:?}");
            } else {
                tracing::info!("Kyoto node exited cleanly.");
            }
        });

        tokio::spawn(async move {
            trace_logs(log_subscriber, info_subscriber, warning_subscriber).await;
        });

        Ok((requester, update_subscriber))
    }

    async fn background_sync(
        wallet: Arc<Mutex<PersistedWallet<Connection>>>,
        conn: Arc<Mutex<Connection>>,
        update_subscriber: Arc<Mutex<bdk_kyoto::UpdateSubscriber>>,
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
                        let _ = wallet.reveal_addresses_to(KeychainKind::External, max_external + RECOVERY_LOOKAHEAD).collect::<Vec<_>>();
                        let _ = wallet.reveal_addresses_to(KeychainKind::Internal, max_internal + RECOVERY_LOOKAHEAD).collect::<Vec<_>>();
                    }

                    if let Err(e) = wallet.persist(&mut conn) {
                        tracing::error!("Failed to persist wallet: {e}");
                    }

                    let height = wallet.local_chain().tip().height();
                    info!("✅ Auto-sync: updated to height {height}");
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
                info!("    script: {}", utxo.script_pubkey);
            }
            info!("  non_witness_utxo: {}", input.non_witness_utxo.is_some());
            info!("  sighash_type: {:?}", input.sighash_type);
            info!("  tap_internal_key: {:?}", input.tap_internal_key);
            info!("  tap_merkle_root: {:?}", input.tap_merkle_root);
            info!("  tap_key_sig: {:?}", input.tap_key_sig);
            info!("  tap_script_sigs: {}", input.tap_script_sigs.len());
            info!("  tap_key_origins: {}", input.tap_key_origins.len());
            for (xonly, (leaf_hashes, (fingerprint, path))) in &input.tap_key_origins {
                info!("    xonly: {}", xonly);
                info!("    fingerprint: {}", fingerprint);
                info!("    path: {}", path);
                info!("    leaf_hashes: {} entries", leaf_hashes.len());
            }
            info!("  bip32_derivation: {}", input.bip32_derivation.len());
            info!("  partial_sigs: {}", input.partial_sigs.len());
            info!("  final_script_witness: {}", input.final_script_witness.is_some());
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
        self.requester.broadcast_tx(tx_broadcast)
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
        // Parse address
        let address = Address::from_str(address_str)
            .map_err(|e| anyhow!("Invalid address: {}", e))?
            .require_network(self.network)
            .map_err(|e| anyhow!("Address network mismatch: {}", e))?;

        let mut wallet = self.wallet.lock().await;

        info!("🔨 Building transaction...");
        let mut tx_builder = wallet.build_tx();
        tx_builder.add_recipient(address.script_pubkey(), Amount::from_sat(amount_sats));
        tx_builder.fee_rate(FeeRate::from_sat_per_vb_unchecked(fee_rate_sat_vb as u64));

        let mut psbt = tx_builder.finish()?;
        info!("✅ PSBT created with {} inputs, {} outputs", psbt.inputs.len(), psbt.outputs.len());

        // PHASE 1 DEBUG: Dump PSBT state after tx_builder.finish() (working case)
        Self::dump_psbt_state(&psbt, "After tx_builder.finish() - WORKING");

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
        info!("✅ Transaction sent: {}", txid);

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
        let sats = wallet.balance().total().to_sat();
        Ok(format!("{sats} sats"))
    }

    /// Get next address and persist derivation index.
    /// Note: In bdk_kyoto 0.15+, scripts are automatically registered from the wallet.
    pub async fn get_next_address(&mut self) -> Result<String> {
        let mut wallet = self.wallet.lock().await;
        let mut conn = self.conn.lock().await;

        let info = wallet.reveal_next_address(KeychainKind::External);

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
        let wallet = self.wallet.lock().await;
        let mut out = vec![];
        for utxo in wallet.list_unspent() {
            out.push(format!(
                "{}:{} ({} sats)",
                utxo.outpoint.txid,
                utxo.outpoint.vout,
                utxo.txout.value.to_sat()
            ));
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
        use bdk_wallet::bitcoin::hashes::Hash;
        use bdk_wallet::rusqlite::Connection;

        // Construct path to Kyoto's headers database
        let project_dirs = directories::ProjectDirs::from("org", "code", "ambient")
            .ok_or_else(|| anyhow::anyhow!("Could not determine data directory"))?;

        let network_str = match self.network {
            bdk_wallet::bitcoin::Network::Bitcoin => "mainnet",
            bdk_wallet::bitcoin::Network::Testnet => "testnet",
            bdk_wallet::bitcoin::Network::Signet => "signet",
            bdk_wallet::bitcoin::Network::Regtest => "regtest",
            _ => return Err(anyhow::anyhow!("Unsupported network")),
        };

        // Construct direct path to this wallet's headers.db
        let headers_db_path = project_dirs.data_local_dir()
            .join(network_str)
            .join(&self.wallet_name)
            .join("kyoto_peers")
            .join("light_client_data")
            .join(network_str)
            .join("headers.db");

        if !headers_db_path.exists() {
            return Err(anyhow::anyhow!("Headers database not found at {:?}", headers_db_path));
        }

        // Open Kyoto's header database (read-only)
        let conn = Connection::open_with_flags(
            &headers_db_path,
            bdk_wallet::rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;

        // Query for block hashes in the height range
        let mut stmt = conn.prepare(
            "SELECT height, block_hash FROM headers WHERE height >= ? AND height <= ? ORDER BY height"
        )?;

        let mut block_hashes = Vec::new();
        let rows = stmt.query_map([start_height, end_height], |row| {
            let height: u32 = row.get(0)?;
            let hash_bytes: Vec<u8> = row.get(1)?;
            Ok((height, hash_bytes))
        })?;

        for row in rows {
            let (height, hash_bytes) = row?;
            // Database stores hashes in internal byte order, which is what BlockHash::from_slice expects
            // (BlockHash handles display order conversion when printing)
            let hash = BlockHash::from_slice(&hash_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid block hash: {}", e))?;
            block_hashes.push((height, hash));
        }

        Ok(block_hashes)
    }

    /// Scan blocks for taproot UTXOs matching size criteria
    ///
    /// Gets block hashes from Kyoto's headers.db, fetches blocks via P2P,
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

        // Get block hashes from Kyoto's headers database
        let block_hashes = self.get_block_hashes_from_headers_db(start_height, tip_height)?;
        info!("📊 Retrieved {} block hashes from headers.db", block_hashes.len());

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

    /// Derive the private key for a specific UTXO
    ///
    /// Used for SNICKER DH operations and tweak validation.
    ///
    /// # Arguments
    /// * `keychain` - External or Internal keychain
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
    mut log_rx: Receiver<String>,
    mut info_rx: Receiver<Info>,
    mut warn_rx: UnboundedReceiver<Warning>,
) {
    loop {
        select! {
            log = log_rx.recv() => if let Some(log) = log { tracing::info!("{log}") },
            warn = warn_rx.recv() => if let Some(warn) = warn { tracing::warn!("{warn}") },
            info = info_rx.recv() => if let Some(info) = info { tracing::info!("{info}") },
        }
    }
}
