use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use directories::ProjectDirs;
use tokio::select;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::info;

use bdk_wallet::{
    PersistedWallet,
    bitcoin::{Network, Address, Amount, FeeRate, Transaction, Txid, psbt::Psbt},
    keys::{
        bip39::{Language, Mnemonic, WordCount},
        DerivableKey, ExtendedKey, GeneratedKey, GeneratableKey,
    },
    rusqlite::Connection,
    template::{Bip86, DescriptorTemplate},
    miniscript::Tap,
    KeychainKind, Wallet, SignOptions,
};

use bdk_kyoto::builder::{NodeBuilder, NodeBuilderExt};
use bdk_kyoto::{Info, LightClient, Receiver, ScanType, UnboundedReceiver, Warning};

const RECOVERY_LOOKAHEAD: u32 = 50;
const NUM_CONNECTIONS: u8 = 1;
const SYNC_LOOKBACK: u32 = 5_000; // blocks to rescan on `sync`

/// High-level struct encapsulating wallet + node + requester
pub struct WalletNode {
    pub wallet: Arc<Mutex<PersistedWallet<Connection>>>,
    pub conn: Arc<Mutex<Connection>>,
    pub requester: bdk_kyoto::Requester,
    update_subscriber: Arc<Mutex<bdk_kyoto::UpdateSubscriber>>,
    pub network: Network,
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
            Self::start_node(&wallet, network, recovery_height)?;

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
        let project_dirs = ProjectDirs::from("org", "code", "rustsnicker")
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

        // BIP86 uses m/86'/cointype'/0' as the account path
        let coin_type = if network == Network::Bitcoin { 0 } else { 1 };

        // Put the full BIP86 derivation path in the descriptor string
        // The descriptor parser will handle the derivation internally
        // Using 'h' for hardened derivation in descriptor syntax
        let external_desc = format!("tr({}/86h/{}h/0h/0/*)", xprv, coin_type);
        let internal_desc = format!("tr({}/86h/{}h/0h/1/*)", xprv, coin_type);

        info!("🔍 Descriptor has private keys: {}", external_desc.contains("prv"));

        let mut conn = Connection::open(db_path)?;
        info!("💾 Wallet database path: {:?}", db_path);

        // Check if wallet already exists by trying to load it
        let maybe_wallet = Wallet::load()
            .check_network(network)
            .load_wallet(&mut conn)?;

        let mut wallet = if let Some(loaded) = maybe_wallet {
            info!("✅ Loaded existing wallet from database");
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

        Ok((wallet, conn))
    }

    fn start_node(
        wallet: &PersistedWallet<Connection>,
        network: Network,
        from_height: u32,
    ) -> Result<(bdk_kyoto::Requester, bdk_kyoto::UpdateSubscriber)> {
        let scan_type = ScanType::Recovery {
            from_height,
        };
        info!("🔍 Recovery starting height: {}", from_height);

        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(34, 135, 189, 101)), 38333);

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

        info!("🔍 Building transaction with {} recipients", recipients.len());
        info!("🔍 Wallet balance: {} sats", wallet.balance().total().to_sat());

        let mut tx_builder = wallet.build_tx();

        // Add all recipients
        for (address, amount) in recipients {
            info!("🔍 Adding recipient: {} sats", amount.to_sat());
            tx_builder.add_recipient(address.script_pubkey(), amount);
        }

        // Set fee rate
        tx_builder.fee_rate(fee_rate);

        // Build the PSBT
        info!("🔍 Finishing transaction build...");
        let mut psbt = tx_builder.finish()?;
        info!("🔍 PSBT created with {} inputs, {} outputs", psbt.inputs.len(), psbt.outputs.len());

        // Fix missing witness_utxo: BDK only sets it if the full previous transaction
        // is in the wallet's graph. With Kyoto, we might not have the full tx, but we
        // do have the TxOut from list_unspent(). Manually populate it here.
        let utxos: Vec<_> = wallet.list_unspent().collect();
        for (i, psbt_input) in psbt.inputs.iter_mut().enumerate() {
            if psbt_input.witness_utxo.is_none() {
                let outpoint = psbt.unsigned_tx.input[i].previous_output;
                if let Some(utxo) = utxos.iter().find(|u| u.outpoint == outpoint) {
                    psbt_input.witness_utxo = Some(utxo.txout.clone());
                    info!("🔧 Manually set witness_utxo for input {}", i);
                }
            }
        }

        // Debug: check PSBT state after building
        for (i, input) in psbt.inputs.iter().enumerate() {
            info!("🔍 Input {} after build - witness_utxo: {}, non_witness_utxo: {}, tap_internal_key: {}, tap_key_origins: {}",
                  i,
                  input.witness_utxo.is_some(),
                  input.non_witness_utxo.is_some(),
                  input.tap_internal_key.is_some(),
                  input.tap_key_origins.len());
        }

        Ok(psbt)
    }

    /// Sign a PSBT with the wallet's keys.
    /// Returns true if the PSBT is fully signed after this operation.
    pub async fn sign_psbt(&mut self, psbt: &mut Psbt) -> Result<bool> {
        let mut wallet = self.wallet.lock().await;

        info!("🔍 Signing PSBT with {} inputs", psbt.inputs.len());

        // Debug: Get wallet's key fingerprint
        let descriptor = wallet.public_descriptor(KeychainKind::External);
        info!("🔍 Wallet descriptor: {}", descriptor);

        // Debug: check PSBT state before signing
        for (i, input) in psbt.inputs.iter().enumerate() {
            info!("🔍 Input {} BEFORE sign:", i);
            info!("    - witness_utxo: {}", input.witness_utxo.is_some());
            info!("    - non_witness_utxo: {}", input.non_witness_utxo.is_some());
            info!("    - tap_internal_key: {:?}", input.tap_internal_key);
            info!("    - tap_merkle_root: {:?}", input.tap_merkle_root);
            info!("    - tap_key_sig: {:?}", input.tap_key_sig);
            info!("    - tap_key_origins: {}", input.tap_key_origins.len());

            // Debug: inspect tap_key_origins
            for (pubkey, (leaf_hashes, (fingerprint, derivation_path))) in &input.tap_key_origins {
                info!("      - pubkey: {}", pubkey);
                info!("        fingerprint: {}", fingerprint);
                info!("        derivation_path: {}", derivation_path);
                info!("        leaf_hashes: {:?}", leaf_hashes);
            }

            info!("    - bip32_derivation: {}", input.bip32_derivation.len());
            info!("    - partial_sigs: {}", input.partial_sigs.len());
            info!("    - final_witness: {}", input.final_script_witness.is_some());
        }

        let finalized = wallet.sign(psbt, SignOptions::default())?;
        info!("🔍 Sign result - finalized: {}", finalized);

        // Debug: check PSBT state after signing
        for (i, input) in psbt.inputs.iter().enumerate() {
            info!("🔍 Input {} AFTER sign:", i);
            info!("    - tap_internal_key: {:?}", input.tap_internal_key);
            info!("    - tap_key_sig: {:?}", input.tap_key_sig);
            info!("    - tap_key_origins: {}", input.tap_key_origins.len());
            info!("    - partial_sigs: {}", input.partial_sigs.len());
            info!("    - final_witness: {}", input.final_script_witness.is_some());
            if let Some(ref witness) = input.final_script_witness {
                info!("    - witness stack size: {}", witness.len());
            }
        }

        Ok(finalized)
    }

    /// Finalize a fully-signed PSBT into a transaction ready for broadcast.
    /// Returns an error if the PSBT is not fully signed.
    pub async fn finalize_psbt(&mut self, mut psbt: Psbt) -> Result<Transaction> {
        // Extract the final transaction (validates PSBT structure and finalization)
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

        info!("📡 Transaction ready for broadcast");
        info!("   Txid: {}", txid);
        info!("   Hex: {}", tx_hex);

        println!("\n⚠️  Broadcast not yet implemented - use this hex to broadcast manually:");
        println!("{}", tx_hex);
        println!();

        Ok(txid)
    }

    /// Convenience method: Build, sign, finalize, and broadcast a transaction in one step.
    /// This is the simple "send" interface for basic usage.
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

        // Build transaction
        let recipients = vec![(address, Amount::from_sat(amount_sats))];
        let fee_rate = FeeRate::from_sat_per_vb_unchecked(fee_rate_sat_vb as u64);

        info!("🔨 Building transaction...");
        let mut psbt = self.build_transaction(recipients, fee_rate).await?;

        // Sign transaction
        info!("✍️  Signing transaction...");
        let finalized = self.sign_psbt(&mut psbt).await?;

        if finalized {
            info!("✅ PSBT fully signed and finalized");
        } else {
            info!("⚠️  PSBT signed but needs finalization");
        }

        // Finalize transaction (extract_tx will fail if not properly signed)
        info!("🔐 Finalizing transaction...");
        let tx = self.finalize_psbt(psbt).await?;

        // Persist wallet state (update used UTXOs, change address, etc.)
        {
            let mut conn = self.conn.lock().await;
            let mut wallet = self.wallet.lock().await;
            wallet.persist(&mut conn)?;
        } // Drop locks before broadcast

        // Broadcast transaction
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
