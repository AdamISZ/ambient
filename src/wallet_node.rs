use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use directories::ProjectDirs;
use tokio::select;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::info;

use bdk_wallet::{
    PersistedWallet,
    bitcoin::Network,
    keys::{
        bip39::{Language, Mnemonic, WordCount},
        DerivableKey, ExtendedKey, GeneratedKey, GeneratableKey,
    },
    rusqlite::Connection,
    template::{Bip86, DescriptorTemplate},
    miniscript::Tap,
    KeychainKind, Wallet,
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

        let (external_desc, _, _) = Bip86(xprv, KeychainKind::External)
            .build(network)
            .expect("Failed to build external descriptor");
        let (internal_desc, _, _) = Bip86(xprv, KeychainKind::Internal)
            .build(network)
            .expect("Failed to build internal descriptor");

        let mut conn = Connection::open(db_path)?;
        info!("💾 Wallet database path: {:?}", db_path);

        if let Some(mut existing) = Wallet::load()
            .descriptor(KeychainKind::External, Some(external_desc.clone()))
            .descriptor(KeychainKind::Internal, Some(internal_desc.clone()))
            .extract_keys()
            .check_network(network)
            .load_wallet(&mut conn)?
        {
            info!("✅ Loaded existing wallet from disk.");

            // Force derivation of lookahead scripts so they're persisted to database
            // This ensures build_with_wallet can find them
            let ext_revealed = existing.derivation_index(KeychainKind::External).unwrap_or(0);
            let int_revealed = existing.derivation_index(KeychainKind::Internal).unwrap_or(0);

            for index in 0..(RECOVERY_LOOKAHEAD + ext_revealed) {
                let _ = existing.peek_address(KeychainKind::External, index);
            }
            for index in 0..(RECOVERY_LOOKAHEAD + int_revealed) {
                let _ = existing.peek_address(KeychainKind::Internal, index);
            }

            existing.persist(&mut conn)?;
            info!("🔧 Derived and persisted {} external + {} internal lookahead scripts",
                  RECOVERY_LOOKAHEAD + ext_revealed, RECOVERY_LOOKAHEAD + int_revealed);

            return Ok((existing, conn));
        }

        info!("🪄 Creating new wallet DB...");
        let mut wallet = Wallet::create(external_desc.clone(), internal_desc.clone())
            .network(network)
            .lookahead(RECOVERY_LOOKAHEAD)
            .create_wallet(&mut conn)?;

        // Force derivation of lookahead scripts for new wallet too
        for index in 0..RECOVERY_LOOKAHEAD {
            let _ = wallet.peek_address(KeychainKind::External, index);
            let _ = wallet.peek_address(KeychainKind::Internal, index);
        }
        wallet.persist(&mut conn)?;
        info!("🔧 Derived and persisted {} lookahead scripts for new wallet", RECOVERY_LOOKAHEAD);

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
        info!("💰 Balance: {}", wallet.balance().total());
        info!("📦 Chain tip: {}", wallet.local_chain().tip().height());
        info!("🧾 Tx count: {}", wallet.transactions().count());
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
