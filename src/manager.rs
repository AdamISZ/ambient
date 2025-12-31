//! Application Manager
//!
//! Coordinates between WalletNode (blockchain/wallet operations) and Snicker (protocol operations).
//! Provides high-level business logic operations that the UI layer can call.

use anyhow::{Result, Context};
use bdk_wallet::bitcoin::{Transaction, psbt::Psbt};
use tracing::info;

use crate::wallet_node::WalletNode;
use crate::snicker::{Snicker, ProposalOpportunity, EncryptedProposal, Proposal};
use crate::network::{ProposalNetwork, ProposalFilter};
use std::path::Path;
use std::sync::Arc;

/// High-level application manager that coordinates wallet and SNICKER operations
pub struct Manager {
    pub wallet_node: WalletNode,
    pub snicker: Snicker,
    /// Network backend for publishing/subscribing to proposals
    pub network: Arc<dyn ProposalNetwork>,
}

/// Result of scanning a proposals directory
#[derive(Debug, Clone)]
pub struct ProposalScanResult {
    pub tag: [u8; 8],
    pub tag_hex: String,
    pub filename: String,
    pub delta: i64,
    pub proposer_input: String,
    pub proposer_value: u64,
    pub receiver_output_value: u64,
}

impl Manager {
    /// Create a new Manager by loading an existing wallet and initializing SNICKER
    ///
    /// # Arguments
    /// * `wallet_name` - Name of the wallet to load
    /// * `network_str` - Network ("regtest", "signet", "mainnet")
    /// * `recovery_height` - Height to start blockchain recovery from
    ///
    /// Load an existing wallet with password
    ///
    /// # Arguments
    /// * `wallet_name` - Name of the wallet to load
    /// * `network_str` - Network ("mainnet", "signet", "regtest", "testnet")
    /// * `recovery_height` - Blockchain height to start scanning from
    /// * `password` - Password for decrypting wallet files
    ///
    /// # TODO
    /// Add wallet file locking to prevent multiple instances from opening the same wallet.
    /// This would avoid SQLite "database is locked" errors and potential double-spending issues.
    /// Consider using a lockfile (e.g., .wallet.lock) or flock() on the wallet database.
    pub async fn load(
        wallet_name: &str,
        network_str: &str,
        recovery_height: u32,
        password: &str,
        peer: Option<String>,
    ) -> Result<Self> {
        // Load wallet and start node
        let wallet_node = WalletNode::load(wallet_name, network_str, recovery_height, password, peer).await?;

        // Initialize SNICKER with shared in-memory database
        let snicker_conn = wallet_node.get_snicker_conn();
        let snicker_db = wallet_node.get_snicker_db_manager();
        let snicker = crate::snicker::Snicker::new(snicker_conn, Some(snicker_db), wallet_node.network)?;

        // Initialize network backend from config
        let config = crate::config::Config::load()?;
        let network = config.create_proposal_network();

        Ok(Self {
            wallet_node,
            snicker,
            network,
        })
    }

    /// Generate a new wallet and initialize SNICKER
    ///
    /// # Arguments
    /// * `wallet_name` - Name of the wallet
    /// * `network_str` - Network ("mainnet", "signet", "regtest", "testnet")
    /// * `recovery_height` - Blockchain height to start scanning from
    /// * `password` - Password for encrypting wallet files
    pub async fn generate(
        wallet_name: &str,
        network_str: &str,
        recovery_height: u32,
        password: &str,
    ) -> Result<(Self, bdk_wallet::keys::bip39::Mnemonic)> {
        // Generate new wallet
        let (wallet_node, mnemonic) = WalletNode::generate(wallet_name, network_str, recovery_height, password).await?;

        // Initialize SNICKER with shared in-memory database
        let snicker_conn = wallet_node.get_snicker_conn();
        let snicker_db = wallet_node.get_snicker_db_manager();
        let snicker = crate::snicker::Snicker::new(snicker_conn, Some(snicker_db), wallet_node.network)?;

        // Initialize network backend from config
        let config = crate::config::Config::load()?;
        let network = config.create_proposal_network();

        Ok((Self {
            wallet_node,
            snicker,
            network,
        }, mnemonic))
    }

    // ============================================================
    // WALLET OPERATIONS (delegate to WalletNode)
    // ============================================================

    /// Get wallet balance
    pub async fn get_balance(&self) -> Result<String> {
        self.wallet_node.get_balance().await
    }

    /// Get next receiving address
    pub async fn get_next_address(&mut self) -> Result<String> {
        self.wallet_node.get_next_address().await
    }

    /// List unspent outputs
    pub async fn list_unspent(&self) -> Result<Vec<String>> {
        self.wallet_node.list_unspent().await
    }

    /// Get all unspent UTXO outpoints (including SNICKER UTXOs)
    /// Returns Vec of (txid_string, vout, amount, is_snicker)
    pub async fn get_all_unspent_outpoints(&self) -> Result<Vec<(String, u32, u64, bool)>> {
        self.wallet_node.get_all_unspent_outpoints().await
    }

    /// Subscribe to wallet update events (balance changes, new blocks, etc.)
    ///
    /// Returns a receiver that will receive events whenever the blockchain state changes.
    /// This is event-driven - consumers only receive updates when Kyoto detects actual
    /// blockchain activity (new blocks, transactions, etc.), not on a polling interval.
    ///
    /// # Example
    /// ```no_run
    /// # use ambient::manager::Manager;
    /// # async fn example(manager: &Manager) {
    /// let mut updates = manager.subscribe_to_updates();
    /// while let Ok(update) = updates.recv().await {
    ///     println!("New block: height={}, balance={}", update.height, update.balance_sats);
    /// }
    /// # }
    /// ```
    pub fn subscribe_to_updates(&self) -> tokio::sync::broadcast::Receiver<crate::wallet_node::WalletUpdate> {
        self.wallet_node.subscribe_to_updates()
    }

    /// Send to address with automatic fee estimation (6-block target)
    ///
    /// Returns error if fee estimation fails - user must specify manual fee rate.
    pub async fn send_to_address_auto(
        &mut self,
        address_str: &str,
        amount_sats: u64,
    ) -> Result<bdk_wallet::bitcoin::Txid> {
        self.wallet_node.send_to_address_auto(address_str, amount_sats).await
    }

    /// Send to address with manual fee rate
    pub async fn send_to_address(
        &mut self,
        address_str: &str,
        amount_sats: u64,
        fee_rate_sat_vb: f32,
    ) -> Result<bdk_wallet::bitcoin::Txid> {
        self.wallet_node.send_to_address(address_str, amount_sats, fee_rate_sat_vb).await
    }

    /// Calculate maximum sendable amount (total balance minus fee)
    pub async fn calculate_max_sendable(&self, address_str: &str, fee_rate_sat_vb: f32) -> Result<u64> {
        self.wallet_node.calculate_max_sendable(address_str, fee_rate_sat_vb).await
    }

    /// Build a SNICKER spending transaction WITHOUT broadcasting (for testing)
    ///
    /// Returns the signed transaction hex that can be tested with testmempoolaccept
    /// before broadcasting via RPC.
    pub async fn build_snicker_tx(
        &mut self,
        address_str: &str,
        amount_sats: u64,
        fee_rate_sat_vb: f32,
    ) -> Result<String> {
        use bdk_wallet::bitcoin::consensus::encode::serialize_hex;

        let tx = self.wallet_node.build_snicker_spend_tx(address_str, amount_sats, fee_rate_sat_vb).await?;
        let tx_hex = serialize_hex(&tx);
        Ok(tx_hex)
    }

    /// Print wallet summary
    pub async fn print_summary(&self) {
        self.wallet_node.print_summary().await
    }

    /// Wait for wallet to sync to at least the specified height
    ///
    /// Waits for blockchain updates from background_sync until the wallet reaches
    /// the target height, or times out.
    ///
    /// # Arguments
    /// * `target_height` - Minimum height to wait for
    /// * `timeout_secs` - Maximum seconds to wait (default 30)
    pub async fn wait_for_height(&self, target_height: u32, timeout_secs: u64) -> Result<u32> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);

        // Check if we're already at the target height
        {
            let wallet = self.wallet_node.wallet.lock().await;
            let current_height = wallet.local_chain().tip().height();
            if current_height >= target_height {
                tracing::info!("✅ Already at height {}", current_height);
                return Ok(current_height);
            }
        }

        // Subscribe to blockchain updates from background_sync
        // This avoids deadlock by not calling .update() directly
        let mut update_rx = self.wallet_node.subscribe_to_updates();

        loop {
            // Wait for next update with timeout
            let update_result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                update_rx.recv()
            ).await;

            match update_result {
                Ok(Ok(_update)) => {
                    // Check if we've reached target height
                    let wallet = self.wallet_node.wallet.lock().await;
                    let current_height = wallet.local_chain().tip().height();
                    if current_height >= target_height {
                        tracing::info!("✅ Synced to height {}", current_height);
                        return Ok(current_height);
                    }
                    tracing::info!("Sync update: height {} / {}", current_height, target_height);
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                    tracing::warn!("Lagged {} blockchain updates, continuing", n);
                    continue;
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                    return Err(anyhow::anyhow!("Background sync stopped"));
                }
                Err(_) => {
                    // Timeout - check total elapsed time
                    if start.elapsed() > timeout {
                        let wallet = self.wallet_node.wallet.lock().await;
                        let current_height = wallet.local_chain().tip().height();
                        return Err(anyhow::anyhow!(
                            "Sync timeout: only reached height {} (expected >= {})",
                            current_height, target_height
                        ));
                    }
                }
            }
        }
    }

    // ============================================================
    // SNICKER OPERATIONS (coordinate between WalletNode and Snicker)
    // ============================================================

    /// Scan recent blocks for SNICKER candidate transactions
    ///
    /// Uses Bitcoin Core RPC to scan for taproot UTXOs matching size criteria.
    /// Requires RPC client to be configured via set_rpc_client().
    ///
    /// # Arguments
    /// * `num_blocks` - Number of recent blocks to scan
    /// * `size_min` - Minimum output size in satoshis
    /// * `size_max` - Maximum output size in satoshis
    ///
    /// # Returns
    /// Number of candidates found and stored
    // Removed: scan_for_snicker_candidates
    // Candidates are now queried directly from partial_utxo_set which is automatically
    // populated during blockchain scanning. No separate scanning or storage needed.

    /// Find SNICKER proposal opportunities for our wallet
    ///
    /// # Arguments
    /// * `min_candidate_sats` - Minimum size of candidate UTXOs
    /// * `max_candidate_sats` - Maximum size of candidate UTXOs (default: u64::MAX for no limit)
    /// * `max_block_age` - Maximum age in blocks from tip (0 = all blocks)
    /// * `snicker_only` - Only consider SNICKER v1 transaction outputs
    ///
    /// # Returns
    /// List of opportunities sorted by value
    pub async fn find_snicker_opportunities(
        &self,
        min_candidate_sats: u64,
        max_candidate_sats: u64,
        max_block_age: u32,
        snicker_only: bool,
    ) -> Result<Vec<ProposalOpportunity>> {
        // Get all our UTXOs (both regular wallet and SNICKER UTXOs)
        let our_utxos = self.wallet_node.get_all_wallet_utxos().await?;

        // Query candidates from partial_utxo_set (unspent P2TR UTXOs in size range)
        let candidates = self.get_snicker_candidates(min_candidate_sats, max_candidate_sats, max_block_age, snicker_only).await?;

        // Find opportunities using Snicker (no longer filtering our UTXOs by size)
        self.snicker.find_opportunities(&our_utxos, &candidates)
    }

    /// Create a SNICKER proposal for a specific opportunity
    ///
    /// # Arguments
    /// * `opportunity` - The opportunity to create a proposal for
    /// * `delta_sats` - Fee adjustment (positive = receiver pays more, negative = proposer incentivizes)
    ///
    /// # Returns
    /// Tuple of (partially-signed PSBT, encrypted proposal with signed PSBT to publish)
    pub async fn create_snicker_proposal(
        &mut self,
        opportunity: &ProposalOpportunity,
        delta_sats: i64,
        min_change_output_size: u64,
    ) -> Result<(Proposal, EncryptedProposal)> {
        // Get our UTXO from unified UTXO list
        let all_utxos = self.wallet_node.get_all_wallet_utxos().await?;
        let our_utxo = all_utxos.iter()
            .find(|utxo| utxo.outpoint() == opportunity.our_outpoint)
            .ok_or_else(|| anyhow::anyhow!("UTXO not found in wallet"))?
            .clone();

        // Get addresses for outputs from wallet
        let mut wallet = self.wallet_node.wallet.lock().await;
        let mut conn = self.wallet_node.conn.lock().await;

        let equal_output_addr = wallet.reveal_next_address(bdk_wallet::KeychainKind::External).address;
        let change_output_addr = wallet.reveal_next_address(bdk_wallet::KeychainKind::Internal).address;

        // Persist updated derivation indices
        wallet.persist(&mut conn)?;

        drop(wallet);
        drop(conn);

        // Derive our input private key (the proposer's input key used for SNICKER tweak)
        let our_input_privkey = self.wallet_node.derive_utxo_privkey(&our_utxo).await?;

        // Get fee rate from wallet (uses real-time fee estimation)
        let fee_rate = self.wallet_node.get_fee_rate().await;

        // Create signing callback that signs the proposer's input
        // Use block_in_place to allow blocking operations in async context
        let wallet_clone = self.wallet_node.wallet.clone();
        let our_utxo_clone = our_utxo.clone();
        let snicker_conn_clone = self.wallet_node.get_snicker_conn();
        let our_input_privkey_clone = our_input_privkey; // Already tweaked, ready for signing
        let sign_callback = move |psbt: &mut Psbt| -> Result<()> {
            use bdk_wallet::KeychainKind;

            let wallet = tokio::task::block_in_place(|| {
                wallet_clone.blocking_lock()
            });

            tracing::info!("🔨 Proposer signing PSBT with {} inputs", psbt.inputs.len());

            // Check if proposer's input is a SNICKER UTXO - if so, sign it manually
            if let crate::wallet_node::WalletUtxo::Snicker { outpoint, amount, script_pubkey } = &our_utxo_clone {
                tracing::info!("🔑 Proposer's input is a SNICKER UTXO, signing with existing helper");

                // Find which input index corresponds to our SNICKER UTXO
                let our_input_idx = psbt.unsigned_tx.input.iter().position(|input| {
                    input.previous_output == *outpoint
                }).ok_or_else(|| anyhow::anyhow!("Proposer's SNICKER input not found in PSBT"))?;

                // Fetch private key on-demand from database in a tight scope
                // SecretKey implements secure drop - memory is zeroed when it goes out of scope
                let privkey_bytes = {
                    use bdk_wallet::bitcoin::secp256k1::SecretKey;
                    let conn = snicker_conn_clone.lock().unwrap();
                    let bytes: Vec<u8> = conn.query_row(
                        "SELECT tweaked_privkey FROM snicker_utxos WHERE txid = ? AND vout = ?",
                        [outpoint.txid.to_string(), outpoint.vout.to_string()],
                        |row| row.get(0),
                    )?;
                    bytes
                };

                // Prepare data in format expected by sign_snicker_inputs helper
                let snicker_utxo_data = vec![(
                    outpoint.txid.to_string(),
                    outpoint.vout,
                    *amount,
                    script_pubkey.to_bytes(),
                    privkey_bytes,
                )];

                // Collect prevouts
                let prevouts: Vec<_> = psbt.inputs.iter()
                    .map(|input| input.witness_utxo.clone()
                        .ok_or_else(|| anyhow::anyhow!("Missing witness_utxo")))
                    .collect::<Result<Vec<_>>>()?;

                // Use existing signing helper
                crate::wallet_node::WalletNode::sign_snicker_inputs(
                    psbt,
                    &snicker_utxo_data,
                    &prevouts,
                    our_input_idx,
                )?;

                tracing::info!("✅ Signed SNICKER input {} with tweaked privkey", our_input_idx);
            } else if let crate::wallet_node::WalletUtxo::Regular(local_utxo) = &our_utxo_clone {
                // Regular wallet UTXO - sign directly using the pre-derived tweaked key
                tracing::info!("🔑 Proposer's input is a Regular UTXO, signing with tweaked privkey");

                // Find which input index corresponds to our UTXO
                let our_input_idx = psbt.unsigned_tx.input.iter().position(|input| {
                    input.previous_output == local_utxo.outpoint
                }).ok_or_else(|| anyhow::anyhow!("Proposer's regular input not found in PSBT"))?;

                // Sign using the pre-derived tweaked private key
                use bdk_wallet::bitcoin::sighash::{SighashCache, TapSighashType, Prevouts};
                use bdk_wallet::bitcoin::secp256k1::{Message, Secp256k1};

                let secp = Secp256k1::new();

                // Collect prevouts for sighash calculation
                let prevouts: Vec<_> = psbt.inputs.iter()
                    .map(|input| input.witness_utxo.clone()
                        .ok_or_else(|| anyhow::anyhow!("Missing witness_utxo")))
                    .collect::<Result<Vec<_>>>()?;

                let prevouts_refs: Vec<_> = prevouts.iter().collect();
                let prevouts_all = Prevouts::All(&prevouts_refs);
                let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

                // Compute taproot sighash
                let sighash = sighash_cache.taproot_key_spend_signature_hash(
                    our_input_idx,
                    &prevouts_all,
                    TapSighashType::Default,
                )?;

                // Sign with the tweaked private key
                let msg = Message::from_digest_slice(sighash.as_ref())?;
                let signature = secp.sign_schnorr(&msg, &our_input_privkey_clone.keypair(&secp));

                // Store signature in PSBT
                psbt.inputs[our_input_idx].tap_key_sig = Some(bdk_wallet::bitcoin::taproot::Signature {
                    signature,
                    sighash_type: TapSighashType::Default,
                });

                tracing::info!("✅ Signed regular input {} with tweaked privkey", our_input_idx);
            }

            // Note: We only sign OUR input (the proposer's input)
            // The other input belongs to the receiver and will be signed by them

            Ok(())
        };

        // Create proposal using Snicker (will sign via callback)
        let (proposal, encrypted_proposal) = self.snicker.propose(
            opportunity.target_outpoint,
            opportunity.target_txout.clone(),
            our_utxo.outpoint(),
            our_utxo.txout(),
            our_input_privkey,  // Proposer's input key for SNICKER tweak (enables recovery)
            equal_output_addr,
            change_output_addr,
            delta_sats,
            fee_rate,
            min_change_output_size,
            sign_callback,
        )?;

        // Note: We don't store created proposals anymore (proposer side)
        // The encrypted blob is returned directly for sharing
        self.snicker.store_created_proposal(&encrypted_proposal).await?;

        // Store decrypted proposal in our database (proposer side)
        let our_utxo_str = format!("{}:{}", opportunity.our_outpoint.txid, opportunity.our_outpoint.vout);
        let target_utxo_str = format!("{}:{}", opportunity.target_outpoint.txid, opportunity.target_outpoint.vout);

        self.snicker.store_decrypted_proposal(
            &proposal,
            "proposer",
            &our_utxo_str,
            &target_utxo_str,
            delta_sats,
        ).await?;

        Ok((proposal, encrypted_proposal))
    }

    /// Finalize a fully-signed PSBT into a transaction
    ///
    /// # Arguments
    /// * `psbt` - A fully-signed PSBT (both proposer and receiver have signed)
    ///
    /// # Returns
    /// The finalized transaction ready for broadcast
    pub async fn finalize_psbt(&mut self, psbt: Psbt) -> Result<Transaction> {
        self.wallet_node.finalize_psbt(psbt).await
    }

    /// Store an encrypted SNICKER proposal (for publishing/sharing)
    /// Store an encrypted SNICKER proposal by attempting to decrypt it
    /// If decryption succeeds (proposal is for one of our UTXOs), stores in decrypted_proposals table
    /// If decryption fails (not for us), silently ignores
    pub async fn store_snicker_proposal(&mut self, proposal: &EncryptedProposal) -> Result<()> {
        // Get all our UTXOs (both regular wallet and SNICKER UTXOs)
        let our_utxos = self.wallet_node.get_all_wallet_utxos().await?;

        // Try to decrypt the proposal for each UTXO
        for utxo in &our_utxos {
            // Derive the private key for this UTXO
            let privkey = self.wallet_node.derive_utxo_privkey(utxo).await?;

            let decrypt_result = self.snicker.try_decrypt_for_utxo(
                proposal,
                utxo,
                |_u| Ok(privkey),
            );

            if let Ok(decrypted) = decrypt_result {
                let outpoint = utxo.outpoint();
                let utxo_type = match utxo {
                    crate::wallet_node::WalletUtxo::Regular(_) => "regular",
                    crate::wallet_node::WalletUtxo::Snicker { .. } => "SNICKER",
                };

                tracing::info!("✅ Decrypted proposal tag {} for {} UTXO {}:{}",
                    ::hex::encode(&proposal.tag),
                    utxo_type,
                    outpoint.txid,
                    outpoint.vout
                );

                // Calculate delta
                let delta = self.snicker.calculate_delta_from_proposal(&decrypted)?;

                // Identify UTXOs in the proposal
                let our_utxo_str = format!("{}:{}", outpoint.txid, outpoint.vout);

                // Find proposer's UTXO (the input that's not ours)
                let mut proposer_utxo_str = String::from("unknown");
                for input in &decrypted.psbt.unsigned_tx.input {
                    let input_str = format!("{}:{}", input.previous_output.txid, input.previous_output.vout);
                    if input_str != our_utxo_str {
                        proposer_utxo_str = input_str;
                        break;
                    }
                }

                // Store in decrypted_proposals table (INSERT OR IGNORE handles duplicates)
                self.snicker.store_decrypted_proposal(
                    &decrypted,
                    "receiver",
                    &our_utxo_str,
                    &proposer_utxo_str,
                    delta,
                ).await?;

                tracing::info!("💾 Stored decrypted proposal with delta {} sats", delta);
                return Ok(());
            }
        }

        // If we get here, proposal wasn't meant for us - that's okay
        tracing::debug!("Proposal tag {} not meant for our wallet (couldn't decrypt)",
            ::hex::encode(&proposal.tag));
        Ok(())
    }

    /// Deserialize and store a proposal from its serialized form
    /// Returns the proposal tag
    pub async fn load_proposal_from_serialized(&mut self, serialized: &str) -> Result<[u8; 8]> {
        // Parse the JSON-like format
        let ephemeral_pubkey = serialized
            .lines()
            .find(|l| l.contains("ephemeral_pubkey"))
            .and_then(|l| l.split('"').nth(3))
            .ok_or_else(|| anyhow::anyhow!("Missing ephemeral_pubkey"))?;

        let tag_hex = serialized
            .lines()
            .find(|l| l.contains("\"tag\""))
            .and_then(|l| l.split('"').nth(3))
            .ok_or_else(|| anyhow::anyhow!("Missing tag"))?;

        let version_str = serialized
            .lines()
            .find(|l| l.contains("\"version\""))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|s| s.trim().trim_end_matches(',').parse::<u8>().ok());

        let encrypted_data_hex = serialized
            .lines()
            .find(|l| l.contains("encrypted_data"))
            .and_then(|l| l.split('"').nth(3))
            .ok_or_else(|| anyhow::anyhow!("Missing encrypted_data"))?;

        // Decode from hex
        let pubkey = ephemeral_pubkey.parse::<bdk_wallet::bitcoin::secp256k1::PublicKey>()?;
        let tag_bytes = ::hex::decode(tag_hex)?;
        let encrypted_data = ::hex::decode(encrypted_data_hex)?;

        if tag_bytes.len() != 8 {
            return Err(anyhow::anyhow!("Invalid tag length"));
        }

        let mut tag = [0u8; 8];
        tag.copy_from_slice(&tag_bytes);

        // Default to v1 if not specified (backward compatibility)
        let version = version_str.unwrap_or(crate::snicker::SNICKER_VERSION_V1);

        let proposal = EncryptedProposal {
            ephemeral_pubkey: pubkey,
            tag,
            version,
            encrypted_data,
        };

        // Store it
        self.store_snicker_proposal(&proposal).await?;

        Ok(tag)
    }

    /// Scan for SNICKER proposals meant for our wallet
    ///
    /// Checks all stored proposals and attempts to decrypt those meant for our UTXOs.
    /// Caches successfully decrypted proposals in the database for later acceptance.
    ///
    /// # Arguments
    /// * `acceptable_delta_range` - Min and max delta we'll accept (e.g., (-1000, 5000))
    ///
    /// # Returns
    /// List of valid proposals we can participate in
    /// Scan for proposals within acceptable delta range
    ///
    /// Note: Proposals are decrypted and stored when received via store_snicker_proposal().
    /// This method simply queries the decrypted_proposals table.
    pub async fn scan_for_our_proposals(
        &self,
        acceptable_delta_range: (i64, i64),
    ) -> Result<Vec<Proposal>> {
        tracing::info!("🔍 Querying decrypted_proposals table with delta range {} to {} and status='pending'",
            acceptable_delta_range.0, acceptable_delta_range.1);

        // Simply query the decrypted_proposals table
        let proposals = self.snicker.get_decrypted_proposals_by_delta_range(
            acceptable_delta_range.0,
            acceptable_delta_range.1,
            "pending",
        ).await?;

        tracing::info!("📊 Query returned {} proposals", proposals.len());
        Ok(proposals)
    }


    /// Process a single incoming proposal (pub-sub architecture)
    ///
    /// Attempts to load and decrypt a single proposal. If successful and within delta range,
    /// returns a ProposalScanResult. This is the pub-sub equivalent of scan_proposals_directory.
    ///
    /// # Arguments
    /// * `proposal` - The encrypted proposal to process
    /// * `delta_range` - (min_delta, max_delta) acceptable range in sats
    ///
    /// # Returns
    /// Some(ProposalScanResult) if proposal is decryptable and within range, None otherwise
    pub async fn process_incoming_proposal(
        &mut self,
        proposal: &crate::snicker::EncryptedProposal,
        delta_range: (i64, i64),
    ) -> Result<Option<ProposalScanResult>> {
        use crate::network::serialization::serialize_proposal_json_pretty;

        // Serialize the proposal to the format expected by load_proposal_from_serialized
        let serialized = serialize_proposal_json_pretty(proposal);

        // Try to load (deserialize, decrypt, store)
        let tag = match self.load_proposal_from_serialized(&serialized).await {
            Ok(tag) => tag,
            Err(e) => {
                // Proposal not decryptable with our UTXOs or invalid
                tracing::debug!("Skipped proposal: {}", e);
                return Ok(None);
            }
        };

        // Query the database to get the decrypted proposal
        let decrypted = match self.snicker.get_decrypted_proposal_by_tag(&tag).await? {
            Some(proposal) => proposal,
            None => {
                // Not in database - means proposal wasn't decryptable (not for our wallet)
                // This is normal - most proposals won't be for us
                tracing::debug!("Proposal {} not decryptable with our UTXOs", hex::encode(&tag));
                return Ok(None);
            }
        };

        // Calculate delta
        let delta = match self.snicker.calculate_delta_from_proposal(&decrypted) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("Failed to calculate delta for proposal {}: {}",
                         hex::encode(&tag), e);
                return Ok(None);
            }
        };

        // Check delta range
        if delta < delta_range.0 || delta > delta_range.1 {
            tracing::debug!("Proposal {} delta {} outside range ({}, {})",
                     hex::encode(&tag), delta, delta_range.0, delta_range.1);
            return Ok(None);
        }

        // Get proposal details using existing formatting method
        let (tag_hex, proposer_input, proposer_value, receiver_output_value, _delta) =
            self.format_proposal_info(&decrypted);

        // Build result
        let result = ProposalScanResult {
            tag,
            tag_hex,
            filename: hex::encode(&tag), // Use tag as filename for stream-received proposals
            delta,
            proposer_input,
            proposer_value,
            receiver_output_value,
        };

        tracing::info!("✅ Accepted incoming proposal {} (delta: {} sats)",
                 hex::encode(&tag), delta);

        Ok(Some(result))
    }

    /// Scan proposals and find all valid proposals matching criteria
    ///
    /// Automatically discovers proposals from the network, deserializes, decrypts with our UTXOs,
    /// and filters by delta range. This provides a foundation for automated SNICKER.
    ///
    /// # Arguments
    /// * `delta_range` - (min_delta, max_delta) acceptable range in sats
    ///
    /// # Returns
    /// Vec of ProposalScanResult containing all matching proposals with details
    pub async fn scan_proposals_directory(
        &mut self,
        delta_range: (i64, i64),
    ) -> Result<Vec<ProposalScanResult>> {
        tracing::debug!("🔍 Fetching proposals from network");

        // Fetch proposals from network
        let proposals = self.network.fetch_proposals(ProposalFilter::default()).await?;

        let mut encrypted_proposals = Vec::new();
        let mut skipped_count = 0;

        // Process each proposal: serialize, deserialize with load_proposal_from_serialized
        for encrypted_proposal in proposals.iter() {
            // Serialize the proposal to the format expected by load_proposal_from_serialized
            let serialized = format!(
                "{{\n  \"ephemeral_pubkey\": \"{}\",\n  \"tag\": \"{}\",\n  \"version\": {},\n  \"encrypted_data\": \"{}\"\n}}",
                encrypted_proposal.ephemeral_pubkey,
                hex::encode(&encrypted_proposal.tag),
                encrypted_proposal.version,
                hex::encode(&encrypted_proposal.encrypted_data)
            );

            match self.load_proposal_from_serialized(&serialized).await {
                Ok(tag) => {
                    // Successfully loaded encrypted proposal
                    let filename = hex::encode(&tag);
                    encrypted_proposals.push((tag, filename));
                }
                Err(e) => {
                    // Skip invalid proposals silently
                    skipped_count += 1;
                    if encrypted_proposals.len() < 10 {
                        tracing::debug!("Skipped proposal: {}", e);
                    }
                }
            }
        }

        tracing::debug!("📄 Found {} proposal(s), {} valid, {} skipped",
                 proposals.len(), encrypted_proposals.len(), skipped_count);

        if encrypted_proposals.is_empty() {
            return Ok(Vec::new());
        }

        tracing::debug!("🔓 Loaded {} proposal(s), checking which are decryptable...", encrypted_proposals.len());

        // Proposals are decrypted and stored by load_proposal_from_serialized
        // Query all decrypted proposals (will only contain those we could decrypt)
        let decrypted = self.snicker.get_decrypted_proposals_by_delta_range(
            i64::MIN,
            i64::MAX,
            "pending",
        ).await?;

        tracing::debug!("✅ Decrypted {} proposal(s) for our wallet", decrypted.len());

        // Filter by delta range and collect results
        let mut results = Vec::new();

        for proposal in decrypted {
            // Calculate delta
            let delta = match self.snicker.calculate_delta_from_proposal(&proposal) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("Failed to calculate delta for proposal {}: {}",
                             hex::encode(&proposal.tag), e);
                    continue;
                }
            };

            // Check if delta is in acceptable range
            if delta < delta_range.0 || delta > delta_range.1 {
                continue;
            }

            // Get proposal details using existing formatting method
            let (tag_hex, proposer_input, proposer_value, receiver_output_value, _delta) =
                self.format_proposal_info(&proposal);

            // Find original filename
            let filename = encrypted_proposals.iter()
                .find(|(tag, _)| tag == &proposal.tag)
                .map(|(_, name)| name.clone())
                .unwrap_or_else(|| hex::encode(&proposal.tag));

            results.push(ProposalScanResult {
                tag: proposal.tag,
                tag_hex,
                filename,
                delta,
                proposer_input,
                proposer_value,
                receiver_output_value,
            });
        }

        // Format delta range for display
        let range_str = if delta_range.0 == i64::MIN && delta_range.1 == i64::MAX {
            "all".to_string()
        } else {
            format!("{} to {}", delta_range.0, delta_range.1)
        };
        tracing::debug!("✅ Found {} matching proposal(s) in delta range: {}",
                 results.len(), range_str);

        Ok(results)
    }

    /// Accept and sign a SNICKER proposal as receiver
    ///
    /// # Arguments
    /// * `tag` - Unique identifier of the proposal to accept
    /// * `acceptable_delta_range` - Min and max delta we'll accept
    ///
    /// # Returns
    /// Fully-signed PSBT (both parties signed) ready for finalization
    pub async fn accept_snicker_proposal(
        &mut self,
        tag: &[u8; 8],
        acceptable_delta_range: (i64, i64),
    ) -> Result<Psbt> {
        // Get proposal from database
        let proposal = self.snicker.get_decrypted_proposal_by_tag(tag).await?
            .ok_or_else(|| anyhow::anyhow!("Proposal not found with tag: {}", hex::encode(tag)))?;

        // Get all our UTXOs (both regular wallet and SNICKER UTXOs)
        let our_utxos = self.wallet_node.get_all_wallet_utxos().await?;

        // Pre-derive private keys for all UTXOs (needed for SNICKER receive)
        use std::collections::HashMap;
        let mut utxo_keys = HashMap::new();
        for utxo in &our_utxos {
            let key = self.wallet_node.derive_utxo_privkey(utxo).await?;
            utxo_keys.insert(utxo.outpoint(), key);
        }

        // Validate and get PSBT from Snicker (already has proposer's signature)
        let mut psbt = self.snicker.receive(
            proposal,
            &our_utxos,
            acceptable_delta_range,
            |utxo| {
                utxo_keys
                    .get(&utxo.outpoint())
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("Missing key for UTXO"))
            },
        )?;

        // Sign with wallet (adds receiver's signature)
        self.wallet_node.sign_psbt(&mut psbt).await?;

        // Update status in database
        self.snicker.update_proposal_status(tag, "accepted").await?;

        // Return fully-signed PSBT (caller can finalize and broadcast)
        Ok(psbt)
    }

    /// Accept a SNICKER proposal and broadcast the transaction (complete workflow)
    ///
    /// This is the high-level method that interfaces should call. It handles:
    /// - Decrypting the proposal if needed (e.g., loaded from file)
    /// - Accepting and signing the proposal
    /// - Finalizing the PSBT
    /// - Storing the resulting SNICKER UTXO
    /// - Broadcasting the transaction
    pub async fn accept_and_broadcast_snicker_proposal(
        &mut self,
        tag: &[u8; 8],
        acceptable_delta_range: (i64, i64),
    ) -> Result<bdk_wallet::bitcoin::Txid> {
        println!("🔍 Step 1: Looking for proposal...");

        // Get decrypted proposal from database
        // Note: Proposals are decrypted at storage time, so they should already be in the database
        let proposal = self.snicker.get_decrypted_proposal_by_tag(tag).await?
            .ok_or_else(|| anyhow::anyhow!(
                "Proposal with tag {} not found. Load it first with 'load_proposal <file>'",
                hex::encode(tag)
            ))?;

        println!("✅ Found proposal");

        println!("🔍 Step 2: Validating proposer UTXO...");
        // Extract proposer's input from PSBT (first input is proposer's)
        let proposer_input = proposal.psbt.unsigned_tx.input.first()
            .ok_or_else(|| anyhow::anyhow!("Proposal PSBT has no inputs"))?;
        let proposer_outpoint = proposer_input.previous_output;

        // Get proposer's UTXO value from PSBT input
        let proposer_value = proposal.psbt.inputs.first()
            .and_then(|input| input.witness_utxo.as_ref())
            .map(|utxo| utxo.value.to_sat())
            .ok_or_else(|| anyhow::anyhow!("Cannot determine proposer UTXO value from PSBT"))?;

        // Validate the proposer's UTXO using our partial UTXO set
        match self.wallet_node.validate_proposer_utxo(&proposer_outpoint, proposer_value).await {
            Ok(()) => {
                println!("✅ Proposer UTXO validated: {}:{} ({} sats)",
                    proposer_outpoint.txid, proposer_outpoint.vout, proposer_value);
                tracing::info!(
                    "✅ Validated proposer UTXO {}:{} via partial UTXO set",
                    proposer_outpoint.txid, proposer_outpoint.vout
                );
            }
            Err(e) => {
                println!("❌ Proposer UTXO validation failed: {}", e);
                tracing::warn!(
                    "❌ Rejected proposal {} - proposer UTXO validation failed: {}",
                    hex::encode(tag), e
                );
                return Err(anyhow::anyhow!(
                    "Proposer UTXO validation failed: {}. This proposal may use a fake, spent, or very old UTXO.",
                    e
                ));
            }
        }

        println!("🔍 Step 3: Getting UTXOs...");
        let our_utxos = self.wallet_node.get_all_wallet_utxos().await?;

        println!("🔍 Step 4: Accepting and signing proposal...");
        // Accept and sign the proposal
        let psbt = self.accept_snicker_proposal(tag, acceptable_delta_range).await?;

        println!("🔍 Step 5: Finalizing PSBT...");
        // Finalize the PSBT
        let tx = self.finalize_psbt(psbt).await?;

        println!("🔍 Step 6: Storing SNICKER UTXO...");
        // Store the SNICKER UTXO for future spending
        self.store_accepted_snicker_utxo(&proposal, &tx, &our_utxos).await?;
        println!("📋 SNICKER UTXO tracked (will be detected during sync)");

        println!("🔍 Step 7: Broadcasting transaction...");
        // Broadcast the transaction
        let txid = self.broadcast_transaction(tx.clone()).await?;

        println!("🔍 Step 8: Marking pending SNICKER UTXO...");
        // Mark the input SNICKER UTXO as pending (broadcast but not confirmed)
        // Spend detection happens via block scanning (see wallet_node::background_sync)
        for input in &tx.input {
            if let Some(utxo) = our_utxos.iter().find(|u| u.outpoint() == input.previous_output) {
                if matches!(utxo, crate::wallet_node::WalletUtxo::Snicker { .. }) {
                    self.wallet_node.mark_snicker_utxo_pending(
                        &input.previous_output.txid.to_string(),
                        input.previous_output.vout,
                        &txid.to_string(),
                    ).await?;
                    println!("✅ Marked SNICKER input {}:{} as pending",
                        input.previous_output.txid, input.previous_output.vout);
                }
            }
        }

        Ok(txid)
    }

    /// Broadcast a transaction to the network
    pub async fn broadcast_transaction(&mut self, tx: Transaction) -> Result<bdk_wallet::bitcoin::Txid> {
        self.wallet_node.broadcast_transaction(tx).await
    }

    /// Query SNICKER candidates from partial_utxo_set
    ///
    /// # Arguments
    /// * `min_amount` - Minimum UTXO amount in satoshis
    /// * `max_amount` - Maximum UTXO amount in satoshis
    /// * `max_block_age` - Maximum age in blocks from tip (0 = all blocks)
    /// * `snicker_only` - Only return UTXOs from SNICKER v1 transactions
    ///
    /// # Returns
    /// Vec of (txid, vout, block_height, amount, script_pubkey) tuples for unspent P2TR UTXOs
    pub async fn get_snicker_candidates(
        &self,
        min_amount: u64,
        max_amount: u64,
        max_block_age: u32,
        snicker_only: bool,
    ) -> Result<Vec<(bdk_wallet::bitcoin::Txid, u32, u32, u64, bdk_wallet::bitcoin::ScriptBuf)>> {
        // Get current blockchain height for query range
        let tip_height = {
            let wallet = self.wallet_node.wallet.lock().await;
            wallet.local_chain().tip().height()
        };

        // Calculate start height based on max_block_age
        let start_height = if max_block_age == 0 {
            0  // Show all blocks
        } else {
            tip_height.saturating_sub(max_block_age)
        };

        // Query partial_utxo_set for unspent P2TR UTXOs in the specified range
        let partial_utxo_set = self.wallet_node.partial_utxo_set.lock().await;

        let transaction_type_filter = if snicker_only { Some("v1") } else { None };
        let utxos = partial_utxo_set.query_range(
            start_height,
            tip_height,
            min_amount,
            max_amount,
            transaction_type_filter,
        )?;

        // Convert PartialUtxo to tuple format expected by find_opportunities
        let candidates: Vec<_> = utxos.iter()
            .map(|utxo| (utxo.txid, utxo.vout, utxo.block_height, utxo.amount, utxo.script_pubkey.clone()))
            .collect();

        tracing::info!("Found {} candidate UTXOs from partial_utxo_set ({}-{} sats, snicker_only={})",
            candidates.len(), min_amount, max_amount, snicker_only);

        Ok(candidates)
    }

    // NOTE: This function has been removed in the refactor to UTXO-based candidates.
    // Candidates are now individual UTXOs (not full transactions), so pattern filtering
    // based on transaction structure is no longer applicable.

    /// Get a decrypted proposal by tag
    pub async fn get_decrypted_proposal_by_tag(&self, tag: &[u8; 8]) -> Result<Option<crate::snicker::Proposal>> {
        self.snicker.get_decrypted_proposal_by_tag(tag).await
    }

    // Removed: clear_snicker_candidates
    // Candidates are now queried from partial_utxo_set on-demand, not stored separately

    /// Clear all SNICKER proposals from database
    pub async fn clear_snicker_proposals(&self) -> Result<usize> {
        self.snicker.clear_snicker_proposals().await
    }

    /// Get SNICKER balance (sum of unspent SNICKER UTXOs)
    pub async fn get_snicker_balance(&self) -> Result<u64> {
        self.snicker.get_snicker_balance().await
    }

    /// List all unspent SNICKER UTXOs
    pub async fn list_snicker_utxos(&self) -> Result<Vec<crate::snicker::SnickerUtxo>> {
        self.snicker.list_snicker_utxos().await
    }

    /// Store a SNICKER UTXO after accepting a proposal and broadcasting
    ///
    /// This should be called after broadcasting a SNICKER coinjoin transaction.
    /// The receiver's tweaked output is always at index 0.
    pub async fn store_accepted_snicker_utxo(
        &self,
        proposal: &crate::snicker::Proposal,
        tx: &Transaction,
        our_utxos: &[crate::wallet_node::WalletUtxo],
    ) -> Result<()> {
        // Find our UTXO that matches the original output
        let our_utxo = our_utxos.iter()
            .find(|utxo| utxo.script_pubkey() == &proposal.tweak_info.original_output.script_pubkey)
            .ok_or_else(|| anyhow::anyhow!("Original output not found in our wallet"))?;

        // Derive our private key using unified method
        let receiver_seckey = self.wallet_node.derive_utxo_privkey(our_utxo).await?;

        // Calculate the SNICKER shared secret
        let snicker_shared_secret = crate::snicker::tweak::calculate_dh_shared_secret(
            &receiver_seckey,
            &proposal.tweak_info.proposer_pubkey
        );

        // Calculate the tweaked private key (for spending the SNICKER output)
        let tweaked_privkey = crate::snicker::tweak::derive_tweaked_seckey(
            &receiver_seckey,
            &snicker_shared_secret
        )?;

        // Find the receiver's tweaked output by matching script_pubkey from proposal
        // Outputs are randomized, so we can't hardcode index 0
        let tweaked_script = &proposal.tweak_info.tweaked_output.script_pubkey;
        let (output_index, tweaked_output) = tx.output.iter().enumerate()
            .find(|(_, output)| &output.script_pubkey == tweaked_script)
            .ok_or_else(|| anyhow::anyhow!("Receiver's tweaked output not found in transaction"))?;
        let txid = tx.compute_txid();

        // NOTE: SNICKER UTXOs are NOT tracked via Kyoto subscriptions.
        // Instead, they are detected and marked as spent via block scanning in background_sync.
        // The block scanner checks every input in every transaction against our SNICKER UTXO database.
        // This architectural separation means:
        // - BDK/Kyoto: Handles regular descriptor-based wallet UTXOs
        // - Block scanning: Handles SNICKER UTXO tracking independently

        // Store in database (spend detection will happen via block scanning)
        self.snicker.store_snicker_utxo(
            txid,
            output_index as u32,
            tweaked_output.value.to_sat(),
            &tweaked_output.script_pubkey,
            &tweaked_privkey,
            &snicker_shared_secret,
            None, // block_height unknown at broadcast time
        ).await?;

        Ok(())
    }

    // ============================================================
    // ADDITIONAL WALLET OPERATIONS (delegated to WalletNode)
    // ============================================================

    /// Configure RPC client for Bitcoin Core access
    pub fn set_rpc_client(&mut self, url: &str, auth: (String, String)) -> Result<()> {
        self.wallet_node.set_rpc_client(url, auth)
    }


    /// Peek at next N addresses without registering them
    pub async fn peek_addresses(&self, count: u32) -> Result<Vec<String>> {
        self.wallet_node.peek_addresses(count).await
    }

    /// Re-register revealed addresses with Kyoto
    pub async fn reregister_revealed(&mut self) -> Result<String> {
        self.wallet_node.reregister_revealed().await
    }

    /// Reveal addresses up to a specific index
    pub async fn reveal_up_to(&mut self, index: u32) -> Result<String> {
        self.wallet_node.reveal_up_to(index).await
    }

    /// Get debug information about transactions
    pub async fn debug_transactions(&self) -> Result<String> {
        self.wallet_node.debug_transactions().await
    }

    /// Get block information by hash (for testing/debugging)
    /// Returns: (version, prev_blockhash, num_txs, num_p2tr_outputs)
    pub async fn get_block_info(&self, block_hash: bdk_wallet::bitcoin::BlockHash) -> Result<(bdk_wallet::bitcoin::block::Version, bdk_wallet::bitcoin::BlockHash, usize, usize)> {
        use bdk_wallet::bitcoin::ScriptBuf;

        let indexed_block = self.wallet_node.requester.get_block(block_hash).await
            .map_err(|e| anyhow::anyhow!("Failed to fetch block: {:?}", e))?;

        let block = &indexed_block.block;

        // Count P2TR outputs
        let mut p2tr_count = 0;
        for tx in &block.txdata {
            for output in &tx.output {
                if output.script_pubkey.is_p2tr() {
                    p2tr_count += 1;
                }
            }
        }

        Ok((block.header.version, block.header.prev_blockhash, block.txdata.len(), p2tr_count))
    }

    /// Get block hashes from headers database (for testing/debugging)
    pub async fn get_block_hashes_from_headers_db(&self, start_height: u32, end_height: u32) -> Result<Vec<(u32, bdk_wallet::bitcoin::BlockHash)>> {
        self.wallet_node.get_block_hashes_from_headers_db(start_height, end_height).await
    }

    // ============================================================
    // PROPOSAL FORMATTING (presentation helpers for UIs)
    // ============================================================

    /// Format proposal information for display
    /// Returns: (tag_hex, proposer_input, proposer_value_sats, receiver_output_sats, delta_sats)
    pub fn format_proposal_info(&self, proposal: &Proposal) -> (String, String, u64, u64, i64) {
        let tag_hex = hex::encode(&proposal.tag);

        let tx = &proposal.psbt.unsigned_tx;
        let proposer_input = tx.input.first()
            .map(|inp| format!("{}:{}", inp.previous_output.txid, inp.previous_output.vout))
            .unwrap_or_else(|| "unknown".to_string());

        let proposer_value = proposal.psbt.inputs.first()
            .and_then(|inp| inp.witness_utxo.as_ref())
            .map(|txout| txout.value.to_sat())
            .unwrap_or(0);

        let receiver_input = proposal.tweak_info.original_output.value.to_sat();
        let tweaked_script = &proposal.tweak_info.tweaked_output.script_pubkey;
        let receiver_output = tx.output.iter()
            .find(|output| &output.script_pubkey == tweaked_script)
            .map(|output| output.value.to_sat())
            .unwrap_or(receiver_input);

        let delta = receiver_input as i64 - receiver_output as i64;

        (tag_hex, proposer_input, proposer_value, receiver_output, delta)
    }

    /// Parse hex tag to bytes
    pub fn parse_hex_tag(tag_hex: &str) -> Result<[u8; 8]> {
        let tag_bytes = hex::decode(tag_hex)
            .map_err(|_| anyhow::anyhow!("Invalid hex tag"))?;

        if tag_bytes.len() != 8 {
            anyhow::bail!("Tag must be exactly 8 bytes (16 hex chars)");
        }

        let mut tag = [0u8; 8];
        tag.copy_from_slice(&tag_bytes);
        Ok(tag)
    }

    // ============================================================
    // AUTOMATION METHODS
    // ============================================================

    /// Automatically accept proposals based on configuration
    ///
    /// Scans proposals directory, filters by delta, checks rate limits,
    /// and auto-accepts proposals that meet criteria.
    ///
    /// **Important**: Only accepts ONE proposal per UTXO per cycle to avoid
    /// double-spend attempts. Other proposals for the same UTXO remain pending
    /// and can be tried in future cycles if the first one fails to confirm.
    ///
    /// Returns number of proposals accepted.
    pub async fn auto_accept_proposals(&mut self, config: &crate::config::SnickerAutomation) -> Result<u32> {
        use crate::config::AutomationMode;
        use std::collections::HashMap;

        // Check if automation is enabled
        if config.mode == AutomationMode::Disabled {
            return Ok(0);
        }

        // Check rate limit
        if !self.snicker.check_rate_limit("auto_accept", config.max_proposals_per_day).await? {
            tracing::info!("⏸️  Rate limit reached for auto-accept (max {} per day)", config.max_proposals_per_day);
            return Ok(0);
        }

        // Scan for proposals in range
        let delta_range = (-config.max_delta, config.max_delta);
        let proposals = self.scan_for_our_proposals(delta_range).await?;

        if proposals.is_empty() {
            tracing::debug!("No proposals found within delta range");
            return Ok(0);
        }

        tracing::info!("🔍 Found {} proposals in database within delta range", proposals.len());

        // Group proposals by the UTXO they consume
        // Key: our UTXO outpoint string, Value: Vec of proposals using that UTXO
        let mut proposals_by_utxo: HashMap<String, Vec<crate::snicker::Proposal>> = HashMap::new();
        let mut stale_proposals = 0;

        // Get all our UTXOs including SNICKER UTXOs (once, outside the loop)
        let our_utxos = self.get_all_unspent_outpoints().await?;
        tracing::debug!("Wallet has {} unspent UTXOs (including SNICKER)", our_utxos.len());
        for (txid, vout, amount, is_snicker) in &our_utxos {
            let marker = if *is_snicker { " [SNICKER]" } else { "" };
            tracing::debug!("  UTXO: {}:{} ({} sats){}", txid, vout, amount, marker);
        }

        for proposal in proposals {
            // Identify which of our UTXOs this proposal consumes
            // by checking which input in the PSBT matches our wallet
            let mut our_utxo_str = None;
            for input in &proposal.psbt.unsigned_tx.input {
                let input_txid = input.previous_output.txid.to_string();
                let input_vout = input.previous_output.vout;
                let outpoint_str = format!("{}:{}", input_txid, input_vout);

                tracing::debug!("Checking if proposal input {} matches our UTXOs", outpoint_str);

                // Check if this input is one of our UTXOs (including SNICKER)
                if our_utxos.iter().any(|(txid, vout, _, _)| {
                    txid == &input_txid && *vout == input_vout
                }) {
                    our_utxo_str = Some(outpoint_str.clone());
                    tracing::debug!("✅ Matched UTXO: {}", outpoint_str);
                    break;
                } else {
                    tracing::debug!("❌ No match for input: {}", outpoint_str);
                }
            }

            if let Some(utxo_str) = our_utxo_str {
                proposals_by_utxo.entry(utxo_str).or_insert_with(Vec::new).push(proposal);
            } else {
                stale_proposals += 1;
            }
        }

        if stale_proposals > 0 {
            tracing::info!("⚠️  Filtered out {} stale proposals (UTXOs no longer in wallet)", stale_proposals);
        }

        tracing::info!("📊 Proposals grouped by UTXO: {} unique UTXOs have proposals", proposals_by_utxo.len());

        if proposals_by_utxo.is_empty() {
            tracing::info!("💤 No actionable proposals (all proposals are stale)");
            return Ok(0);
        }

        // For each UTXO, select ONE proposal to try this cycle
        // Strategy: Pick the first one (by order returned from DB)
        // Future enhancement: Could pick by best delta, random, or other criteria
        let mut selected_proposals = Vec::new();
        for (utxo_str, mut utxo_proposals) in proposals_by_utxo {
            let count = utxo_proposals.len();
            if let Some(selected) = utxo_proposals.pop() {
                tracing::info!("  UTXO {}: Selected 1 of {} proposals", utxo_str, count);
                selected_proposals.push(selected);
            }
        }

        let mut accepted_count = 0;

        for proposal in selected_proposals {
            // Check rate limit before each acceptance
            if !self.snicker.check_rate_limit("auto_accept", config.max_proposals_per_day).await? {
                tracing::info!("⏸️  Rate limit reached during auto-accept, stopping");
                break;
            }

            // Calculate delta for logging
            let delta = self.snicker.calculate_delta_from_proposal(&proposal).ok();

            // Accept and broadcast the proposal
            match self.accept_and_broadcast_snicker_proposal(&proposal.tag, delta_range).await {
                Ok(txid) => {
                    accepted_count += 1;
                    tracing::info!("✅ Auto-accepted proposal {} → txid: {}", hex::encode(proposal.tag), txid);

                    // Mark proposal as broadcast to avoid re-processing
                    self.snicker.update_proposal_status(&proposal.tag, "broadcast").await?;

                    // Log success
                    self.snicker.log_automation_action(
                        "auto_accept",
                        Some(&proposal.tag),
                        Some(&txid),
                        delta,
                        true,
                    ).await?;
                }
                Err(e) => {
                    tracing::warn!("❌ Failed to auto-accept proposal {}: {}", hex::encode(proposal.tag), e);

                    // Log failure
                    self.snicker.log_automation_action(
                        "auto_accept",
                        Some(&proposal.tag),
                        None,
                        delta,
                        false,
                    ).await?;
                }
            }
        }

        Ok(accepted_count)
    }

    /// Automatically create proposals based on configuration
    ///
    /// Scans for candidates, finds opportunities, checks rate limits,
    /// and auto-creates proposals.
    ///
    /// Returns number of proposals created.
    pub async fn auto_create_proposals(
        &mut self,
        config: &crate::config::SnickerAutomation,
        min_utxo_sats: u64,
        delta_sats: i64,
    ) -> Result<u32> {
        use crate::config::AutomationMode;

        // Check if proposer mode is enabled
        if config.mode != AutomationMode::Advanced {
            return Ok(0);
        }

        // Check rate limit
        if !self.snicker.check_rate_limit("auto_create", config.max_proposals_per_day).await? {
            tracing::info!("⏸️  Rate limit reached for auto-create (max {} per day)", config.max_proposals_per_day);
            return Ok(0);
        }

        // Find opportunities (candidates are queried from partial_utxo_set)
        // Use wide range for candidates (min_utxo_sats to u64::MAX)
        // Use all blocks (0) and don't filter to SNICKER-only for automation (maximize opportunities)
        let opportunities = self.find_snicker_opportunities(min_utxo_sats, u64::MAX, 0, false).await?;

        if opportunities.is_empty() {
            tracing::debug!("No opportunities found");
            return Ok(0);
        }

        tracing::info!("💡 Found {} opportunities", opportunities.len());

        let mut created_count = 0;

        for opportunity in opportunities {
            // Check rate limit before each creation
            if !self.snicker.check_rate_limit("auto_create", config.max_proposals_per_day).await? {
                tracing::info!("⏸️  Rate limit reached during auto-create, stopping");
                break;
            }

            // Check if we already created a proposal for this UTXO pair
            let our_utxo_str = format!("{}:{}", opportunity.our_outpoint.txid, opportunity.our_outpoint.vout);
            let target_utxo_str = format!("{}:{}", opportunity.target_outpoint.txid, opportunity.target_outpoint.vout);

            if let Some(existing) = self.snicker.get_proposal_for_utxo_pair(
                &our_utxo_str,
                &target_utxo_str,
                "proposer",
            ).await? {
                tracing::debug!("Already created proposal {} for UTXO pair ({} -> {}), skipping",
                    hex::encode(&existing.tag), our_utxo_str, target_utxo_str);
                continue;
            }

            // Create proposal
            match self.create_snicker_proposal(&opportunity, delta_sats, config.min_change_output_size).await {
                Ok((proposal, encrypted_proposal)) => {
                    created_count += 1;
                    let tag_hex = hex::encode(proposal.tag);
                    tracing::info!("✅ Auto-created proposal {}", tag_hex);

                    // Publish to network
                    if let Err(e) = self.network.publish_proposal(&encrypted_proposal).await {
                        tracing::warn!("Failed to publish proposal: {}", e);
                        continue;
                    }

                    // Log success
                    self.snicker.log_automation_action(
                        "auto_create",
                        Some(&proposal.tag),
                        None,
                        Some(delta_sats),
                        true,
                    ).await?;
                }
                Err(e) => {
                    tracing::warn!("❌ Failed to auto-create proposal: {}", e);

                    // Log failure
                    self.snicker.log_automation_action(
                        "auto_create",
                        None,
                        None,
                        Some(delta_sats),
                        false,
                    ).await?;
                }
            }
        }

        Ok(created_count)
    }
}
