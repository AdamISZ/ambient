//! Application Manager
//!
//! Coordinates between WalletNode (blockchain/wallet operations) and Snicker (protocol operations).
//! Provides high-level business logic operations that the UI layer can call.

use anyhow::{Result, Context};
use bdk_wallet::bitcoin::{Transaction, psbt::Psbt};
use tracing::info;

use crate::wallet_node::WalletNode;
use crate::snicker::{Snicker, ProposalOpportunity, EncryptedProposal, Proposal};
use std::path::Path;

/// High-level application manager that coordinates wallet and SNICKER operations
pub struct Manager {
    pub wallet_node: WalletNode,
    pub snicker: Snicker,
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
    /// # TODO
    /// Add wallet file locking to prevent multiple instances from opening the same wallet.
    /// This would avoid SQLite "database is locked" errors and potential double-spending issues.
    /// Consider using a lockfile (e.g., .wallet.lock) or flock() on the wallet database.
    pub async fn load(
        wallet_name: &str,
        network_str: &str,
        recovery_height: u32,
    ) -> Result<Self> {
        // Load wallet and start node
        let wallet_node = WalletNode::load(wallet_name, network_str, recovery_height).await?;

        // Initialize SNICKER with its own database
        let snicker = Self::init_snicker(wallet_name, network_str, wallet_node.network)?;

        Ok(Self {
            wallet_node,
            snicker,
        })
    }

    /// Generate a new wallet and initialize SNICKER
    pub async fn generate(
        wallet_name: &str,
        network_str: &str,
        recovery_height: u32,
    ) -> Result<(Self, bdk_wallet::keys::bip39::Mnemonic)> {
        // Generate new wallet
        let (wallet_node, mnemonic) = WalletNode::generate(wallet_name, network_str, recovery_height).await?;

        // Initialize SNICKER
        let snicker = Self::init_snicker(wallet_name, network_str, wallet_node.network)?;

        Ok((Self {
            wallet_node,
            snicker,
        }, mnemonic))
    }

    /// Initialize SNICKER database for a given wallet
    fn init_snicker(
        wallet_name: &str,
        network_str: &str,
        network: bdk_wallet::bitcoin::Network,
    ) -> Result<Snicker> {
        use directories::ProjectDirs;

        let project_dirs = ProjectDirs::from("org", "code", "ambient")
            .ok_or_else(|| anyhow::anyhow!("Cannot determine project dir"))?;

        let snicker_db_path = project_dirs
            .data_local_dir()
            .join(network_str)
            .join(wallet_name)
            .join("snicker.sqlite");

        std::fs::create_dir_all(snicker_db_path.parent().unwrap())?;

        Snicker::new(&snicker_db_path, network)
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

    /// Send to address (simple interface)
    pub async fn send_to_address(
        &mut self,
        address_str: &str,
        amount_sats: u64,
        fee_rate_sat_vb: f32,
    ) -> Result<bdk_wallet::bitcoin::Txid> {
        self.wallet_node.send_to_address(address_str, amount_sats, fee_rate_sat_vb).await
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
    /// Actively pulls updates from Kyoto and applies them to the wallet until
    /// it reaches the target height, or times out.
    ///
    /// # Arguments
    /// * `target_height` - Minimum height to wait for
    /// * `timeout_secs` - Maximum seconds to wait (default 30)
    pub async fn wait_for_height(&self, target_height: u32, timeout_secs: u64) -> Result<u32> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);

        loop {
            // Check if we've reached the expected height
            {
                let wallet = self.wallet_node.wallet.lock().await;
                let current_height = wallet.local_chain().tip().height();
                if current_height >= target_height {
                    tracing::info!("✅ Synced to height {}", current_height);
                    return Ok(current_height);
                }
            }

            // Try to get next update with timeout
            let mut sub = self.wallet_node.update_subscriber.lock().await;
            let update_result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                sub.update()
            ).await;
            drop(sub);

            match update_result {
                Ok(Ok(update)) => {
                    let mut wallet = self.wallet_node.wallet.lock().await;
                    let mut conn = self.wallet_node.conn.lock().await;

                    wallet.apply_update(update)?;
                    wallet.persist(&mut conn)?;

                    let height = wallet.local_chain().tip().height();
                    tracing::info!("Sync update: height {} / {}", height, target_height);
                }
                Ok(Err(e)) => return Err(anyhow::anyhow!("Sync error: {}", e)),
                Err(_) => {
                    // Timeout on this update - check if we've exceeded total timeout
                    if start.elapsed() > timeout {
                        let wallet = self.wallet_node.wallet.lock().await;
                        let current_height = wallet.local_chain().tip().height();
                        return Err(anyhow::anyhow!(
                            "Sync timeout: only reached height {} (expected >= {})",
                            current_height, target_height
                        ));
                    }
                    // Otherwise continue waiting
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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
    pub async fn scan_for_snicker_candidates(
        &self,
        num_blocks: u32,
        size_min: u64,
        size_max: u64,
    ) -> Result<usize> {
        // Scan blockchain using RPC to find taproot UTXOs in the size range
        let candidates = self.wallet_node.scan_blocks_for_taproot_utxos(
            num_blocks,
            size_min,
            size_max
        ).await?;

        // Store candidates in SNICKER database
        for (block_height, _txid, tx) in &candidates {
            self.snicker.store_candidate(*block_height, tx).await?;
        }

        Ok(candidates.len())
    }

    /// Find SNICKER proposal opportunities for our wallet
    ///
    /// # Arguments
    /// * `min_utxo_sats` - Minimum size of our UTXO to consider
    ///
    /// # Returns
    /// List of opportunities sorted by value
    pub async fn find_snicker_opportunities(
        &self,
        min_utxo_sats: u64,
    ) -> Result<Vec<ProposalOpportunity>> {
        // Get our UTXOs from wallet
        let wallet = self.wallet_node.wallet.lock().await;
        let our_utxos: Vec<_> = wallet.list_unspent().collect();
        drop(wallet);

        // Find opportunities using Snicker
        self.snicker.find_opportunities(&our_utxos, min_utxo_sats).await
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
    ) -> Result<(Proposal, EncryptedProposal)> {
        // Get our UTXO details and addresses from wallet
        let mut wallet = self.wallet_node.wallet.lock().await;
        let mut conn = self.wallet_node.conn.lock().await;

        let our_utxo = wallet.list_unspent()
            .find(|utxo| utxo.outpoint == opportunity.our_outpoint)
            .ok_or_else(|| anyhow::anyhow!("UTXO not found in wallet"))?;

        // Derive the proposer's input private key (for SNICKER tweak)
        let our_keychain = our_utxo.keychain;
        let our_derivation_index = our_utxo.derivation_index;

        // Get addresses for outputs
        let equal_output_addr = wallet.reveal_next_address(bdk_wallet::KeychainKind::External).address;
        let change_output_addr = wallet.reveal_next_address(bdk_wallet::KeychainKind::Internal).address;

        // Persist updated derivation indices
        wallet.persist(&mut conn)?;

        drop(wallet);
        drop(conn);

        // Derive our input private key (the proposer's input key used for SNICKER tweak)
        let our_input_privkey = self.wallet_node.derive_utxo_privkey(our_keychain, our_derivation_index)?;

        // Get fee rate from wallet
        let fee_rate = self.wallet_node.get_fee_rate();

        // Create signing callback that signs the proposer's input
        // Use block_in_place to allow blocking operations in async context
        let wallet_clone = self.wallet_node.wallet.clone();
        let sign_callback = move |psbt: &mut Psbt| -> Result<()> {
            use bdk_wallet::KeychainKind;

            let wallet = tokio::task::block_in_place(|| {
                wallet_clone.blocking_lock()
            });

            tracing::info!("🔨 Proposer signing PSBT with {} inputs", psbt.inputs.len());

            // Get wallet descriptor for comparison
            let ext_descriptor = wallet.public_descriptor(KeychainKind::External);
            let int_descriptor = wallet.public_descriptor(KeychainKind::Internal);
            tracing::info!("🔨 Wallet External descriptor: {}", ext_descriptor);
            tracing::info!("🔨 Wallet Internal descriptor: {}", int_descriptor);

            // Log PSBT state before signing
            for (i, input) in psbt.inputs.iter().enumerate() {
                tracing::info!("🔨 Input {} BEFORE proposer sign:", i);
                tracing::info!("    - witness_utxo: {}", input.witness_utxo.is_some());
                tracing::info!("    - tap_internal_key: {:?}", input.tap_internal_key);
                tracing::info!("    - tap_key_sig: {:?}", input.tap_key_sig);
                tracing::info!("    - tap_key_origins: {}", input.tap_key_origins.len());

                if let Some(ref witness_utxo) = input.witness_utxo {
                    tracing::info!("    - script_pubkey: {}", witness_utxo.script_pubkey);
                    let is_mine = wallet.is_mine(witness_utxo.script_pubkey.clone());
                    tracing::info!("    - Wallet recognizes as mine: {}", is_mine);

                    // Check if wallet has a UTXO with matching script_pubkey
                    let matching_utxo = wallet.list_unspent()
                        .find(|u| u.txout.script_pubkey == witness_utxo.script_pubkey);
                    tracing::info!("    - Wallet has UTXO with matching script: {}", matching_utxo.is_some());
                    if let Some(utxo) = matching_utxo {
                        tracing::info!("      UTXO: {:?}, keychain: {:?}, index: {}",
                            utxo.outpoint, utxo.keychain, utxo.derivation_index);
                    }
                }
            }

            // CRITICAL: Check if wallet can derive the exact address for our UTXO
            tracing::info!("🔑 Checking if wallet can derive UTXO addresses...");

            // For each PSBT input, check if wallet can derive its address
            for (i, input) in psbt.inputs.iter().enumerate() {
                if let Some(ref witness_utxo) = input.witness_utxo {
                    let script = &witness_utxo.script_pubkey;
                    tracing::info!("🔑 Input {} script: {}", i, script);

                    // Check if wallet has a matching UTXO and get its derivation info
                    if let Some(utxo) = wallet.list_unspent()
                        .find(|u| &u.txout.script_pubkey == script)
                    {
                        tracing::info!("🔑 Input {} is in wallet: {:?}/{}", i, utxo.keychain, utxo.derivation_index);

                        // Manually derive the address at this index
                        let derived_addr = wallet.peek_address(utxo.keychain, utxo.derivation_index);
                        tracing::info!("🔑 Wallet derives at {:?}/{}: {}",
                            utxo.keychain, utxo.derivation_index, derived_addr.address);
                        tracing::info!("🔑 Derived script: {}", derived_addr.address.script_pubkey());
                        tracing::info!("🔑 Scripts match: {}", derived_addr.address.script_pubkey() == *script);
                    }
                }
            }

            // CRITICAL: Manually update PSBT with descriptor since automatic update isn't working
            use bdk_wallet::miniscript::psbt::PsbtInputExt;

            for input_idx in 0..psbt.inputs.len() {
                if let Some(ref witness_utxo) = psbt.inputs[input_idx].witness_utxo {
                    // Find matching UTXO in wallet
                    if let Some(utxo) = wallet.list_unspent()
                        .find(|u| u.txout.script_pubkey == witness_utxo.script_pubkey)
                    {
                        tracing::info!("🔧 Manually updating PSBT input {} with descriptor at {:?}/{}",
                            input_idx, utxo.keychain, utxo.derivation_index);

                        // Get descriptor and derive to the specific index
                        let descriptor = wallet.public_descriptor(utxo.keychain);
                        let derived_desc = descriptor.at_derivation_index(utxo.derivation_index)
                            .expect("valid derivation index");

                        // Use miniscript's PsbtInputExt trait to update the input
                        let input = &mut psbt.inputs[input_idx];
                        if let Err(e) = input.update_with_descriptor_unchecked(&derived_desc) {
                            tracing::error!("❌ Failed to update input {}: {:?}", input_idx, e);
                        } else {
                            tracing::info!("✅ Updated input {} - tap_internal_key: {:?}, tap_key_origins: {}",
                                input_idx, input.tap_internal_key, input.tap_key_origins.len());
                        }
                    }
                }
            }

            // Check PSBT state RIGHT BEFORE calling wallet.sign()
            tracing::info!("🔨 PSBT state BEFORE wallet.sign():");
            for (i, input) in psbt.inputs.iter().enumerate() {
                tracing::info!("  Input {}: tap_internal_key={:?}, tap_key_origins={}",
                    i, input.tap_internal_key.is_some(), input.tap_key_origins.len());
            }

            let sign_options = bdk_wallet::SignOptions {
                trust_witness_utxo: true,
                try_finalize: false,  // Don't finalize - SNICKER requires partial signing!
                ..Default::default()
            };

            let finalized = wallet.sign(psbt, sign_options)?;

            // Check PSBT state RIGHT AFTER calling wallet.sign()
            tracing::info!("🔨 PSBT state AFTER wallet.sign():");
            for (i, input) in psbt.inputs.iter().enumerate() {
                tracing::info!("  Input {}: tap_internal_key={:?}, tap_key_origins={}",
                    i, input.tap_internal_key.is_some(), input.tap_key_origins.len());
            }
            tracing::info!("🔨 Proposer sign result - finalized: {}", finalized);

            // Log PSBT state after signing
            for (i, input) in psbt.inputs.iter().enumerate() {
                tracing::info!("🔨 Input {} AFTER proposer sign:", i);
                tracing::info!("    - tap_internal_key: {:?}", input.tap_internal_key);
                tracing::info!("    - tap_key_sig: {:?}", input.tap_key_sig);
                tracing::info!("    - tap_key_origins: {}", input.tap_key_origins.len());

                // Log detailed tap_key_origins data to understand why signing fails
                for (pubkey, (leaf_hashes, (fingerprint, derivation_path))) in &input.tap_key_origins {
                    tracing::info!("      * pubkey: {}", pubkey);
                    tracing::info!("        fingerprint: {}", fingerprint);
                    tracing::info!("        derivation_path: {}", derivation_path);
                    tracing::info!("        leaf_hashes: {} entries", leaf_hashes.len());
                }

                if input.tap_key_sig.is_none() {
                    tracing::warn!("    ⚠️  No signature added!");
                }
            }

            Ok(())
        };

        // Create proposal using Snicker (will sign via callback)
        let (proposal, encrypted_proposal) = self.snicker.propose(
            opportunity.target_tx.clone(),
            opportunity.target_output_index,
            our_utxo.outpoint,
            our_utxo.txout.clone(),
            our_input_privkey,  // Proposer's input key for SNICKER tweak (enables recovery)
            equal_output_addr,
            change_output_addr,
            delta_sats,
            fee_rate,
            sign_callback,
        )?;

        // Store encrypted proposal for sharing
        self.snicker.store_snicker_proposal(&encrypted_proposal).await?;

        // Store decrypted proposal in our database (proposer side)
        let our_utxo_str = format!("{}:{}", opportunity.our_outpoint.txid, opportunity.our_outpoint.vout);
        let target_utxo_str = self.snicker.extract_receiver_utxo(
            &proposal,
            &opportunity.target_tx,
            opportunity.target_output_index
        )?;

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
    pub async fn store_snicker_proposal(&self, proposal: &EncryptedProposal) -> Result<()> {
        self.snicker.store_snicker_proposal(proposal).await
    }

    /// Serialize an encrypted proposal to a string format (for file storage/network sharing)
    pub fn serialize_encrypted_proposal(&self, proposal: &EncryptedProposal) -> String {
        format!(
            "{{\n  \"ephemeral_pubkey\": \"{}\",\n  \"tag\": \"{}\",\n  \"encrypted_data\": \"{}\"\n}}",
            proposal.ephemeral_pubkey,
            ::hex::encode(&proposal.tag),
            ::hex::encode(&proposal.encrypted_data)
        )
    }

    /// Deserialize and store a proposal from its serialized form
    /// Returns the proposal tag
    pub async fn load_proposal_from_serialized(&self, serialized: &str) -> Result<[u8; 8]> {
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

        let proposal = EncryptedProposal {
            ephemeral_pubkey: pubkey,
            tag,
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
    pub async fn scan_for_our_proposals(
        &self,
        acceptable_delta_range: (i64, i64),
    ) -> Result<Vec<Proposal>> {
        // Get our UTXOs from wallet
        let wallet = self.wallet_node.wallet.lock().await;
        let our_utxos: Vec<_> = wallet.list_unspent().collect();
        drop(wallet);

        // Create callback for deriving private keys
        let derive_privkey = |keychain, index| {
            self.wallet_node.derive_utxo_privkey(keychain, index)
        };

        // Scan proposals using Snicker (decrypts all proposals meant for our UTXOs)
        let all_proposals = self.snicker.scan_proposals(&our_utxos, derive_privkey).await?;

        tracing::info!("💾 Storing {} decrypted proposals in cache...", all_proposals.len());

        // Store each successfully decrypted proposal in the database
        for proposal in &all_proposals {
            tracing::info!("Processing proposal with tag {}", hex::encode(&proposal.tag));

            // Calculate delta using a wide range to get the actual value
            match self.snicker.calculate_delta_from_proposal(proposal) {
                Ok(delta) => {
                    tracing::info!("  Calculated delta: {} sats", delta);

                    // Identify which input is ours by checking against our UTXOs
                    let mut our_utxo_str = None;
                    let mut proposer_utxo_str = None;

                    for (idx, input) in proposal.psbt.unsigned_tx.input.iter().enumerate() {
                        let outpoint_str = format!("{}:{}", input.previous_output.txid, input.previous_output.vout);

                        // Check if this input matches any of our UTXOs
                        let is_ours = our_utxos.iter().any(|utxo| {
                            utxo.outpoint.txid == input.previous_output.txid
                                && utxo.outpoint.vout == input.previous_output.vout
                        });

                        if is_ours {
                            our_utxo_str = Some(outpoint_str);
                            tracing::info!("  Our UTXO (input {}): {}", idx, our_utxo_str.as_ref().unwrap());
                        } else {
                            proposer_utxo_str = Some(outpoint_str);
                            tracing::info!("  Proposer UTXO (input {}): {}", idx, proposer_utxo_str.as_ref().unwrap());
                        }
                    }

                    let our_utxo = match our_utxo_str {
                        Some(u) => u,
                        None => {
                            tracing::warn!("Could not identify our UTXO in proposal inputs");
                            continue;
                        }
                    };

                    let proposer_utxo = match proposer_utxo_str {
                        Some(u) => u,
                        None => {
                            tracing::warn!("Could not identify proposer UTXO in proposal inputs");
                            continue;
                        }
                    };

                    // Store in database with role="receiver" and status="pending"
                    match self.snicker.store_decrypted_proposal(
                        proposal,
                        "receiver",
                        &our_utxo,
                        &proposer_utxo,
                        delta,
                    ).await {
                        Ok(_) => tracing::info!("  ✅ Stored in decrypted_proposals table"),
                        Err(e) => tracing::warn!("  ❌ Failed to cache proposal {}: {}", hex::encode(&proposal.tag), e),
                    }
                }
                Err(e) => {
                    tracing::warn!("Could not calculate delta for proposal: {}", e);
                }
            }
        }

        // Now query from database with delta filter
        tracing::info!("🔍 Querying decrypted_proposals table with delta range {} to {} and status='pending'",
                      acceptable_delta_range.0, acceptable_delta_range.1);
        let results = self.snicker.get_decrypted_proposals_by_delta_range(
            acceptable_delta_range.0,
            acceptable_delta_range.1,
            "pending"
        ).await?;
        tracing::info!("📊 Query returned {} proposals", results.len());
        Ok(results)
    }

    /// Scan proposals directory and find all valid proposals matching criteria
    ///
    /// Automatically discovers proposal files, deserializes, decrypts with our UTXOs,
    /// and filters by delta range. This provides a foundation for automated SNICKER.
    ///
    /// # Arguments
    /// * `proposals_dir` - Directory containing proposal files
    /// * `delta_range` - (min_delta, max_delta) acceptable range in sats
    ///
    /// # Returns
    /// Vec of ProposalScanResult containing all matching proposals with details
    pub async fn scan_proposals_directory(
        &mut self,
        proposals_dir: &Path,
        delta_range: (i64, i64),
    ) -> Result<Vec<ProposalScanResult>> {
        use std::fs;

        // Create directory if it doesn't exist
        if !proposals_dir.exists() {
            fs::create_dir_all(proposals_dir)?;
            println!("📁 Created proposals directory: {}", proposals_dir.display());
            return Ok(Vec::new());
        }

        println!("🔍 Scanning proposals directory: {}", proposals_dir.display());

        // Read all files in directory
        let entries = fs::read_dir(proposals_dir)
            .with_context(|| format!("Failed to read proposals directory: {}", proposals_dir.display()))?;

        let mut encrypted_proposals = Vec::new();
        let mut file_count = 0;
        let mut skipped_count = 0;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("⚠️  Failed to read directory entry: {}", e);
                    continue;
                }
            };

            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            file_count += 1;

            // Limit to prevent scanning too many files
            if file_count > 1000 {
                eprintln!("⚠️  Directory has >1000 files, limiting scan to first 1000");
                break;
            }

            // Try to read and deserialize file
            match fs::read_to_string(&path) {
                Ok(contents) => {
                    match self.load_proposal_from_serialized(&contents).await {
                        Ok(tag) => {
                            // Successfully loaded encrypted proposal
                            let filename = path.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("unknown")
                                .to_string();
                            encrypted_proposals.push((tag, filename));
                        }
                        Err(e) => {
                            // Skip invalid files silently (might not be proposal files)
                            skipped_count += 1;
                            if file_count < 10 { // Only log first few to avoid spam
                                eprintln!("⚠️  Skipped {}: {}", path.display(), e);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  Failed to read {}: {}", path.display(), e);
                    skipped_count += 1;
                }
            }
        }

        println!("📄 Found {} files, {} valid proposal(s), {} skipped",
                 file_count, encrypted_proposals.len(), skipped_count);

        if encrypted_proposals.is_empty() {
            return Ok(Vec::new());
        }

        // Get our UTXOs for decryption
        let wallet = self.wallet_node.wallet.lock().await;
        let our_utxos: Vec<_> = wallet.list_unspent().collect();
        drop(wallet);

        println!("🔓 Attempting to decrypt {} proposal(s) with {} UTXO(s)...",
                 encrypted_proposals.len(), our_utxos.len());

        // Decrypt all proposals
        let decrypted = self.snicker.scan_proposals(&our_utxos, |keychain, index| {
            self.wallet_node.derive_utxo_privkey(keychain, index)
        }).await?;

        println!("✅ Decrypted {} proposal(s)", decrypted.len());

        // Filter by delta range and collect results
        let mut results = Vec::new();

        for proposal in decrypted {
            // Calculate delta
            let delta = match self.snicker.calculate_delta_from_proposal(&proposal) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("⚠️  Failed to calculate delta for proposal {}: {}",
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

        println!("✅ Found {} matching proposal(s) in delta range ({}, {})",
                 results.len(), delta_range.0, delta_range.1);

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

        // Get our UTXOs from wallet
        let wallet = self.wallet_node.wallet.lock().await;
        let our_utxos: Vec<_> = wallet.list_unspent().collect();
        drop(wallet);

        // Validate and get PSBT from Snicker (already has proposer's signature)
        let mut psbt = self.snicker.receive(
            proposal,
            &our_utxos,
            acceptable_delta_range,
            |keychain, index| self.wallet_node.derive_utxo_privkey(keychain, index),
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
        println!("🔍 Step 1: Looking for decrypted proposal...");

        // Try to get decrypted proposal first
        let proposal = match self.snicker.get_decrypted_proposal_by_tag(tag).await? {
            Some(p) => {
                println!("✅ Found cached decrypted proposal");
                p
            },
            None => {
                // Not decrypted yet (e.g., just loaded from file)
                // Try to decrypt it now with our UTXOs
                println!("🔓 Proposal not decrypted yet, attempting to decrypt...");

                let wallet = self.wallet_node.wallet.lock().await;
                let our_utxos: Vec<_> = wallet.list_unspent().collect();
                drop(wallet);

                println!("🔍 Scanning {} UTXOs to decrypt proposal...", our_utxos.len());

                // Try to decrypt this specific proposal
                let proposals = self.snicker.scan_proposals(&our_utxos, |keychain, index| {
                    self.wallet_node.derive_utxo_privkey(keychain, index)
                }).await?;

                println!("🔍 Decrypted {} proposal(s), looking for matching tag...", proposals.len());

                // Find the one with matching tag
                let proposal = proposals.into_iter()
                    .find(|p| &p.tag == tag)
                    .ok_or_else(|| anyhow::anyhow!("Could not decrypt proposal with tag: {} (not meant for our UTXOs)", hex::encode(tag)))?;

                println!("✅ Successfully decrypted proposal");

                // Cache it for future use
                if let Ok(delta) = self.snicker.calculate_delta_from_proposal(&proposal) {
                    let wallet = self.wallet_node.wallet.lock().await;
                    let our_utxos: Vec<_> = wallet.list_unspent().collect();
                    drop(wallet);

                    let our_utxo_str = proposal.psbt.unsigned_tx.input.get(1)
                        .map(|i| format!("{}:{}", i.previous_output.txid, i.previous_output.vout))
                        .unwrap_or_else(|| "unknown".to_string());
                    let proposer_utxo_str = proposal.psbt.unsigned_tx.input.get(0)
                        .map(|i| format!("{}:{}", i.previous_output.txid, i.previous_output.vout))
                        .unwrap_or_else(|| "unknown".to_string());

                    let _ = self.snicker.store_decrypted_proposal(&proposal, "receiver", &our_utxo_str, &proposer_utxo_str, delta).await;
                }

                proposal
            }
        };

        println!("🔍 Step 2: Getting UTXOs...");
        let wallet = self.wallet_node.wallet.lock().await;
        let our_utxos: Vec<_> = wallet.list_unspent().collect();
        drop(wallet);

        println!("🔍 Step 3: Accepting and signing proposal...");
        // Accept and sign the proposal
        let psbt = self.accept_snicker_proposal(tag, acceptable_delta_range).await?;

        println!("🔍 Step 4: Finalizing PSBT...");
        // Finalize the PSBT
        let tx = self.finalize_psbt(psbt).await?;

        println!("🔍 Step 5: Storing SNICKER UTXO...");
        // Store the SNICKER UTXO for future spending
        self.store_accepted_snicker_utxo(&proposal, &tx, &our_utxos).await?;
        println!("📋 SNICKER UTXO tracked (will be detected during sync)");

        println!("🔍 Step 6: Broadcasting transaction...");
        // Broadcast the transaction
        let txid = self.broadcast_transaction(tx).await?;

        Ok(txid)
    }

    /// Broadcast a transaction to the network
    pub async fn broadcast_transaction(&mut self, tx: Transaction) -> Result<bdk_wallet::bitcoin::Txid> {
        self.wallet_node.broadcast_transaction(tx).await
    }

    /// Get all stored SNICKER candidates
    pub async fn get_snicker_candidates(&self) -> Result<Vec<(u32, bdk_wallet::bitcoin::Txid, Transaction)>> {
        self.snicker.get_snicker_candidates().await
    }

    /// Get a decrypted proposal by tag
    pub async fn get_decrypted_proposal_by_tag(&self, tag: &[u8; 8]) -> Result<Option<crate::snicker::Proposal>> {
        self.snicker.get_decrypted_proposal_by_tag(tag).await
    }

    /// Clear all SNICKER candidates from database
    pub async fn clear_snicker_candidates(&self) -> Result<usize> {
        self.snicker.clear_snicker_candidates().await
    }

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
        our_utxos: &[bdk_wallet::LocalOutput],
    ) -> Result<()> {
        // Find our UTXO to get keychain and derivation index
        let our_utxo = our_utxos.iter()
            .find(|utxo| utxo.txout.script_pubkey == proposal.tweak_info.original_output.script_pubkey)
            .ok_or_else(|| anyhow::anyhow!("Original output not found in our wallet"))?;

        // Derive our private key
        let receiver_seckey = self.wallet_node.derive_utxo_privkey(
            our_utxo.keychain,
            our_utxo.derivation_index
        )?;

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

        // The receiver's tweaked output is always at index 0
        let output_index = 0;
        let tweaked_output = &tx.output[output_index];
        let txid = tx.compute_txid();

        // Add the tweaked scriptPubKey to Kyoto's watch list so it gets detected during sync
        {
            match self.wallet_node.update_subscriber.try_lock() {
                Ok(mut update_subscriber) => {
                    update_subscriber.add_script(tweaked_output.script_pubkey.clone());
                    println!("✅ Added SNICKER tweaked script to Kyoto watch list");
                }
                Err(_) => {
                    // Update subscriber is busy, but the UTXO will still be in the database
                    // and will be detected on next sync
                    println!("⚠️  Update subscriber busy, SNICKER UTXO will be detected on next sync");
                }
            }
        }

        // Store in database
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

    /// Sync recent blocks
    pub async fn sync_recent(&mut self) -> Result<()> {
        self.wallet_node.sync_recent().await
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
    pub fn get_block_hashes_from_headers_db(&self, start_height: u32, end_height: u32) -> Result<Vec<(u32, bdk_wallet::bitcoin::BlockHash)>> {
        self.wallet_node.get_block_hashes_from_headers_db(start_height, end_height)
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
}
