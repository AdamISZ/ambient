//! Application Manager
//!
//! Coordinates between WalletNode (blockchain/wallet operations) and Snicker (protocol operations).
//! Provides high-level business logic operations that the UI layer can call.

use anyhow::Result;
use bdk_wallet::bitcoin::{Transaction, psbt::Psbt};

use crate::wallet_node::WalletNode;
use crate::snicker::{Snicker, ProposalOpportunity, EncryptedProposal, Proposal};

/// High-level application manager that coordinates wallet and SNICKER operations
pub struct Manager {
    pub wallet_node: WalletNode,
    pub snicker: Snicker,
}

impl Manager {
    /// Create a new Manager by loading an existing wallet and initializing SNICKER
    ///
    /// # Arguments
    /// * `wallet_name` - Name of the wallet to load
    /// * `network_str` - Network ("regtest", "signet", "mainnet")
    /// * `recovery_height` - Height to start blockchain recovery from
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

        let project_dirs = ProjectDirs::from("org", "code", "rustsnicker")
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

    /// Print wallet summary
    pub async fn print_summary(&self) {
        self.wallet_node.print_summary().await
    }

    // ============================================================
    // SNICKER OPERATIONS (coordinate between WalletNode and Snicker)
    // ============================================================

    /// Scan recent blocks for SNICKER candidate transactions
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
        // Create filter function using SNICKER's logic
        let filter = |tx: &Transaction| {
            crate::snicker::is_snicker_candidate(tx, size_min, size_max)
        };

        // Scan blockchain using WalletNode's generic scanner
        let candidates = self.wallet_node.scan_for_transactions(num_blocks, filter).await?;

        // Store candidates in SNICKER database
        for (block_height, tx) in &candidates {
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
    /// Tuple of (unsigned PSBT for proposer to sign, encrypted proposal to publish)
    pub async fn create_snicker_proposal(
        &self,
        opportunity: &ProposalOpportunity,
        delta_sats: i64,
    ) -> Result<(Psbt, EncryptedProposal)> {
        // Get our UTXO details and addresses from wallet
        let mut wallet = self.wallet_node.wallet.lock().await;
        let mut conn = self.wallet_node.conn.lock().await;

        let our_utxo = wallet.list_unspent()
            .find(|utxo| utxo.outpoint == opportunity.our_outpoint)
            .ok_or_else(|| anyhow::anyhow!("UTXO not found in wallet"))?;

        // Get addresses for outputs
        let equal_output_addr = wallet.reveal_next_address(bdk_wallet::KeychainKind::External).address;
        let change_output_addr = wallet.reveal_next_address(bdk_wallet::KeychainKind::Internal).address;

        // Persist updated derivation indices
        wallet.persist(&mut conn)?;

        drop(wallet);
        drop(conn);

        // Get fee rate from wallet
        let fee_rate = self.wallet_node.get_fee_rate();

        // Create proposal using Snicker
        let (psbt, encrypted_proposal) = self.snicker.propose(
            opportunity.target_tx.clone(),
            opportunity.target_output_index,
            our_utxo.outpoint,
            our_utxo.txout.clone(),
            equal_output_addr,
            change_output_addr,
            delta_sats,
            fee_rate,
        )?;

        Ok((psbt, encrypted_proposal))
    }

    /// Sign a SNICKER proposal PSBT and finalize it
    ///
    /// # Arguments
    /// * `psbt` - The unsigned PSBT from create_snicker_proposal
    ///
    /// # Returns
    /// The finalized transaction ready for broadcast
    pub async fn sign_and_finalize_proposal(&mut self, mut psbt: Psbt) -> Result<Transaction> {
        // Sign with wallet
        let finalized = self.wallet_node.sign_psbt(&mut psbt).await?;

        if !finalized {
            return Err(anyhow::anyhow!("PSBT not fully signed"));
        }

        // Finalize
        let tx = self.wallet_node.finalize_psbt(psbt).await?;

        Ok(tx)
    }

    /// Store an encrypted SNICKER proposal (for publishing/sharing)
    pub async fn store_snicker_proposal(&self, proposal: &EncryptedProposal) -> Result<()> {
        self.snicker.store_snicker_proposal(proposal).await
    }

    /// Scan for SNICKER proposals meant for our wallet
    ///
    /// Checks all stored proposals and attempts to decrypt those meant for our UTXOs.
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

        // Scan proposals using Snicker
        let all_proposals = self.snicker.scan_proposals(&our_utxos, derive_privkey).await?;

        // Filter to only proposals within acceptable delta range
        let mut valid_proposals = Vec::new();
        for proposal in all_proposals {
            // Validate the proposal (this checks delta among other things)
            match self.snicker.receive(
                proposal.clone(),
                &our_utxos,
                acceptable_delta_range,
                |keychain, index| self.wallet_node.derive_utxo_privkey(keychain, index),
            ) {
                Ok(_) => valid_proposals.push(proposal),
                Err(e) => {
                    tracing::info!("Rejected proposal: {}", e);
                }
            }
        }

        Ok(valid_proposals)
    }

    /// Accept and sign a SNICKER proposal as receiver
    ///
    /// # Arguments
    /// * `proposal` - The proposal to accept
    /// * `acceptable_delta_range` - Min and max delta we'll accept
    ///
    /// # Returns
    /// Signed transaction ready for broadcast
    pub async fn accept_snicker_proposal(
        &mut self,
        proposal: Proposal,
        acceptable_delta_range: (i64, i64),
    ) -> Result<Transaction> {
        // Get our UTXOs from wallet
        let wallet = self.wallet_node.wallet.lock().await;
        let our_utxos: Vec<_> = wallet.list_unspent().collect();
        drop(wallet);

        // Validate and get unsigned PSBT from Snicker
        let mut psbt = self.snicker.receive(
            proposal,
            &our_utxos,
            acceptable_delta_range,
            |keychain, index| self.wallet_node.derive_utxo_privkey(keychain, index),
        )?;

        // Sign with wallet
        let finalized = self.wallet_node.sign_psbt(&mut psbt).await?;

        if !finalized {
            return Err(anyhow::anyhow!("PSBT not fully signed after receiver signature"));
        }

        // Finalize
        let tx = self.wallet_node.finalize_psbt(psbt).await?;

        Ok(tx)
    }

    /// Broadcast a transaction to the network
    pub async fn broadcast_transaction(&mut self, tx: Transaction) -> Result<bdk_wallet::bitcoin::Txid> {
        self.wallet_node.broadcast_transaction(tx).await
    }

    /// Get all stored SNICKER candidates
    pub async fn get_snicker_candidates(&self) -> Result<Vec<(u32, bdk_wallet::bitcoin::Txid, Transaction)>> {
        self.snicker.get_snicker_candidates().await
    }

    /// Clear all SNICKER candidates from database
    pub async fn clear_snicker_candidates(&self) -> Result<usize> {
        self.snicker.clear_snicker_candidates().await
    }

    /// Clear all SNICKER proposals from database
    pub async fn clear_snicker_proposals(&self) -> Result<usize> {
        self.snicker.clear_snicker_proposals().await
    }
}
