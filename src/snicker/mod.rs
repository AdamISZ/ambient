//! SNICKER (Simple Non-Interactive Coinjoin with Keys for Encryption Reused)
//!
//! This module implements both Proposer and Receiver functionality for SNICKER transactions.
//! A single `Snicker` struct provides methods for both roles, sharing common logic.
//!
//! # Example Usage
//!
//! ```no_run
//! use rustsnicker::snicker::Snicker;
//! use bdk_wallet::bitcoin::Transaction;
//!
//! # async fn example(wallet_node: &WalletNode) -> anyhow::Result<()> {
//! // Create a SNICKER instance
//! let snicker = Snicker::new(&wallet_node);
//!
//! // As a proposer: propose to co-spend output 0 of an existing transaction
//! let target_tx: Transaction = /* ... get from blockchain ... */;
//! let proposal = snicker.propose(target_tx, 0).await?;
//! // Send proposal to receiver...
//!
//! // As a receiver: validate and sign a received proposal
//! let received_proposal = /* ... receive from somewhere ... */;
//! match snicker.receive(received_proposal).await {
//!     Ok(signed_psbt) => {
//!         // Validation passed, PSBT is fully signed
//!         // Receiver can now choose to broadcast it
//!         // wallet_node.broadcast(signed_psbt)?;
//!     }
//!     Err(e) => {
//!         // Validation failed, ignore the proposal
//!         eprintln!("Rejected proposal: {}", e);
//!     }
//! }
//! # Ok(())
//! # }
//! ```

pub mod tweak;

use std::sync::Arc;

use anyhow::Result;
use bdk_wallet::{
    bitcoin::{Network, OutPoint, Transaction, TxOut, psbt::Psbt, secp256k1::PublicKey},
    rusqlite::Connection,
    PersistedWallet,
};
use serde::{Serialize, Deserialize};
use tokio::sync::Mutex;

use crate::wallet_node::WalletNode;

/// Information about a key tweak applied to create a SNICKER output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TweakInfo {
    /// The original output being tweaked (receiver's output)
    pub original_output: TxOut,
    /// The resulting tweaked output
    pub tweaked_output: TxOut,
    /// The proposer's public key (used to calculate DH shared secret)
    pub proposer_pubkey: PublicKey,
}

/// A SNICKER transaction proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    /// The partially signed Bitcoin transaction
    pub psbt: Psbt,
    /// Information about the tweak applied
    pub tweak_info: TweakInfo,
}

/// An encrypted SNICKER proposal with ephemeral key for routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedProposal {
    /// Ephemeral public key (not linked to any transaction input)
    pub ephemeral_pubkey: PublicKey,
    /// Tag for efficient matching (first 8 bytes of hash of shared secret)
    pub tag: [u8; 8],
    /// Encrypted Proposal data
    pub encrypted_data: Vec<u8>,
}


/// SNICKER functionality for a wallet
///
/// Provides both Proposer and Receiver operations on the same wallet.
pub struct Snicker {
    wallet: Arc<Mutex<PersistedWallet<Connection>>>,
    conn: Arc<Mutex<Connection>>,
    network: Network,
}

impl Snicker {
    /// Create a new SNICKER instance from a wallet node
    pub fn new(wallet_node: &WalletNode) -> Self {
        Self {
            wallet: Arc::clone(&wallet_node.wallet),
            conn: Arc::clone(&wallet_node.conn),
            network: wallet_node.network,
        }
    }

    // ============================================================
    // PUBLIC API - PROPOSER
    // ============================================================

    /// Propose a SNICKER transaction
    ///
    /// Takes an existing on-chain transaction and proposes to co-spend one of its outputs
    /// along with an output from our own wallet.
    ///
    /// Creates an encrypted proposal using an ephemeral key for privacy.
    ///
    /// # Arguments
    /// * `target_tx` - The on-chain transaction containing the output to co-spend
    /// * `output_index` - Which output of the target transaction to co-spend
    ///
    /// # Returns
    /// An `EncryptedProposal` ready to be shared/broadcast
    pub async fn propose(
        &self,
        target_tx: Transaction,
        output_index: usize,
    ) -> Result<EncryptedProposal> {
        use bdk_wallet::bitcoin::secp256k1::{rand, Secp256k1, SecretKey};

        // 1. Select a coin from our wallet
        let _our_input = self.select_coin().await?;

        // 2. Create the tweaked output
        let target_output = &target_tx.output.get(output_index)
            .ok_or_else(|| anyhow::anyhow!("Output index out of bounds"))?;
        let (tweaked_output, proposer_pubkey) = self.create_tweaked_output(target_output)?;

        // 3. Build the PSBT
        let mut psbt = self.build_psbt(&target_tx, output_index, tweaked_output.clone()).await?;

        // 4. Sign our inputs
        self.sign_our_inputs(&mut psbt).await?;

        // 5. Create the proposal with real keys
        let tweak_info = TweakInfo {
            original_output: (*target_output).clone(),
            tweaked_output,
            proposer_pubkey,
        };
        let proposal = Proposal { psbt, tweak_info };

        // 6. Generate ephemeral keypair for encryption
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let ephemeral_seckey = SecretKey::new(&mut rng);
        let ephemeral_pubkey = ephemeral_seckey.public_key(&secp);

        // 7. Extract receiver's pubkey from target output
        let receiver_pubkey_xonly = tweak::extract_taproot_pubkey(target_output)?;
        // Convert x-only to full pubkey (assume even parity)
        let mut receiver_pubkey_bytes = [0u8; 33];
        receiver_pubkey_bytes[0] = 0x02;
        receiver_pubkey_bytes[1..].copy_from_slice(&receiver_pubkey_xonly);
        let receiver_pubkey = bdk_wallet::bitcoin::secp256k1::PublicKey::from_slice(
            &receiver_pubkey_bytes
        )?;

        // 8. Calculate shared secret using ephemeral key
        let shared_secret = tweak::calculate_dh_shared_secret(
            &ephemeral_seckey,
            &receiver_pubkey
        );

        // 9. Calculate tag
        let tag = tweak::compute_proposal_tag(&shared_secret);

        // 10. Serialize and encrypt the proposal
        let proposal_bytes = serde_json::to_vec(&proposal)?;
        let encrypted_data = tweak::encrypt_proposal(&proposal_bytes, &shared_secret)?;

        Ok(EncryptedProposal {
            ephemeral_pubkey,
            tag,
            encrypted_data,
        })
    }

    // ============================================================
    // PUBLIC API - RECEIVER
    // ============================================================

    /// Receive and validate a SNICKER proposal
    ///
    /// Validates the proposal, checks if we can sign it, verifies the tweak.
    /// If validation passes, signs the transaction and returns the fully signed PSBT
    /// ready for broadcast. If validation fails, returns an error.
    ///
    /// The receiver never communicates back to the proposer - they simply choose
    /// whether to broadcast the final transaction or not.
    ///
    /// # Arguments
    /// * `proposal` - The SNICKER proposal to evaluate
    ///
    /// # Returns
    /// The fully signed PSBT if accepted, or an error if rejected
    ///
    /// # Errors
    /// Returns an error if:
    /// - The proposal fails validation (amounts, structure, tweak)
    /// - We cannot sign our input (not our key)
    /// - The ruleset is violated
    pub async fn receive(&self, proposal: Proposal) -> Result<Psbt> {
        // TODO: Implement receiver logic
        // 1. Validate the proposal (returns Err if invalid)
        self.validate_proposal(&proposal).await?;

        // 2. Sign our inputs
        let mut psbt = proposal.psbt;
        self.sign_our_inputs(&mut psbt).await?;

        // 3. Return the signed PSBT for broadcast
        Ok(psbt)
    }

    // ============================================================
    // SHARED PRIVATE METHODS
    // ============================================================

    /// Build a PSBT for a SNICKER transaction
    async fn build_psbt(
        &self,
        _target_tx: &Transaction,
        _output_index: usize,
        _tweaked_output: TxOut,
    ) -> Result<Psbt> {
        // TODO: Implement PSBT construction
        // - Add input from target_tx
        // - Add input from our wallet
        // - Add tweaked output
        // - Add change output
        todo!("PSBT construction not yet implemented")
    }

    /// Sign the inputs that belong to our wallet
    async fn sign_our_inputs(&self, _psbt: &mut Psbt) -> Result<()> {
        // TODO: Implement signing
        // - Identify which inputs belong to us
        // - Sign those inputs using wallet.sign()
        todo!("Signing not yet implemented")
    }

    /// Create a tweaked output from an original output
    fn create_tweaked_output(&self, original: &TxOut) -> Result<(TxOut, PublicKey)> {
        // TODO: Implement tweak calculation using tweak module
        // 1. Get our (proposer's) secret key from wallet
        // 2. Extract receiver's public key from the original output
        // 3. Call tweak::create_tweaked_output(original, proposer_seckey, receiver_pubkey)
        // 4. Return (tweaked_output, proposer_pubkey)

        // Placeholder: return cloned output and dummy pubkey
        use bdk_wallet::bitcoin::secp256k1::Secp256k1;
        let secp = Secp256k1::new();
        let dummy_seckey = bdk_wallet::bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32])?;
        let dummy_pubkey = PublicKey::from_secret_key(&secp, &dummy_seckey);
        Ok((original.clone(), dummy_pubkey))
    }

    /// Select a coin from our wallet to use as input
    async fn select_coin(&self) -> Result<OutPoint> {
        // TODO: Implement coin selection
        // - Query wallet for available UTXOs
        // - Select appropriate coin based on amount/privacy considerations
        todo!("Coin selection not yet implemented")
    }

    /// Validate amounts in the PSBT
    async fn validate_amounts(&self, _psbt: &Psbt) -> Result<()> {
        // TODO: Implement amount validation
        // - Check that outputs don't exceed inputs
        // - Verify fee is reasonable
        // - Check that our output amounts are correct
        todo!("Amount validation not yet implemented")
    }

    /// Validate a received proposal
    async fn validate_proposal(&self, proposal: &Proposal) -> Result<()> {
        // TODO: Implement full validation
        // - Check PSBT structure
        // - Validate amounts
        // - Verify tweak is correct
        // - Check that we can sign our input
        // - Validate outputs follow ruleset
        self.validate_amounts(&proposal.psbt).await?;
        self.validate_tweak(&proposal.tweak_info)?;
        Ok(())
    }

    /// Validate that the tweak follows the correct rules
    fn validate_tweak(&self, tweak_info: &TweakInfo) -> Result<()> {
        // TODO: Implement tweak validation using tweak module
        // 1. Get our (receiver's) secret key from wallet
        // 2. Call tweak::verify_tweaked_output(
        //      &original_output,
        //      &tweaked_output,
        //      receiver_seckey,
        //      &proposer_pubkey
        //    )
        // 3. If verification succeeds, the tweak is valid
        //
        // For now, just verify the outputs are P2TR
        if !tweak_info.original_output.script_pubkey.is_p2tr() {
            return Err(anyhow::anyhow!("Original output is not P2TR"));
        }
        if !tweak_info.tweaked_output.script_pubkey.is_p2tr() {
            return Err(anyhow::anyhow!("Tweaked output is not P2TR"));
        }
        Ok(()) // Placeholder: basic validation for now
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snicker_struct_creation() {
        // Basic compile test - actual functionality tests will come later
        assert!(true);
    }
}
