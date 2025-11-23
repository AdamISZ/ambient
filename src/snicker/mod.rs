//! SNICKER (Simple Non-Interactive Coinjoin with Keys for Encryption Reused)
//!
//! This module implements both Proposer and Receiver functionality for SNICKER transactions.
//! A single `Snicker` struct provides methods for both roles, sharing common logic.
//!
//! # Example Usage
//!
//! ```no_run
//! use ambient::snicker::Snicker;
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

#[cfg(test)]
mod tweak_tests;

use std::sync::{Arc, Mutex};
use std::str::FromStr;

use anyhow::Result;
use bdk_wallet::{
    bitcoin::{Network, OutPoint, Transaction, TxOut, Txid, psbt::Psbt, secp256k1::PublicKey},
    rusqlite::Connection,
};
use serde::{Serialize, Deserialize};

// ============================================================
// SNICKER TRANSACTION FILTERS
// ============================================================

/// Check if a transaction is a potential SNICKER candidate
///
/// A transaction is a candidate if it has at least one P2TR output
/// within the specified size range.
///
/// # Arguments
/// * `tx` - The transaction to check
/// * `size_min` - Minimum output value in satoshis
/// * `size_max` - Maximum output value in satoshis
///
/// # Returns
/// `true` if the transaction has at least one qualifying P2TR output
pub fn is_snicker_candidate(tx: &Transaction, size_min: u64, size_max: u64) -> bool {
    tx.output.iter().any(|output| {
        let is_p2tr = output.script_pubkey.is_p2tr();
        let in_range = output.value.to_sat() >= size_min
                    && output.value.to_sat() <= size_max;
        is_p2tr && in_range
    })
}

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

/// A SNICKER UTXO stored in the database
#[derive(Debug, Clone)]
pub struct SnickerUtxo {
    /// The outpoint (txid:vout)
    pub outpoint: bdk_wallet::bitcoin::OutPoint,
    /// Amount in satoshis
    pub amount: u64,
    /// The tweaked script pubkey
    pub script_pubkey: bdk_wallet::bitcoin::ScriptBuf,
    /// The tweaked private key (for spending)
    pub tweaked_privkey: bdk_wallet::bitcoin::secp256k1::SecretKey,
    /// The SNICKER shared secret (for recovery verification)
    pub snicker_shared_secret: [u8; 32],
    /// Block height when confirmed (if known)
    pub block_height: Option<u32>,
}

/// SNICKER functionality
///
/// Provides both Proposer and Receiver operations.
/// Independent of wallet operations - data is passed in as parameters.
pub struct Snicker {
    conn: Arc<Mutex<Connection>>,
    network: Network,
}

impl Snicker {
    /// Create a new SNICKER instance
    ///
    /// # Arguments
    /// * `db_path` - Path to the SNICKER database file
    /// * `network` - Bitcoin network (mainnet, testnet, signet, regtest)
    pub fn new(db_path: &std::path::Path, network: Network) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        let conn = Arc::new(Mutex::new(conn));

        // Initialize database tables
        let mut conn_guard = conn.lock().unwrap();
        Self::init_candidates_table(&mut conn_guard)?;
        Self::init_proposals_table(&mut conn_guard)?;
        Self::init_snicker_utxos_table(&mut conn_guard)?;
        drop(conn_guard);

        Ok(Self {
            conn,
            network,
        })
    }

    // ============================================================
    // PUBLIC API - PROPOSER
    // ============================================================

    /// Propose a SNICKER transaction
    ///
    /// Takes an existing on-chain transaction and proposes to co-spend one of its outputs
    /// along with a specified output from the proposer's wallet.
    ///
    /// Creates an encrypted proposal using an ephemeral key for privacy.
    /// The proposer's input is signed before encryption, so the encrypted proposal
    /// contains a partially-signed PSBT.
    ///
    /// # Arguments
    /// * `target_tx` - The on-chain transaction containing the output to co-spend
    /// * `output_index` - Which output of the target transaction to co-spend
    /// * `proposer_outpoint` - Proposer's UTXO to use as input
    /// * `proposer_utxo_txout` - The full TxOut of proposer's UTXO (for witness_utxo)
    /// * `proposer_equal_output_addr` - Address for proposer's equal-sized output
    /// * `proposer_change_output_addr` - Address for proposer's change output
    /// * `delta_sats` - Fee adjustment (positive = receiver pays, 0 = proposer pays all, negative = proposer pays receiver)
    /// * `fee_rate` - Fee rate for the transaction
    /// * `sign_psbt` - Callback to sign the PSBT (should only sign proposer's input)
    ///
    /// # Returns
    /// Tuple of (partially-signed PSBT, encrypted proposal with signed PSBT)
    pub fn propose<F>(
        &self,
        target_tx: Transaction,
        output_index: usize,
        proposer_outpoint: OutPoint,
        proposer_utxo_txout: TxOut,
        proposer_input_seckey: bdk_wallet::bitcoin::secp256k1::SecretKey,
        proposer_equal_output_addr: bdk_wallet::bitcoin::Address,
        proposer_change_output_addr: bdk_wallet::bitcoin::Address,
        delta_sats: i64,
        fee_rate: bdk_wallet::bitcoin::FeeRate,
        sign_psbt: F,
    ) -> Result<(Psbt, EncryptedProposal)>
    where
        F: FnOnce(&mut Psbt) -> Result<()>,
    {
        use bdk_wallet::bitcoin::secp256k1::{rand, Secp256k1, SecretKey};

        // 1. Extract proposer's input public key from the UTXO being spent
        let secp = Secp256k1::new();
        let proposer_input_pubkey = proposer_input_seckey.public_key(&secp);

        // 2. Create the tweaked output using proposer's input key
        let target_output = &target_tx.output.get(output_index)
            .ok_or_else(|| anyhow::anyhow!("Output index out of bounds"))?;
        let (tweaked_output, snicker_shared_secret) = self.create_tweaked_output(
            target_output,
            &proposer_input_seckey,
        )?;

        // 2. Build the PSBT (unsigned)
        let mut psbt = self.build_psbt(
            &target_tx,
            output_index,
            tweaked_output.clone(),
            proposer_outpoint,
            proposer_utxo_txout.clone(),
            proposer_equal_output_addr,
            proposer_change_output_addr,
            delta_sats,
            fee_rate,
        )?;

        // 3. Sign the proposer's input (partial signature)
        sign_psbt(&mut psbt)?;

        // 4. Create the proposal with signed PSBT
        let tweak_info = TweakInfo {
            original_output: (*target_output).clone(),
            tweaked_output,
            proposer_pubkey: proposer_input_pubkey,
        };
        let proposal = Proposal {
            psbt: psbt.clone(),
            tweak_info
        };

        // 5. Generate ephemeral keypair for encryption (separate from SNICKER tweak)
        let mut rng = rand::thread_rng();
        let ephemeral_seckey = SecretKey::new(&mut rng);
        let ephemeral_pubkey = ephemeral_seckey.public_key(&secp);

        // 6. Extract receiver's pubkey from target output
        let receiver_pubkey_xonly = tweak::extract_taproot_pubkey(target_output)?;
        // Convert x-only to full pubkey (assume even parity)
        let mut receiver_pubkey_bytes = [0u8; 33];
        receiver_pubkey_bytes[0] = 0x02;
        receiver_pubkey_bytes[1..].copy_from_slice(&receiver_pubkey_xonly);
        let receiver_pubkey = bdk_wallet::bitcoin::secp256k1::PublicKey::from_slice(
            &receiver_pubkey_bytes
        )?;

        // 7. Calculate encryption shared secret using ephemeral key (for privacy)
        let encryption_shared_secret = tweak::calculate_dh_shared_secret(
            &ephemeral_seckey,
            &receiver_pubkey
        );

        // 8. Calculate tag from encryption shared secret (for efficient proposal matching)
        // Receiver tries each UTXO with ephemeral key to check tag before decrypting
        let tag = tweak::compute_proposal_tag(&encryption_shared_secret);

        // 9. Serialize and encrypt the proposal (contains partially-signed PSBT)
        // After decryption, receiver will extract proposer's input key from PSBT witness
        let proposal_bytes = serde_json::to_vec(&proposal)?;
        let encrypted_data = tweak::encrypt_proposal(&proposal_bytes, &encryption_shared_secret)?;

        let encrypted_proposal = EncryptedProposal {
            ephemeral_pubkey,
            tag,
            encrypted_data,
        };

        // Return both the partially-signed PSBT and the encrypted proposal (for sharing)
        Ok((psbt, encrypted_proposal))
    }

    // ============================================================
    // PUBLIC API - RECEIVER
    // ============================================================

    /// Receive and validate a SNICKER proposal
    ///
    /// Validates the proposal, checks amounts and tweak.
    /// Returns the unsigned PSBT if validation passes - caller should sign and broadcast.
    /// If validation fails, returns an error.
    ///
    /// The receiver never communicates back to the proposer - they simply choose
    /// whether to broadcast the final transaction or not.
    ///
    /// # Arguments
    /// * `proposal` - The SNICKER proposal to evaluate
    /// * `our_utxos` - Our wallet's UTXOs (for finding which input belongs to us)
    /// * `acceptable_delta_range` - (min_delta, max_delta) in satoshis defining acceptable fee contribution
    /// * `derive_privkey` - Function to derive private key given (keychain, derivation_index)
    ///
    /// # Returns
    /// The unsigned PSBT if accepted (caller should sign), or an error if rejected
    ///
    /// # Errors
    /// Returns an error if:
    /// - The proposal fails validation (amounts, structure, tweak)
    /// - The ruleset is violated
    pub fn receive<F>(
        &self,
        proposal: Proposal,
        our_utxos: &[bdk_wallet::LocalOutput],
        acceptable_delta_range: (i64, i64),
        derive_privkey: F,
    ) -> Result<Psbt>
    where
        F: Fn(bdk_wallet::KeychainKind, u32) -> Result<bdk_wallet::bitcoin::secp256k1::SecretKey>,
    {
        // 1. Validate the proposal (returns Err if invalid)
        self.validate_proposal(&proposal, our_utxos, acceptable_delta_range, &derive_privkey)?;

        // 2. Return the unsigned PSBT - caller will sign it
        Ok(proposal.psbt)
    }

    // ============================================================
    // SHARED PRIVATE METHODS
    // ============================================================

    /// Calculate outputs for "two equal outputs + proposer change" structure
    ///
    /// This is the default SNICKER proposal structure where:
    /// - Both parties get equal-sized outputs (for privacy)
    /// - Proposer gets one change output
    /// - Receiver gets no change (to avoid increasing their UTXO count)
    ///
    /// # Returns
    /// Tuple of (outputs_vector, total_fees)
    fn build_equal_outputs_structure(
        receiver_output: &TxOut,
        proposer_amount: bdk_wallet::bitcoin::Amount,
        delta_sats: i64,
        fee_rate: bdk_wallet::bitcoin::FeeRate,
        tweaked_output: TxOut,
        proposer_equal_addr: bdk_wallet::bitcoin::Address,
        proposer_change_addr: bdk_wallet::bitcoin::Address,
    ) -> Result<(Vec<TxOut>, bdk_wallet::bitcoin::Amount)> {
        use bdk_wallet::bitcoin::Amount;

        // Calculate equal output size
        let receiver_amount_sats = receiver_output.value.to_sat() as i64;
        let equal_output_sats = receiver_amount_sats - delta_sats;

        if equal_output_sats <= 546 {
            return Err(anyhow::anyhow!(
                "Equal output would be dust: {} sats (delta: {})",
                equal_output_sats, delta_sats
            ));
        }
        let equal_output_amount = Amount::from_sat(equal_output_sats as u64);

        // Estimate fees: 2 P2TR inputs + 3 P2TR outputs
        let estimated_vsize = 10 + (2 * 58) + (3 * 43); // ~205 vbytes
        let estimated_fee = fee_rate.fee_vb(estimated_vsize)
            .ok_or_else(|| anyhow::anyhow!("Fee calculation overflow"))?;

        // Calculate change
        let total_in = receiver_output.value + proposer_amount;
        let total_out_before_change = equal_output_amount + equal_output_amount;
        let change_amount = total_in - total_out_before_change - estimated_fee;

        if change_amount.to_sat() < 546 {
            return Err(anyhow::anyhow!(
                "Insufficient proposer funds: change would be dust ({} sats)",
                change_amount.to_sat()
            ));
        }

        // Build outputs vector
        let outputs = vec![
            // Equal output 1: to receiver (tweaked)
            TxOut {
                value: equal_output_amount,
                script_pubkey: tweaked_output.script_pubkey,
            },
            // Equal output 2: to proposer
            TxOut {
                value: equal_output_amount,
                script_pubkey: proposer_equal_addr.script_pubkey(),
            },
            // Change output: to proposer
            TxOut {
                value: change_amount,
                script_pubkey: proposer_change_addr.script_pubkey(),
            },
        ];

        Ok((outputs, estimated_fee))
    }

    /// Build a PSBT for a SNICKER transaction
    ///
    /// Constructs the transaction structure and creates a PSBT ready for signing.
    ///
    /// # Arguments
    /// * `target_tx` - Transaction containing receiver's UTXO
    /// * `output_index` - Index of receiver's output in target_tx
    /// * `tweaked_output` - Pre-created tweaked output for receiver
    /// * `proposer_outpoint` - Pre-selected proposer UTXO outpoint
    /// * `proposer_txout` - The full TxOut of proposer's UTXO
    /// * `proposer_equal_addr` - Address for proposer's equal output
    /// * `proposer_change_addr` - Address for proposer's change output
    /// * `delta_sats` - Fee adjustment (positive = receiver pays, negative = proposer incentivizes)
    /// * `fee_rate` - Fee rate for the transaction
    fn build_psbt(
        &self,
        target_tx: &Transaction,
        output_index: usize,
        tweaked_output: TxOut,
        proposer_outpoint: OutPoint,
        proposer_txout: TxOut,
        proposer_equal_addr: bdk_wallet::bitcoin::Address,
        proposer_change_addr: bdk_wallet::bitcoin::Address,
        delta_sats: i64,
        fee_rate: bdk_wallet::bitcoin::FeeRate,
    ) -> Result<Psbt> {
        use bdk_wallet::bitcoin::{Transaction as BdkTransaction, TxIn, Sequence, Witness};
        use bdk_wallet::bitcoin::transaction::Version;

        // Get receiver's original output
        let receiver_output = target_tx.output.get(output_index)
            .ok_or_else(|| anyhow::anyhow!("Output index out of bounds"))?;

        // Calculate outputs using the "equal outputs + change" structure
        let (outputs, _estimated_fee) = Self::build_equal_outputs_structure(
            receiver_output,
            proposer_txout.value,
            delta_sats,
            fee_rate,
            tweaked_output,
            proposer_equal_addr.clone(),
            proposer_change_addr.clone(),
        )?;

        // Build the transaction
        let receiver_outpoint = OutPoint {
            txid: target_tx.compute_txid(),
            vout: output_index as u32,
        };

        let tx = BdkTransaction {
            version: Version::TWO,
            lock_time: bdk_wallet::bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![
                // Receiver's input (to be signed by receiver)
                TxIn {
                    previous_output: receiver_outpoint,
                    script_sig: bdk_wallet::bitcoin::ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
                // Proposer's input (to be signed by us)
                TxIn {
                    previous_output: proposer_outpoint,
                    script_sig: bdk_wallet::bitcoin::ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
            ],
            output: outputs,
        };

        // Create PSBT from transaction
        let mut psbt = Psbt::from_unsigned_tx(tx)?;

        // Add witness_utxo for receiver's input
        psbt.inputs[0].witness_utxo = Some(receiver_output.clone());

        // Add witness_utxo for proposer's input
        psbt.inputs[1].witness_utxo = Some(proposer_txout);

        Ok(psbt)
    }

    /// Create a tweaked output from an original output using the proposer's input key
    ///
    /// This uses the proposer's INPUT private key (not ephemeral) for the SNICKER tweak,
    /// enabling wallet recovery from seed alone by scanning spent UTXOs.
    fn create_tweaked_output(
        &self,
        original: &TxOut,
        proposer_input_seckey: &bdk_wallet::bitcoin::secp256k1::SecretKey,
    ) -> Result<(TxOut, [u8; 32])> {
        // 1. Extract receiver's public key from the original output
        let receiver_pubkey_xonly = tweak::extract_taproot_pubkey(original)?;

        // Convert x-only to full pubkey (assume even parity)
        let mut receiver_pubkey_bytes = [0u8; 33];
        receiver_pubkey_bytes[0] = 0x02;
        receiver_pubkey_bytes[1..].copy_from_slice(&receiver_pubkey_xonly);
        let receiver_pubkey = PublicKey::from_slice(&receiver_pubkey_bytes)?;

        // 2. Create the tweaked output using proposer's INPUT key (for recoverability)
        let (tweaked_output, snicker_shared_secret) = tweak::create_tweaked_output(
            original,
            proposer_input_seckey,
            &receiver_pubkey
        )?;

        // 3. Return tweaked output and the SNICKER shared secret
        Ok((tweaked_output, snicker_shared_secret))
    }


    /// Validate amounts in the PSBT (from receiver's perspective)
    ///
    /// Checks that:
    /// 1. Exactly one input belongs to us (prevent malicious proposer from including multiple)
    /// 2. Exactly one output matches the tweaked output
    /// 3. Our output value = our input value - delta (where delta is acceptable)
    /// 4. The overall transaction fee rate is sufficient for confirmation
    ///
    /// # Arguments
    /// * `psbt` - The PSBT to validate
    /// * `tweak_info` - Tweak information for finding our output
    /// * `our_utxos` - Our wallet's UTXOs
    /// * `acceptable_delta_range` - (min_delta, max_delta) in satoshis. Negative means we receive payment.
    fn validate_amounts(
        &self,
        psbt: &Psbt,
        tweak_info: &TweakInfo,
        our_utxos: &[bdk_wallet::LocalOutput],
        acceptable_delta_range: (i64, i64),
    ) -> Result<()> {
        use bdk_wallet::bitcoin::Amount;

        // Find all inputs that belong to us
        let mut our_input_value = None;

        for (input_idx, input) in psbt.inputs.iter().enumerate() {
            let outpoint = psbt.unsigned_tx.input.get(input_idx)
                .ok_or_else(|| anyhow::anyhow!("PSBT input mismatch"))?
                .previous_output;

            // Check if this input belongs to us
            if our_utxos.iter().any(|utxo| utxo.outpoint == outpoint) {
                if our_input_value.is_some() {
                    return Err(anyhow::anyhow!(
                        "Multiple receiver inputs detected - rejecting malicious proposal"
                    ));
                }
                our_input_value = Some(
                    input.witness_utxo.as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Missing witness_utxo"))?
                        .value
                );
            }
        }

        let our_input_value = our_input_value
            .ok_or_else(|| anyhow::anyhow!("No receiver input found in PSBT"))?;

        // Find our output by matching against the tweaked output
        let mut our_output_value = None;
        for output in &psbt.unsigned_tx.output {
            if output.script_pubkey == tweak_info.tweaked_output.script_pubkey {
                if our_output_value.is_some() {
                    return Err(anyhow::anyhow!(
                        "Multiple outputs match tweaked output - rejecting malicious proposal"
                    ));
                }
                our_output_value = Some(output.value);
            }
        }

        let our_output_value = our_output_value
            .ok_or_else(|| anyhow::anyhow!("Tweaked output not found in PSBT"))?;

        // Calculate delta: how much we're paying/receiving
        let delta_sats = our_input_value.to_sat() as i64 - our_output_value.to_sat() as i64;

        // Validate delta is within acceptable range
        let (min_delta, max_delta) = acceptable_delta_range;
        if delta_sats < min_delta || delta_sats > max_delta {
            return Err(anyhow::anyhow!(
                "Unacceptable delta: {} sats (acceptable range: {} to {} sats)",
                delta_sats, min_delta, max_delta
            ));
        }

        // Calculate total fee
        let mut total_in = Amount::ZERO;
        for input in &psbt.inputs {
            if let Some(ref utxo) = input.witness_utxo {
                total_in += utxo.value;
            }
        }
        let mut total_out = Amount::ZERO;
        for output in &psbt.unsigned_tx.output {
            total_out += output.value;
        }
        let fee = total_in - total_out;

        // Estimate transaction size (2 P2TR inputs + 3 P2TR outputs)
        let estimated_vsize = 10 + (2 * 58) + (3 * 43); // ~205 vbytes

        // Calculate fee rate
        let fee_rate_sat_vb = fee.to_sat() / estimated_vsize;

        // Require at least 1 sat/vbyte (very conservative minimum)
        if fee_rate_sat_vb < 1 {
            return Err(anyhow::anyhow!(
                "Fee rate too low: {} sat/vb (fee {} sats, estimated size {} vbytes)",
                fee_rate_sat_vb, fee.to_sat(), estimated_vsize
            ));
        }

        Ok(())
    }

    /// Validate a received proposal
    fn validate_proposal<F>(
        &self,
        proposal: &Proposal,
        our_utxos: &[bdk_wallet::LocalOutput],
        acceptable_delta_range: (i64, i64),
        derive_privkey: &F,
    ) -> Result<()>
    where
        F: Fn(bdk_wallet::KeychainKind, u32) -> Result<bdk_wallet::bitcoin::secp256k1::SecretKey>,
    {
        // Validate inputs: all must be taproot, and verify proposer's input key
        self.validate_inputs(&proposal.psbt, &proposal.tweak_info, our_utxos)?;

        // Validate amounts (including finding our input/output correctly)
        self.validate_amounts(&proposal.psbt, &proposal.tweak_info, our_utxos, acceptable_delta_range)?;

        // Verify the tweak is correct
        self.validate_tweak(&proposal.tweak_info, our_utxos, derive_privkey)?;

        Ok(())
    }

    /// Validate that all inputs are taproot and verify proposer's input key
    fn validate_inputs(
        &self,
        psbt: &Psbt,
        tweak_info: &TweakInfo,
        our_utxos: &[bdk_wallet::LocalOutput],
    ) -> Result<()> {
        // Find our input to identify which input is the proposer's
        let our_input_idx = psbt.unsigned_tx.input.iter().position(|input| {
            our_utxos.iter().any(|utxo| utxo.outpoint == input.previous_output)
        }).ok_or_else(|| anyhow::anyhow!("Could not find our input in PSBT"))?;

        // Find the proposer's input (first input that's not ours)
        let proposer_input_idx = if our_input_idx == 0 { 1 } else { 0 };

        // Get the proposer's input
        let proposer_psbt_input = psbt.inputs.get(proposer_input_idx)
            .ok_or_else(|| anyhow::anyhow!("Proposer input not found in PSBT"))?;

        // Get the witness_utxo (previous output being spent)
        let proposer_prevout = proposer_psbt_input.witness_utxo.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Proposer input missing witness_utxo"))?;

        // Verify it's P2TR
        if !proposer_prevout.script_pubkey.is_p2tr() {
            return Err(anyhow::anyhow!("Proposer input is not P2TR"));
        }

        // Extract the proposer's input public key from the script
        let proposer_input_pubkey_xonly = tweak::extract_taproot_pubkey(proposer_prevout)?;

        // Convert to full pubkey (assume even parity)
        let mut proposer_input_pubkey_bytes = [0u8; 33];
        proposer_input_pubkey_bytes[0] = 0x02;
        proposer_input_pubkey_bytes[1..].copy_from_slice(&proposer_input_pubkey_xonly);
        let proposer_input_pubkey = PublicKey::from_slice(&proposer_input_pubkey_bytes)?;

        // Verify it matches the proposer_pubkey in TweakInfo
        if proposer_input_pubkey != tweak_info.proposer_pubkey {
            return Err(anyhow::anyhow!(
                "Proposer input pubkey mismatch: PSBT has {}, TweakInfo claims {}",
                proposer_input_pubkey,
                tweak_info.proposer_pubkey
            ));
        }

        // Verify ALL inputs are P2TR (taproot only)
        for (idx, input) in psbt.inputs.iter().enumerate() {
            let prevout = input.witness_utxo.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Input {} missing witness_utxo", idx))?;

            if !prevout.script_pubkey.is_p2tr() {
                return Err(anyhow::anyhow!("Input {} is not P2TR (taproot required)", idx));
            }
        }

        Ok(())
    }

    /// Validate that the tweak follows the correct rules
    fn validate_tweak<F>(
        &self,
        tweak_info: &TweakInfo,
        our_utxos: &[bdk_wallet::LocalOutput],
        derive_privkey: &F,
    ) -> Result<()>
    where
        F: Fn(bdk_wallet::KeychainKind, u32) -> Result<bdk_wallet::bitcoin::secp256k1::SecretKey>,
    {
        // Basic checks first
        if !tweak_info.original_output.script_pubkey.is_p2tr() {
            return Err(anyhow::anyhow!("Original output is not P2TR"));
        }
        if !tweak_info.tweaked_output.script_pubkey.is_p2tr() {
            return Err(anyhow::anyhow!("Tweaked output is not P2TR"));
        }

        // Find the UTXO that matches the original output's script
        let our_utxo = our_utxos.iter()
            .find(|utxo| utxo.txout.script_pubkey == tweak_info.original_output.script_pubkey)
            .ok_or_else(|| anyhow::anyhow!("Original output not found in our wallet"))?;

        // Derive our secret key for this UTXO
        let receiver_seckey = derive_privkey(our_utxo.keychain, our_utxo.derivation_index)?;

        // IMPORTANT: Verify the tweaked output was created using the proposer_pubkey from TweakInfo
        // This ensures the SNICKER tweak uses the proposer's input key (for wallet recovery)
        tweak::verify_tweaked_output(
            &tweak_info.original_output,
            &tweak_info.tweaked_output,
            &receiver_seckey,
            &tweak_info.proposer_pubkey
        )?;

        Ok(())
    }

    // ============================================================
    // DATABASE OPERATIONS
    // ============================================================

    /// Initialize the candidates database table
    fn init_candidates_table(conn: &mut Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS snicker_candidates (
                block_height INTEGER NOT NULL,
                txid TEXT NOT NULL,
                tx_data BLOB NOT NULL,
                PRIMARY KEY (block_height, txid)
            )",
            [],
        )?;
        Ok(())
    }

    /// Initialize the proposals database table
    fn init_proposals_table(conn: &mut Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS snicker_proposals (
                ephemeral_pubkey BLOB NOT NULL,
                tag BLOB NOT NULL,
                encrypted_data BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (ephemeral_pubkey, tag)
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_proposals_tag
             ON snicker_proposals(tag)",
            [],
        )?;
        Ok(())
    }

    /// Initialize the SNICKER UTXOs database table
    fn init_snicker_utxos_table(conn: &mut Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS snicker_utxos (
                txid TEXT NOT NULL,
                vout INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                script_pubkey BLOB NOT NULL,
                tweaked_privkey BLOB NOT NULL,
                snicker_shared_secret BLOB NOT NULL,
                block_height INTEGER,
                spent BOOLEAN DEFAULT 0,
                spent_in_txid TEXT,
                PRIMARY KEY (txid, vout)
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_snicker_utxos_spent
             ON snicker_utxos(spent)",
            [],
        )?;
        Ok(())
    }

    /// Store a candidate transaction in the database
    pub async fn store_candidate(&self, block_height: u32, tx: &Transaction) -> Result<()> {
        use bdk_wallet::bitcoin::consensus::encode::serialize;

        let conn = self.conn.lock().unwrap();
        let txid = tx.compute_txid().to_string();
        let tx_data = serialize(tx);

        conn.execute(
            "INSERT OR REPLACE INTO snicker_candidates (block_height, txid, tx_data) VALUES (?1, ?2, ?3)",
            (block_height, txid, tx_data),
        )?;

        Ok(())
    }

    /// Retrieve all stored candidate transactions
    pub async fn get_snicker_candidates(&self) -> Result<Vec<(u32, Txid, Transaction)>> {
        use bdk_wallet::bitcoin::consensus::encode::deserialize;

        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT block_height, txid, tx_data FROM snicker_candidates ORDER BY block_height DESC"
        )?;

        let candidates = stmt.query_map([], |row| {
            let height: u32 = row.get(0)?;
            let txid_str: String = row.get(1)?;
            let tx_data: Vec<u8> = row.get(2)?;

            Ok((height, txid_str, tx_data))
        })?;

        let mut result = Vec::new();
        for candidate in candidates {
            let (height, txid_str, tx_data) = candidate?;
            let txid = Txid::from_str(&txid_str)?;
            let tx: Transaction = deserialize(&tx_data)?;
            result.push((height, txid, tx));
        }

        Ok(result)
    }

    /// Clear all stored candidates
    pub async fn clear_snicker_candidates(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count = conn.execute("DELETE FROM snicker_candidates", [])?;
        tracing::info!("🗑️  Cleared {} SNICKER candidates from database", count);
        Ok(count)
    }

    /// Store a SNICKER proposal in the database
    pub async fn store_snicker_proposal(&self, proposal: &EncryptedProposal) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        let pubkey_bytes = proposal.ephemeral_pubkey.serialize();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        conn.execute(
            "INSERT OR REPLACE INTO snicker_proposals
             (ephemeral_pubkey, tag, encrypted_data, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            (
                &pubkey_bytes[..],
                &proposal.tag[..],
                &proposal.encrypted_data,
                timestamp,
            ),
        )?;

        Ok(())
    }

    /// Retrieve all SNICKER proposals from the database
    pub async fn get_all_snicker_proposals(&self) -> Result<Vec<EncryptedProposal>> {
        use bdk_wallet::bitcoin::secp256k1::PublicKey;

        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT ephemeral_pubkey, tag, encrypted_data FROM snicker_proposals
             ORDER BY created_at DESC"
        )?;

        let proposals = stmt.query_map([], |row| {
            let pubkey_bytes: Vec<u8> = row.get(0)?;
            let tag_bytes: Vec<u8> = row.get(1)?;
            let encrypted_data: Vec<u8> = row.get(2)?;
            Ok((pubkey_bytes, tag_bytes, encrypted_data))
        })?;

        let mut result = Vec::new();
        for proposal in proposals {
            let (pubkey_bytes, tag_bytes, encrypted_data) = proposal?;

            let ephemeral_pubkey = PublicKey::from_slice(&pubkey_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid pubkey in database: {}", e))?;

            let mut tag = [0u8; 8];
            if tag_bytes.len() != 8 {
                continue; // Skip invalid entries
            }
            tag.copy_from_slice(&tag_bytes);

            result.push(EncryptedProposal {
                ephemeral_pubkey,
                tag,
                encrypted_data,
            });
        }

        Ok(result)
    }

    /// Clear all SNICKER proposals from the database
    pub async fn clear_snicker_proposals(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count = conn.execute("DELETE FROM snicker_proposals", [])?;
        tracing::info!("🗑️  Cleared {} SNICKER proposals from database", count);
        Ok(count)
    }

    /// Store a SNICKER UTXO after accepting a proposal
    pub async fn store_snicker_utxo(
        &self,
        txid: bdk_wallet::bitcoin::Txid,
        vout: u32,
        amount: u64,
        script_pubkey: &bdk_wallet::bitcoin::ScriptBuf,
        tweaked_privkey: &bdk_wallet::bitcoin::secp256k1::SecretKey,
        snicker_shared_secret: &[u8; 32],
        block_height: Option<u32>,
    ) -> Result<()> {
        use bdk_wallet::bitcoin::consensus::encode::serialize;

        let conn = self.conn.lock().unwrap();

        let script_pubkey_bytes = serialize(script_pubkey);
        let tweaked_privkey_bytes = tweaked_privkey.secret_bytes();

        conn.execute(
            "INSERT OR REPLACE INTO snicker_utxos
             (txid, vout, amount, script_pubkey, tweaked_privkey, snicker_shared_secret, block_height, spent)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
            (
                txid.to_string(),
                vout,
                amount as i64,
                script_pubkey_bytes,
                &tweaked_privkey_bytes[..],
                &snicker_shared_secret[..],
                block_height,
            ),
        )?;

        tracing::info!("💾 Stored SNICKER UTXO: {}:{} ({} sats)", txid, vout, amount);
        Ok(())
    }

    /// Get the total balance of unspent SNICKER UTXOs
    pub async fn get_snicker_balance(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap();

        let balance: i64 = conn.query_row(
            "SELECT COALESCE(SUM(amount), 0) FROM snicker_utxos WHERE spent = 0",
            [],
            |row| row.get(0),
        )?;

        Ok(balance as u64)
    }

    /// List all unspent SNICKER UTXOs
    pub async fn list_snicker_utxos(&self) -> Result<Vec<SnickerUtxo>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT txid, vout, amount, script_pubkey, tweaked_privkey, snicker_shared_secret, block_height
             FROM snicker_utxos
             WHERE spent = 0
             ORDER BY block_height DESC, amount DESC"
        )?;

        let utxos = stmt.query_map([], |row| {
            let txid_str: String = row.get(0)?;
            let vout: u32 = row.get(1)?;
            let amount: i64 = row.get(2)?;
            let script_pubkey_bytes: Vec<u8> = row.get(3)?;
            let tweaked_privkey_bytes: Vec<u8> = row.get(4)?;
            let snicker_shared_secret_bytes: Vec<u8> = row.get(5)?;
            let block_height: Option<u32> = row.get(6)?;

            Ok((txid_str, vout, amount, script_pubkey_bytes, tweaked_privkey_bytes, snicker_shared_secret_bytes, block_height))
        })?.collect::<std::result::Result<Vec<_>, _>>()?;

        let mut result = Vec::new();
        for (txid_str, vout, amount, script_bytes, privkey_bytes, secret_bytes, block_height) in utxos {
            use bdk_wallet::bitcoin::consensus::encode::deserialize;

            let txid = bdk_wallet::bitcoin::Txid::from_str(&txid_str)?;
            let script_pubkey: bdk_wallet::bitcoin::ScriptBuf = deserialize(&script_bytes)?;
            let tweaked_privkey = bdk_wallet::bitcoin::secp256k1::SecretKey::from_slice(&privkey_bytes)?;

            let mut snicker_shared_secret = [0u8; 32];
            snicker_shared_secret.copy_from_slice(&secret_bytes);

            result.push(SnickerUtxo {
                outpoint: bdk_wallet::bitcoin::OutPoint { txid, vout },
                amount: amount as u64,
                script_pubkey,
                tweaked_privkey,
                snicker_shared_secret,
                block_height,
            });
        }

        Ok(result)
    }

    /// Mark a SNICKER UTXO as spent
    pub async fn mark_snicker_utxo_spent(
        &self,
        txid: bdk_wallet::bitcoin::Txid,
        vout: u32,
        spent_in_txid: bdk_wallet::bitcoin::Txid,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "UPDATE snicker_utxos SET spent = 1, spent_in_txid = ?1 WHERE txid = ?2 AND vout = ?3",
            (spent_in_txid.to_string(), txid.to_string(), vout),
        )?;

        tracing::info!("✅ Marked SNICKER UTXO {}:{} as spent in {}", txid, vout, spent_in_txid);
        Ok(())
    }

    // ============================================================
    // OPPORTUNITY FINDING
    // ============================================================

    /// Find all SNICKER proposal opportunities
    ///
    /// Returns list of opportunities sorted by our UTXO value (highest first),
    /// then by target output value (highest first).
    ///
    /// # Arguments
    /// * `our_utxos` - Our wallet's UTXOs to use as proposer inputs
    /// * `min_utxo_sats` - Minimum size of our UTXO to consider (e.g., 75,000 sats)
    ///
    /// # Algorithm
    /// 1. Sort our UTXOs by value descending
    /// 2. Filter to only UTXOs >= min_utxo_sats
    /// 3. For each qualifying UTXO:
    ///    - Filter candidates where output value < our UTXO value
    ///    - Add ALL matches to results list
    /// 4. Return complete list of opportunities
    pub async fn find_opportunities(
        &self,
        our_utxos: &[bdk_wallet::LocalOutput],
        min_utxo_sats: u64,
    ) -> Result<Vec<ProposalOpportunity>> {
        // 1. Sort our UTXOs by value descending
        let mut sorted_utxos: Vec<_> = our_utxos.to_vec();
        sorted_utxos.sort_by(|a, b| b.txout.value.cmp(&a.txout.value));

        // 2. Filter to only UTXOs >= min_utxo_sats
        let qualifying_utxos: Vec<_> = sorted_utxos
            .into_iter()
            .filter(|utxo| utxo.txout.value.to_sat() >= min_utxo_sats)
            .collect();

        if qualifying_utxos.is_empty() {
            tracing::info!("⚠️  No UTXOs >= {} sats available for SNICKER proposals", min_utxo_sats);
            return Ok(Vec::new());
        }

        tracing::info!("🔍 Found {} qualifying UTXOs (>= {} sats) for SNICKER",
              qualifying_utxos.len(), min_utxo_sats);

        // 3. Get all snicker_candidates from database
        let candidates = self.get_snicker_candidates().await?;

        if candidates.is_empty() {
            tracing::info!("⚠️  No SNICKER candidates in database.");
            return Ok(Vec::new());
        }

        tracing::info!("🔍 Scanning {} candidates against {} UTXOs",
              candidates.len(), qualifying_utxos.len());

        // 4. For each qualifying UTXO, find ALL matching candidates
        let mut opportunities = Vec::new();

        for our_utxo in &qualifying_utxos {
            let our_value = our_utxo.txout.value;
            let mut matches_for_this_utxo = 0;

            // Find all candidates where output value < our UTXO value
            for (_height, _txid, target_tx) in &candidates {
                for (output_index, output) in target_tx.output.iter().enumerate() {
                    // Only consider P2TR outputs smaller than our UTXO
                    if output.script_pubkey.is_p2tr() && output.value < our_value {
                        opportunities.push(ProposalOpportunity {
                            our_outpoint: our_utxo.outpoint,
                            our_value,
                            target_tx: target_tx.clone(),
                            target_output_index: output_index,
                            target_value: output.value,
                        });
                        matches_for_this_utxo += 1;
                    }
                }
            }

            if matches_for_this_utxo > 0 {
                tracing::info!("  UTXO {}:{} ({} sats) → {} opportunities",
                      our_utxo.outpoint.txid, our_utxo.outpoint.vout,
                      our_value.to_sat(), matches_for_this_utxo);
            }
        }

        // Sort opportunities by our value (desc), then target value (desc)
        opportunities.sort_by(|a, b| {
            b.our_value.cmp(&a.our_value)
                .then(b.target_value.cmp(&a.target_value))
        });

        tracing::info!("🎯 Found {} total SNICKER opportunities", opportunities.len());

        Ok(opportunities)
    }

    // ============================================================
    // PROPOSAL SCANNING
    // ============================================================

    /// Scan all proposals and attempt to decrypt those meant for our outputs
    ///
    /// Iterates through all proposals and our wallet outputs, checking if the
    /// tag matches. If it does, attempts decryption.
    ///
    /// # Arguments
    /// * `our_utxos` - Our wallet's UTXOs (for matching proposals)
    /// * `derive_privkey` - Function to derive private key given (keychain, derivation_index)
    ///
    /// # Returns
    /// Vector of successfully decrypted proposals meant for us
    pub async fn scan_proposals<F>(
        &self,
        our_utxos: &[bdk_wallet::LocalOutput],
        derive_privkey: F,
    ) -> Result<Vec<Proposal>>
    where
        F: Fn(bdk_wallet::KeychainKind, u32) -> Result<bdk_wallet::bitcoin::secp256k1::SecretKey>,
    {
        use crate::snicker::tweak::{
            calculate_dh_shared_secret, compute_proposal_tag, decrypt_proposal,
        };

        // Get all proposals
        let proposals = self.get_all_snicker_proposals().await?;
        if proposals.is_empty() {
            return Ok(Vec::new());
        }

        tracing::info!("🔍 Scanning {} proposals for our wallet", proposals.len());
        tracing::info!("🔍 Checking against {} UTXOs", our_utxos.len());

        let mut decrypted_proposals = Vec::new();

        // For each proposal, try to match with our outputs
        for encrypted_proposal in &proposals {
            for utxo in our_utxos {
                // 1. Get secret key for this UTXO
                let our_seckey = match derive_privkey(utxo.keychain, utxo.derivation_index) {
                    Ok(sk) => sk,
                    Err(e) => {
                        tracing::warn!("Failed to derive private key for UTXO: {}", e);
                        continue;
                    }
                };

                // 2. Calculate shared secret = ECDH(our_seckey, ephemeral_pubkey)
                let shared_secret = calculate_dh_shared_secret(
                    &our_seckey,
                    &encrypted_proposal.ephemeral_pubkey
                );

                // 3. Calculate expected tag
                let expected_tag = compute_proposal_tag(&shared_secret);

                // 4. Check if tags match
                if expected_tag == encrypted_proposal.tag {
                    // 5. Try to decrypt
                    match decrypt_proposal(&encrypted_proposal.encrypted_data, &shared_secret) {
                        Ok(decrypted_bytes) => {
                            // Deserialize the proposal
                            match serde_json::from_slice::<Proposal>(&decrypted_bytes) {
                                Ok(proposal) => {
                                    tracing::info!("✅ Successfully decrypted proposal for UTXO {}:{}",
                                          utxo.outpoint.txid, utxo.outpoint.vout);
                                    decrypted_proposals.push(proposal);
                                    break; // Move to next proposal
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to deserialize proposal: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Decryption failed despite tag match: {}", e);
                        }
                    }
                }
            }
        }

        tracing::info!("🎯 Found {} proposals meant for our wallet", decrypted_proposals.len());
        Ok(decrypted_proposals)
    }
}

/// Opportunity for creating a SNICKER proposal
#[derive(Debug, Clone)]
pub struct ProposalOpportunity {
    /// Our UTXO to use as input
    pub our_outpoint: OutPoint,
    /// Our UTXO value
    pub our_value: bdk_wallet::bitcoin::Amount,
    /// Target transaction containing receiver's UTXO
    pub target_tx: Transaction,
    /// Index of target output in target_tx
    pub target_output_index: usize,
    /// Value of target output
    pub target_value: bdk_wallet::bitcoin::Amount,
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
