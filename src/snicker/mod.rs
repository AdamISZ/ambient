//! SNICKER (Simple Non-Interactive Coinjoin with Keys for Encryption Reused)
//!
//! This module implements both Proposer and Receiver functionality for SNICKER transactions.
//! A single `Snicker` struct provides methods for both roles, sharing common logic.
//!
//! # Example Usage
//!
//! ```no_run
//! use ambient::snicker::Snicker;
//! use bdk_wallet::bitcoin::Network;
//! use std::path::Path;
//!
//! # fn example() -> anyhow::Result<()> {
//! // Create a SNICKER instance with database path and network
//! let db_path = Path::new("snicker.db");
//! let snicker = Snicker::new(db_path, Network::Bitcoin)?;
//!
//! // The Snicker instance provides methods for:
//! // - propose(): Create encrypted coinjoin proposals
//! // - receive(): Validate and sign received proposals
//! // - Database storage for candidates, proposals, and SNICKER UTXOs
//! # Ok(())
//! # }
//! ```

pub mod tweak;
pub mod pattern;

// Re-export pattern detection function for easy access
pub use pattern::is_likely_snicker_transaction;

#[cfg(test)]
mod tweak_tests;

#[cfg(test)]
mod validation_tests;

use std::sync::{Arc, Mutex};
use std::str::FromStr;

use anyhow::{Result, anyhow};
use zeroize::Zeroizing;
use bdk_wallet::{
    bitcoin::{Network, OutPoint, Transaction, TxOut, Txid, psbt::Psbt, secp256k1::PublicKey},
    rusqlite::Connection,
};
use serde::{Serialize, Deserialize};

// ============================================================
// AUTOMATION STATE
// ============================================================

/// Role in the SNICKER automation state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AutomationRole {
    /// Actively maintaining N outstanding proposals
    Proposer,
    /// Waiting only, no new proposals created
    Receiver,
}

impl AutomationRole {
    /// Flip a coin to get a random role
    pub fn coin_flip() -> Self {
        if rand::random::<bool>() {
            AutomationRole::Proposer
        } else {
            AutomationRole::Receiver
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AutomationRole::Proposer => "proposer",
            AutomationRole::Receiver => "receiver",
        }
    }
}

impl std::str::FromStr for AutomationRole {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "proposer" => Ok(AutomationRole::Proposer),
            "receiver" => Ok(AutomationRole::Receiver),
            _ => Err(anyhow!("Invalid automation role: {}", s)),
        }
    }
}

impl std::fmt::Display for AutomationRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Persisted automation state
#[derive(Debug, Clone)]
pub struct AutomationState {
    /// Current role (Proposer or Receiver)
    pub role: AutomationRole,
    /// Block height of most recent successful coinjoin (or wallet creation height)
    pub last_coinjoin_height: u32,
}

impl Default for AutomationState {
    fn default() -> Self {
        Self {
            role: AutomationRole::Proposer,
            last_coinjoin_height: 0,
        }
    }
}

// ============================================================
// SNICKER PROPOSAL VERSIONING
// ============================================================

/// Magic bytes identifying a SNICKER proposal: "SNIC" in ASCII
/// Used to prevent false positives when scanning files/network data
pub const SNICKER_MAGIC: [u8; 4] = [0x53, 0x4E, 0x49, 0x43];

/// Current proposal format version
pub const SNICKER_VERSION_V1: u8 = 0x01;

/// Proposal feature flags (reserved for future use)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposalFlags(pub u32);

impl ProposalFlags {
    /// No flags set (current default)
    pub const NONE: u32 = 0x00000000;

    // (Imaginary examples!) Reserved for future features:
    // pub const FEATURE_RBF: u32           = 0x00000001; // Opt-in RBF
    // pub const FEATURE_TAPROOT_ONLY: u32  = 0x00000002; // All inputs are Taproot
    // pub const FEATURE_BATCH: u32         = 0x00000004; // Part of batch proposal
    // pub const FEATURE_TIME_LOCKED: u32   = 0x00000008; // Contains time locks

    pub fn new(flags: u32) -> Self {
        ProposalFlags(flags)
    }

    pub fn none() -> Self {
        ProposalFlags(Self::NONE)
    }
}

/// Validate proposal header (magic + version)
/// Returns the version if valid, or an error
pub fn validate_proposal_header(bytes: &[u8]) -> Result<u8> {
    if bytes.len() < 5 {
        return Err(anyhow!("Proposal too short (need at least 5 bytes for header)"));
    }

    // Check magic bytes
    if &bytes[0..4] != SNICKER_MAGIC {
        return Err(anyhow!(
            "Invalid magic bytes: expected 'SNIC' (0x534E4943), got {:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        ));
    }

    let version = bytes[4];

    // Validate version
    match version {
        SNICKER_VERSION_V1 => Ok(version),
        _ => Err(anyhow!("Unsupported proposal version: 0x{:02x}", version)),
    }
}

/// Extract proposal blob (after magic+version header)
pub fn extract_proposal_blob(bytes: &[u8]) -> Result<Vec<u8>> {
    validate_proposal_header(bytes)?;
    Ok(bytes[5..].to_vec())
}

/// Prepend magic+version to proposal blob for transmission/storage
pub fn wrap_proposal_blob(version: u8, encrypted_data: &[u8]) -> Vec<u8> {
    let mut wrapped = Vec::with_capacity(5 + encrypted_data.len());
    wrapped.extend_from_slice(&SNICKER_MAGIC);
    wrapped.push(version);
    wrapped.extend_from_slice(encrypted_data);
    wrapped
}

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
    let txid = tx.compute_txid();
    let mut found_match = false;

    for (vout, output) in tx.output.iter().enumerate() {
        let is_p2tr = output.script_pubkey.is_p2tr();
        let amount = output.value.to_sat();
        let in_range = amount >= size_min && amount <= size_max;

        if is_p2tr && in_range {
            tracing::info!("✅ Candidate match: {}:{} ({} sats, range {}-{})",
                txid, vout, amount, size_min, size_max);
            found_match = true;
        } else if is_p2tr {
            tracing::debug!("⏭️  Skipping P2TR output {}:{} ({} sats, out of range {}-{})",
                txid, vout, amount, size_min, size_max);
        }
    }

    found_match
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
    /// Tag for identifying this proposal (from EncryptedProposal)
    pub tag: [u8; 8],
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
    /// Proposal format version (prepended to encrypted_data on wire)
    pub version: u8,
    /// Encrypted Proposal data (contains [flags:4 bytes][proposal_bytes])
    /// Wire format: [MAGIC:4][version:1][encrypted_data]
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
    db_manager: Option<crate::encryption::EncryptedMemoryDb>,
    _network: Network,
}

impl Snicker {
    /// Create a new SNICKER instance with in-memory encrypted database
    ///
    /// # Arguments
    /// * `conn` - Shared in-memory database connection
    /// * `db_manager` - Optional encrypted database manager for flushing changes
    /// * `network` - Bitcoin network (mainnet, testnet, signet, regtest)
    pub fn new(
        conn: Arc<Mutex<Connection>>,
        db_manager: Option<crate::encryption::EncryptedMemoryDb>,
        network: Network,
    ) -> Result<Self> {
        Ok(Self {
            conn,
            db_manager,
            _network: network,
        })
    }

    /// Test-only constructor that creates a connection from a path
    #[cfg(test)]
    pub fn new_from_path(db_path: &std::path::Path, network: Network) -> Result<Self> {
        let mut conn_raw = rusqlite::Connection::open(db_path)?;
        Self::init_snicker_db(&mut conn_raw)?;
        let conn = Arc::new(Mutex::new(conn_raw));
        Self::new(conn, None, network)
    }

    /// Flush in-memory database to encrypted file
    ///
    /// Called after any modification to SNICKER UTXO set
    fn flush_db(&self) -> Result<()> {
        if let Some(ref db_manager) = self.db_manager {
            let conn_guard = self.conn.lock().unwrap();
            db_manager.flush(&*conn_guard)?;
            tracing::debug!("💾 Flushed snicker.sqlite.enc after UTXO change");
        }
        Ok(())
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
    /// * `min_change_output_size` - Minimum UTXO size to create (change below this bumps fee)
    /// * `sign_psbt` - Callback to sign the PSBT (should only sign proposer's input)
    ///
    /// # Returns
    /// Tuple of (partially-signed PSBT, encrypted proposal with signed PSBT)
    pub fn propose<F>(
        &self,
        receiver_outpoint: OutPoint,
        receiver_txout: TxOut,
        proposer_outpoint: OutPoint,
        proposer_utxo_txout: TxOut,
        proposer_input_seckey: bdk_wallet::bitcoin::secp256k1::SecretKey,
        proposer_equal_output_addr: bdk_wallet::bitcoin::Address,
        proposer_change_output_addr: bdk_wallet::bitcoin::Address,
        delta_sats: i64,
        fee_rate: bdk_wallet::bitcoin::FeeRate,
        min_change_output_size: u64,
        sign_psbt: F,
    ) -> Result<(Proposal, EncryptedProposal)>
    where
        F: FnOnce(&mut Psbt) -> Result<()>,
    {
        use bdk_wallet::bitcoin::secp256k1::{rand, Secp256k1, SecretKey};

        // 1. Extract proposer's input public key from the UTXO being spent
        let secp = Secp256k1::new();
        let proposer_input_pubkey = proposer_input_seckey.public_key(&secp);

        // 2. Create the tweaked output using proposer's input key
        let (tweaked_output, _snicker_shared_secret) = self.create_tweaked_output(
            &receiver_txout,
            &proposer_input_seckey,
        )?;

        // 2. Build the PSBT (unsigned)
        let mut psbt = self.build_psbt(
            receiver_outpoint,
            &receiver_txout,
            tweaked_output.clone(),
            proposer_outpoint,
            proposer_utxo_txout.clone(),
            proposer_equal_output_addr,
            proposer_change_output_addr,
            delta_sats,
            fee_rate,
            min_change_output_size,
        )?;

        // 3. Sign the proposer's input (partial signature)
        sign_psbt(&mut psbt)?;

        // 4. Create the proposal with signed PSBT
        let tweak_info = TweakInfo {
            original_output: receiver_txout.clone(),
            tweaked_output,
            proposer_pubkey: proposer_input_pubkey,
        };

        // 5. Generate ephemeral keypair for encryption (separate from SNICKER tweak)
        let mut rng = rand::thread_rng();
        let ephemeral_seckey = SecretKey::new(&mut rng);
        let ephemeral_pubkey = ephemeral_seckey.public_key(&secp);

        // 6. Extract receiver's pubkey from target output
        let receiver_pubkey_xonly = tweak::extract_taproot_pubkey(&receiver_txout)?;
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

        // Create proposal with tag
        let proposal = Proposal {
            tag,
            psbt: psbt.clone(),
            tweak_info
        };

        // 9. Serialize and encrypt the proposal (contains partially-signed PSBT)
        // After decryption, receiver will extract proposer's input key from PSBT witness
        let proposal_bytes = serde_json::to_vec(&proposal)?;

        // Use v1 encryption with flags (currently no flags set)
        let flags = ProposalFlags::none().0;
        let encrypted_data = tweak::encrypt_proposal_v1(&proposal_bytes, flags, &encryption_shared_secret)?;

        let encrypted_proposal = EncryptedProposal {
            ephemeral_pubkey,
            tag,
            version: SNICKER_VERSION_V1,
            encrypted_data,
        };

        // Return both the Proposal (with PSBT + tag) and the encrypted proposal (for sharing)
        Ok((proposal, encrypted_proposal))
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
        our_utxos: &[crate::wallet_node::WalletUtxo],
        acceptable_delta_range: (i64, i64),
        derive_privkey: F,
    ) -> Result<Psbt>
    where
        F: Fn(&crate::wallet_node::WalletUtxo) -> Result<bdk_wallet::bitcoin::secp256k1::SecretKey>,
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
    /// # Arguments
    /// * `min_change_output_size` - Minimum UTXO size to create (change below this bumps fee)
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
        min_change_output_size: u64,
    ) -> Result<(Vec<TxOut>, bdk_wallet::bitcoin::Amount)> {
        use bdk_wallet::bitcoin::Amount;
        use bdk_wallet::bitcoin::secp256k1::rand::{self, seq::SliceRandom};

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

        // Estimate transaction weight: 2 P2TR inputs + variable outputs
        // Overhead: version(4) + locktime(4) + #inputs(1) + #outputs(1) = 10 bytes non-witness = 40 WU
        //           + segwit flag/marker(2) witness bytes = 2 WU
        //           Total overhead: 42 WU
        // Per P2TR input: txid(32) + vout(4) + scriptsig_len(1) + sequence(4) = 41 bytes non-witness = 164 WU
        //                 + witness: stack_count(1) + sig_len(1) + sig(64) = 66 bytes witness = 66 WU
        //                 Total per input: 230 WU
        // Per P2TR output: amount(8) + script_len(1) + scriptpubkey(34) = 43 bytes non-witness = 172 WU
        // Formula: (42 + 230*num_inputs + 172*num_outputs + 3) / 4  (the +3 ensures rounding up)
        let weight_units_3_outputs = 42 + (230 * 2) + (172 * 3); // = 1018 WU
        let estimated_vsize_3_outputs = (weight_units_3_outputs + 3) / 4; // = 255 vbytes
        let estimated_fee_3_outputs = fee_rate.fee_vb(estimated_vsize_3_outputs)
            .ok_or_else(|| anyhow::anyhow!("Fee calculation overflow"))?;

        // Calculate change (initially assuming 3 outputs)
        let total_in = receiver_output.value + proposer_amount;
        let total_out_before_change = equal_output_amount + equal_output_amount;
        let change_amount = total_in - total_out_before_change - estimated_fee_3_outputs;

        // Check if change is below dust limit (cannot create at all)
        if change_amount.to_sat() < 546 {
            return Err(anyhow::anyhow!(
                "Insufficient proposer funds: change would be dust ({} sats)",
                change_amount.to_sat()
            ));
        }

        // Build outputs vector - drop change if below min_change_output_size
        let (outputs, actual_fee) = if change_amount.to_sat() < min_change_output_size {
            // Change is above dust but below min_change_output_size - drop it and bump fee
            tracing::info!(
                "💸 Change output {} sats is below min_change_output_size {} sats - dropping and bumping miner fee",
                change_amount.to_sat(), min_change_output_size
            );

            // Recalculate fee for 2-output transaction (no change)
            let weight_units_2_outputs = 42 + (230 * 2) + (172 * 2); // = 846 WU
            let estimated_vsize_2_outputs = (weight_units_2_outputs + 3) / 4; // = 212 vbytes
            let estimated_fee_2_outputs = fee_rate.fee_vb(estimated_vsize_2_outputs)
                .ok_or_else(|| anyhow::anyhow!("Fee calculation overflow"))?;

            // Actual fee will be: estimated_fee_2_outputs + change_amount
            let actual_fee = estimated_fee_2_outputs + change_amount;

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
            ];
            (outputs, actual_fee)
        } else {
            // Change is above min_change_output_size - include it
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
            (outputs, estimated_fee_3_outputs)
        };

        // Randomize output order for privacy
        let mut rng = rand::thread_rng();
        let mut outputs = outputs; // Make mutable for shuffle
        outputs.shuffle(&mut rng);

        Ok((outputs, actual_fee))
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
    /// * `min_change_output_size` - Minimum UTXO size to create (change below this bumps fee)
    fn build_psbt(
        &self,
        receiver_outpoint: OutPoint,
        receiver_txout: &TxOut,
        tweaked_output: TxOut,
        proposer_outpoint: OutPoint,
        proposer_txout: TxOut,
        proposer_equal_addr: bdk_wallet::bitcoin::Address,
        proposer_change_addr: bdk_wallet::bitcoin::Address,
        delta_sats: i64,
        fee_rate: bdk_wallet::bitcoin::FeeRate,
        min_change_output_size: u64,
    ) -> Result<Psbt> {
        use bdk_wallet::bitcoin::{Transaction as BdkTransaction, TxIn, Sequence, Witness};
        use bdk_wallet::bitcoin::transaction::Version;

        // Receiver's original output (from candidate UTXO)
        let receiver_output = receiver_txout;

        // Calculate outputs using the "equal outputs + change" structure
        let (outputs, _estimated_fee) = Self::build_equal_outputs_structure(
            receiver_output,
            proposer_txout.value,
            delta_sats,
            fee_rate,
            tweaked_output,
            proposer_equal_addr.clone(),
            proposer_change_addr.clone(),
            min_change_output_size,
        )?;

        // Build the transaction
        // (receiver_outpoint is now passed as a parameter)

        // Create inputs with associated metadata
        let mut inputs_with_metadata = vec![
            (
                // Receiver's input (to be signed by receiver)
                TxIn {
                    previous_output: receiver_outpoint,
                    script_sig: bdk_wallet::bitcoin::ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
                receiver_output.clone(),
            ),
            (
                // Proposer's input (to be signed by us)
                TxIn {
                    previous_output: proposer_outpoint,
                    script_sig: bdk_wallet::bitcoin::ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
                proposer_txout.clone(),
            ),
        ];

        // Randomize input order for privacy
        use bdk_wallet::bitcoin::secp256k1::rand::{self, seq::SliceRandom};
        let mut rng = rand::thread_rng();
        inputs_with_metadata.shuffle(&mut rng);

        // Separate inputs and witness_utxos after shuffling
        let (tx_inputs, witness_utxos): (Vec<_>, Vec<_>) = inputs_with_metadata.into_iter().unzip();

        let tx = BdkTransaction {
            version: Version::TWO,
            lock_time: bdk_wallet::bitcoin::locktime::absolute::LockTime::ZERO,
            input: tx_inputs,
            output: outputs,
        };

        // Create PSBT from transaction
        let mut psbt = Psbt::from_unsigned_tx(tx)?;

        // Add witness_utxo for each input (now in randomized order)
        for (i, witness_utxo) in witness_utxos.iter().enumerate() {
            psbt.inputs[i].witness_utxo = Some(witness_utxo.clone());
        }

        // Set sighash type for taproot signing (SIGHASH_ALL is standard)
        use bdk_wallet::bitcoin::sighash::TapSighashType;
        for input in &mut psbt.inputs {
            input.sighash_type = Some(TapSighashType::All.into());
        }

        // PHASE 1 DEBUG: Dump PSBT state after manual creation (before adding tap fields)
        crate::utils::dump_psbt_state(&psbt, "After manual SNICKER PSBT creation - BEFORE adding tap fields");

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
        our_utxos: &[crate::wallet_node::WalletUtxo],
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
            if our_utxos.iter().any(|utxo| utxo.outpoint() == outpoint) {
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
        our_utxos: &[crate::wallet_node::WalletUtxo],
        acceptable_delta_range: (i64, i64),
        derive_privkey: &F,
    ) -> Result<()>
    where
        F: Fn(&crate::wallet_node::WalletUtxo) -> Result<bdk_wallet::bitcoin::secp256k1::SecretKey>,
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
        our_utxos: &[crate::wallet_node::WalletUtxo],
    ) -> Result<()> {
        // Find our input to identify which input is the proposer's
        let our_input_idx = psbt.unsigned_tx.input.iter().position(|input| {
            our_utxos.iter().any(|utxo| utxo.outpoint() == input.previous_output)
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
        our_utxos: &[crate::wallet_node::WalletUtxo],
        derive_privkey: &F,
    ) -> Result<()>
    where
        F: Fn(&crate::wallet_node::WalletUtxo) -> Result<bdk_wallet::bitcoin::secp256k1::SecretKey>,
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
            .find(|utxo| utxo.script_pubkey() == &tweak_info.original_output.script_pubkey)
            .ok_or_else(|| anyhow::anyhow!("Original output not found in our wallet"))?;

        // Derive our secret key for this UTXO
        let receiver_seckey = derive_privkey(our_utxo)?;

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

    /// Initialize all SNICKER database tables (public for wallet generation)
    pub fn init_snicker_db(conn: &mut Connection) -> Result<()> {
        Self::init_decrypted_proposals_table(conn)?;
        Self::init_snicker_utxos_table(conn)?;
        Self::init_automation_log_table(conn)?;
        Self::init_pending_transactions_table(conn)?;
        Self::init_proposal_pairings_table(conn)?;
        Self::init_automation_state_table(conn)?;
        Self::init_coinjoin_spending_table(conn)?;
        Ok(())
    }

    /// Removed: encrypted proposals table no longer used
    /// Proposals are decrypted at storage time and stored directly in decrypted_proposals

    /// Initialize the decrypted proposals database table
    fn init_decrypted_proposals_table(conn: &mut Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS decrypted_proposals (
                tag BLOB PRIMARY KEY,
                psbt BLOB NOT NULL,
                tweak_info BLOB NOT NULL,
                role TEXT NOT NULL,
                status TEXT NOT NULL,
                our_utxo TEXT NOT NULL,
                counterparty_utxo TEXT NOT NULL,
                delta_sats INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_decrypted_status
             ON decrypted_proposals(status)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_decrypted_delta
             ON decrypted_proposals(delta_sats)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_utxo_pair
             ON decrypted_proposals(our_utxo, counterparty_utxo, role, status)",
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
                status TEXT DEFAULT 'unspent',
                spent_in_txid TEXT,
                PRIMARY KEY (txid, vout)
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_snicker_utxos_status
             ON snicker_utxos(status)",
            [],
        )?;

        // Migration: Convert old 'spent' boolean column to 'status' text column if it exists
        let has_spent_column: Result<bool, _> = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('snicker_utxos') WHERE name='spent'",
            [],
            |row| {
                let count: i64 = row.get(0)?;
                Ok(count > 0)
            },
        );

        if has_spent_column.unwrap_or(false) {
            // Migrate data: spent=0 -> 'unspent', spent=1 -> 'spent'
            conn.execute(
                "UPDATE snicker_utxos SET status = CASE WHEN spent = 0 THEN 'unspent' ELSE 'spent' END",
                [],
            )?;
            // Note: SQLite doesn't easily support DROP COLUMN, so old 'spent' column remains but unused
        }

        // Migration: Add pending_since timestamp column if it doesn't exist
        let has_pending_since: Result<bool, _> = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('snicker_utxos') WHERE name='pending_since'",
            [],
            |row| {
                let count: i64 = row.get(0)?;
                Ok(count > 0)
            },
        );

        if !has_pending_since.unwrap_or(false) {
            conn.execute(
                "ALTER TABLE snicker_utxos ADD COLUMN pending_since INTEGER",
                [],
            )?;
            tracing::info!("✅ Added pending_since column to snicker_utxos table");
        }

        Ok(())
    }

    /// Initialize the automation log database table
    fn init_automation_log_table(conn: &mut Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS automation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                action_type TEXT NOT NULL,
                tag BLOB,
                txid TEXT,
                delta INTEGER,
                success BOOLEAN NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_automation_log_timestamp
             ON automation_log(timestamp)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_automation_log_action
             ON automation_log(action_type, timestamp)",
            [],
        )?;
        Ok(())
    }

    /// Initialize the pending transactions table for tracking broadcast-but-unconfirmed txs
    fn init_pending_transactions_table(conn: &mut Connection) -> Result<()> {
        // Track pending transactions (broadcast but not confirmed)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pending_transactions (
                txid TEXT PRIMARY KEY,
                broadcast_time INTEGER NOT NULL,
                total_input_sats INTEGER NOT NULL,
                total_output_sats INTEGER NOT NULL,
                fee_sats INTEGER NOT NULL
            )",
            [],
        )?;
        // Track which outpoints are spent by pending transactions
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pending_inputs (
                spending_txid TEXT NOT NULL,
                spent_txid TEXT NOT NULL,
                spent_vout INTEGER NOT NULL,
                amount_sats INTEGER NOT NULL,
                PRIMARY KEY (spent_txid, spent_vout),
                FOREIGN KEY (spending_txid) REFERENCES pending_transactions(txid) ON DELETE CASCADE
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pending_inputs_spending_txid
             ON pending_inputs(spending_txid)",
            [],
        )?;
        Ok(())
    }

    /// Initialize the proposal pairings table for tracking which UTXOs have live proposals
    fn init_proposal_pairings_table(conn: &mut Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS proposal_pairings (
                our_txid TEXT NOT NULL,
                our_vout INTEGER NOT NULL,
                target_txid TEXT NOT NULL,
                target_vout INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (our_txid, our_vout, target_txid, target_vout)
            )",
            [],
        )?;
        // Index for cleanup when target is spent
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_proposal_pairings_target
             ON proposal_pairings(target_txid, target_vout)",
            [],
        )?;
        // Index for querying by our outpoint
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_proposal_pairings_our
             ON proposal_pairings(our_txid, our_vout)",
            [],
        )?;
        Ok(())
    }

    /// Initialize the automation state table for persisting proposer/receiver mode
    fn init_automation_state_table(conn: &mut Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS automation_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                mode TEXT NOT NULL DEFAULT 'proposer',
                last_coinjoin_height INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL
            )",
            [],
        )?;
        Ok(())
    }

    /// Initialize the coinjoin spending table for tracking sats spent on coinjoins
    fn init_coinjoin_spending_table(conn: &mut Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS coinjoin_spending (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                delta_sats INTEGER NOT NULL,
                role TEXT NOT NULL,
                txid TEXT NOT NULL
            )",
            [],
        )?;
        // Index for efficient time-based queries
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_coinjoin_spending_timestamp
             ON coinjoin_spending(timestamp)",
            [],
        )?;
        Ok(())
    }

    // Removed: snicker_candidates table and related methods
    // Candidates are now queried directly from partial_utxo_set with appropriate filters

    /// Store a SNICKER proposal in the database
    /// Store an encrypted proposal (proposer side - for later sharing/export)
    /// This is used when creating proposals, not receiving them
    /// Does NOT attempt decryption (we created it, we already know what's in it)
    pub async fn store_created_proposal(&self, proposal: &EncryptedProposal) -> Result<()> {
        // For now, do nothing - we don't need to store created proposals
        // They can be exported directly when created
        // This method exists for API compatibility
        tracing::debug!("Skipping storage of created proposal tag {} (not needed)",
            ::hex::encode(&proposal.tag));
        Ok(())
    }

    /// Try to decrypt an encrypted proposal using a SNICKER UTXO's tweaked private key
    /// Returns Ok(proposal) if decryption succeeds, Err otherwise
    pub fn try_decrypt_with_privkey(
        &self,
        encrypted: &EncryptedProposal,
        tweaked_privkey: &bdk_wallet::bitcoin::secp256k1::SecretKey,
    ) -> Result<Proposal>
    {
        use crate::snicker::tweak::{
            calculate_dh_shared_secret, compute_proposal_tag, decrypt_proposal_v1,
        };

        // Calculate shared secret = ECDH(tweaked_privkey, ephemeral_pubkey)
        let shared_secret = calculate_dh_shared_secret(tweaked_privkey, &encrypted.ephemeral_pubkey);

        // Calculate expected tag
        let expected_tag = compute_proposal_tag(&shared_secret);

        // Check if tags match
        if expected_tag != encrypted.tag {
            return Err(anyhow::anyhow!("Tag mismatch - proposal not for this SNICKER UTXO"));
        }

        // Decrypt the proposal (v1 format with flags)
        let (flags, decrypted_bytes) = decrypt_proposal_v1(&encrypted.encrypted_data, &shared_secret)?;

        // Log flags if any are set (currently should be 0)
        if flags != ProposalFlags::NONE {
            tracing::info!("📋 Proposal has flags set: 0x{:08x}", flags);
        }

        // Deserialize the proposal
        let proposal = serde_json::from_slice::<Proposal>(&decrypted_bytes)?;

        Ok(proposal)
    }

    /// Try to decrypt an encrypted proposal for a specific UTXO
    /// Returns Ok(proposal) if decryption succeeds, Err otherwise
    pub fn try_decrypt_for_utxo<F>(
        &self,
        encrypted: &EncryptedProposal,
        utxo: &crate::wallet_node::WalletUtxo,
        derive_privkey: F,
    ) -> Result<Proposal>
    where
        F: Fn(&crate::wallet_node::WalletUtxo) -> Result<bdk_wallet::bitcoin::secp256k1::SecretKey>,
    {
        use crate::snicker::tweak::{
            calculate_dh_shared_secret, compute_proposal_tag, decrypt_proposal_v1,
        };

        // Get secret key for this UTXO using unified derivation
        let our_seckey = derive_privkey(utxo)?;

        // Calculate shared secret = ECDH(our_seckey, ephemeral_pubkey)
        let shared_secret = calculate_dh_shared_secret(&our_seckey, &encrypted.ephemeral_pubkey);

        // Calculate expected tag
        let expected_tag = compute_proposal_tag(&shared_secret);

        // Check if tags match
        if expected_tag != encrypted.tag {
            return Err(anyhow::anyhow!("Tag mismatch - proposal not for this UTXO"));
        }

        // Try to decrypt (v1 format with flags)
        let (flags, decrypted_bytes) = decrypt_proposal_v1(&encrypted.encrypted_data, &shared_secret)?;

        // Log flags if any are set (currently should be 0)
        if flags != ProposalFlags::NONE {
            tracing::info!("📋 Proposal has flags set: 0x{:08x}", flags);
        }

        // Deserialize the proposal
        let proposal = serde_json::from_slice::<Proposal>(&decrypted_bytes)?;

        Ok(proposal)
    }

    /// Removed: get_all_snicker_proposals() no longer needed
    /// Proposals are decrypted at storage time and queried from decrypted_proposals table

    /// Clear all SNICKER proposals from the database
    pub async fn clear_snicker_proposals(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count = conn.execute("DELETE FROM decrypted_proposals", [])?;
        tracing::info!("🗑️  Cleared {} proposals from database", count);
        Ok(count)
    }

    // ============================================================
    // Decrypted Proposals Methods
    // ============================================================

    /// Store a decrypted proposal in the database
    pub async fn store_decrypted_proposal(
        &self,
        proposal: &Proposal,
        role: &str,  // "proposer" or "receiver"
        our_utxo: &str,  // "txid:vout"
        counterparty_utxo: &str,  // "txid:vout"
        delta_sats: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        let psbt_bytes = proposal.psbt.serialize();
        let tweak_info_bytes = serde_json::to_vec(&proposal.tweak_info)?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        let rows_affected = conn.execute(
            "INSERT OR IGNORE INTO decrypted_proposals
             (tag, psbt, tweak_info, role, status, our_utxo, counterparty_utxo, delta_sats, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            (
                &proposal.tag[..],
                &psbt_bytes,
                &tweak_info_bytes,
                role,
                "pending",
                our_utxo,
                counterparty_utxo,
                delta_sats,
                timestamp,
                timestamp,
            ),
        )?;

        if rows_affected == 0 {
            tracing::debug!("Proposal tag {} already exists in database, skipping",
                          ::hex::encode(&proposal.tag));
        }

        Ok(())
    }

    /// Get decrypted proposals filtered by delta range and status
    pub async fn get_decrypted_proposals_by_delta_range(
        &self,
        min_delta: i64,
        max_delta: i64,
        status: &str,  // e.g., "pending"
    ) -> Result<Vec<Proposal>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT tag, psbt, tweak_info FROM decrypted_proposals
             WHERE delta_sats BETWEEN ?1 AND ?2 AND status = ?3
             ORDER BY created_at DESC"
        )?;

        let proposals = stmt.query_map((min_delta, max_delta, status), |row| {
            let tag_bytes: Vec<u8> = row.get(0)?;
            let psbt_bytes: Vec<u8> = row.get(1)?;
            let tweak_info_bytes: Vec<u8> = row.get(2)?;

            let mut tag = [0u8; 8];
            tag.copy_from_slice(&tag_bytes);

            let psbt: Psbt = Psbt::deserialize(&psbt_bytes)
                .map_err(|e| bdk_wallet::rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            let tweak_info: TweakInfo = serde_json::from_slice(&tweak_info_bytes)
                .map_err(|e| bdk_wallet::rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            Ok(Proposal { tag, psbt, tweak_info })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(proposals)
    }

    /// Get a specific decrypted proposal by tag
    pub async fn get_decrypted_proposal_by_tag(&self, tag: &[u8; 8]) -> Result<Option<Proposal>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT psbt, tweak_info FROM decrypted_proposals WHERE tag = ?1"
        )?;

        let result = stmt.query_row([&tag[..]], |row| {
            let psbt_bytes: Vec<u8> = row.get(0)?;
            let tweak_info_bytes: Vec<u8> = row.get(1)?;

            let psbt: Psbt = Psbt::deserialize(&psbt_bytes)
                .map_err(|e| bdk_wallet::rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            let tweak_info: TweakInfo = serde_json::from_slice(&tweak_info_bytes)
                .map_err(|e| bdk_wallet::rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            Ok(Proposal { tag: *tag, psbt, tweak_info })
        });

        match result {
            Ok(proposal) => Ok(Some(proposal)),
            Err(bdk_wallet::rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get a proposal for a specific UTXO pair and role (for deduplication)
    /// Returns the existing proposal if we already created/received one for this pair
    pub async fn get_proposal_for_utxo_pair(
        &self,
        our_utxo: &str,
        counterparty_utxo: &str,
        role: &str,
    ) -> Result<Option<Proposal>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT tag, psbt, tweak_info FROM decrypted_proposals
             WHERE our_utxo = ?1 AND counterparty_utxo = ?2 AND role = ?3
             LIMIT 1"
        )?;

        let result = stmt.query_row((our_utxo, counterparty_utxo, role), |row| {
            let tag_bytes: Vec<u8> = row.get(0)?;
            let psbt_bytes: Vec<u8> = row.get(1)?;
            let tweak_info_bytes: Vec<u8> = row.get(2)?;

            let mut tag = [0u8; 8];
            if tag_bytes.len() != 8 {
                return Err(bdk_wallet::rusqlite::Error::InvalidQuery);
            }
            tag.copy_from_slice(&tag_bytes);

            let psbt: Psbt = Psbt::deserialize(&psbt_bytes)
                .map_err(|e| bdk_wallet::rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            let tweak_info: TweakInfo = serde_json::from_slice(&tweak_info_bytes)
                .map_err(|e| bdk_wallet::rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            Ok(Proposal { tag, psbt, tweak_info })
        });

        match result {
            Ok(proposal) => Ok(Some(proposal)),
            Err(bdk_wallet::rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Update the status of a decrypted proposal
    pub async fn update_proposal_status(&self, tag: &[u8; 8], new_status: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        conn.execute(
            "UPDATE decrypted_proposals SET status = ?1, updated_at = ?2 WHERE tag = ?3",
            (new_status, timestamp, &tag[..]),
        )?;

        Ok(())
    }

    // ============================================================
    // Helper Methods
    // ============================================================

    /// Calculate delta from a proposal's PSBT
    /// Delta = receiver's contribution (how much receiver loses)
    /// Positive delta = receiver contributes/loses sats
    /// Negative delta = receiver gains sats (proposer incentivizes)
    pub fn calculate_delta_from_proposal(&self, proposal: &Proposal) -> Result<i64> {
        // Receiver's input value (what they're putting in)
        let receiver_input_value = proposal.tweak_info.original_output.value.to_sat();

        // Find receiver's output by matching the tweaked script_pubkey
        // The receiver's output is the one with the tweaked script pubkey
        let tweaked_script = &proposal.tweak_info.tweaked_output.script_pubkey;
        let receiver_output = proposal.psbt.unsigned_tx.output.iter()
            .find(|output| &output.script_pubkey == tweaked_script)
            .ok_or_else(|| anyhow::anyhow!("Could not find receiver's output in transaction"))?;

        let receiver_output_value = receiver_output.value.to_sat();

        // Delta = contribution = input - output
        // Positive means receiver loses (contributes), negative means receiver gains
        let delta = receiver_input_value as i64 - receiver_output_value as i64;

        Ok(delta)
    }

    /// Extract proposer's UTXO from a proposal's PSBT
    pub fn extract_proposer_utxo(&self, proposal: &Proposal) -> Result<String> {
        let proposer_input = proposal.psbt.unsigned_tx.input.first()
            .ok_or_else(|| anyhow::anyhow!("No inputs in PSBT"))?;

        Ok(format!("{}:{}", proposer_input.previous_output.txid, proposer_input.previous_output.vout))
    }

    /// Extract receiver's UTXO from a proposal's tweak info
    pub fn extract_receiver_utxo(&self, _proposal: &Proposal, target_tx: &Transaction, output_index: usize) -> Result<String> {
        let txid = target_tx.compute_txid();
        Ok(format!("{}:{}", txid, output_index))
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
        let conn = self.conn.lock().unwrap();

        // Store raw script bytes (not consensus-encoded, which adds length prefix)
        let script_pubkey_bytes = script_pubkey.to_bytes();
        let tweaked_privkey_bytes = tweaked_privkey.secret_bytes();

        conn.execute(
            "INSERT OR REPLACE INTO snicker_utxos
             (txid, vout, amount, script_pubkey, tweaked_privkey, snicker_shared_secret, block_height, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'unspent')",
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
        drop(conn);

        tracing::info!("💾 Stored SNICKER UTXO: {}:{} ({} sats)", txid, vout, amount);

        // Flush to encrypted file after UTXO change
        self.flush_db()?;

        Ok(())
    }

    /// Get the total balance of unspent SNICKER UTXOs
    pub async fn get_snicker_balance(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap();

        let balance: i64 = conn.query_row(
            "SELECT COALESCE(SUM(amount), 0) FROM snicker_utxos WHERE status = 'unspent'",
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
             WHERE status = 'unspent'
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
            let txid = bdk_wallet::bitcoin::Txid::from_str(&txid_str)?;
            // ScriptPubKey is stored as raw bytes (not consensus-encoded)
            let script_pubkey = bdk_wallet::bitcoin::ScriptBuf::from_bytes(script_bytes);
            // Wrap in Zeroizing so intermediate bytes are zeroed after SecretKey is created
            let privkey_bytes = Zeroizing::new(privkey_bytes);
            let tweaked_privkey = bdk_wallet::bitcoin::secp256k1::SecretKey::from_slice(&privkey_bytes)?;

            // Wrap shared secret bytes in Zeroizing for secure cleanup
            let secret_bytes = Zeroizing::new(secret_bytes);
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
            "UPDATE snicker_utxos SET status = 'spent', spent_in_txid = ?1 WHERE txid = ?2 AND vout = ?3",
            (spent_in_txid.to_string(), txid.to_string(), vout),
        )?;

        tracing::info!("Marked SNICKER UTXO {}:{} as SPENT (confirmed) in {}", txid, vout, spent_in_txid);
        Ok(())
    }

    // ============================================================
    // PENDING TRANSACTION TRACKING
    // ============================================================

    /// Store a pending transaction after broadcast (for tracking unconfirmed state)
    pub fn store_pending_transaction(
        &self,
        txid: &str,
        inputs: &[(String, u32, u64)], // (txid, vout, amount_sats)
        total_output_sats: u64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        Self::store_pending_transaction_raw(&conn, txid, inputs, total_output_sats)
    }

    /// Store a pending transaction (raw connection version for use without Snicker instance)
    pub fn store_pending_transaction_raw(
        conn: &Connection,
        txid: &str,
        inputs: &[(String, u32, u64)], // (txid, vout, amount_sats)
        total_output_sats: u64,
    ) -> Result<()> {
        let broadcast_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let total_input_sats: u64 = inputs.iter().map(|(_, _, amt)| amt).sum();
        let fee_sats = total_input_sats.saturating_sub(total_output_sats);

        conn.execute(
            "INSERT OR REPLACE INTO pending_transactions (txid, broadcast_time, total_input_sats, total_output_sats, fee_sats)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (txid, broadcast_time, total_input_sats as i64, total_output_sats as i64, fee_sats as i64),
        )?;

        for (spent_txid, spent_vout, amount) in inputs {
            conn.execute(
                "INSERT OR REPLACE INTO pending_inputs (spending_txid, spent_txid, spent_vout, amount_sats)
                 VALUES (?1, ?2, ?3, ?4)",
                (txid, spent_txid, spent_vout, *amount as i64),
            )?;
        }

        tracing::debug!("Stored pending transaction {} with {} inputs", txid, inputs.len());
        Ok(())
    }

    /// Check if an outpoint is spent by a pending (unconfirmed) transaction
    pub fn is_outpoint_pending_spent(&self, txid: &str, vout: u32) -> bool {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT 1 FROM pending_inputs WHERE spent_txid = ?1 AND spent_vout = ?2",
            (txid, vout),
            |_| Ok(()),
        ).is_ok()
    }

    /// Get all pending spent outpoints (for UTXO list display)
    pub fn get_pending_spent_outpoints(&self) -> Vec<(String, u32, u64, String)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = match conn.prepare(
            "SELECT spent_txid, spent_vout, amount_sats, spending_txid FROM pending_inputs"
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let mut result = Vec::new();
        let mut rows = match stmt.query([]) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        while let Ok(Some(row)) = rows.next() {
            if let (Ok(txid), Ok(vout), Ok(amount), Ok(spending_txid)) = (
                row.get::<_, String>(0),
                row.get::<_, u32>(1),
                row.get::<_, i64>(2),
                row.get::<_, String>(3),
            ) {
                result.push((txid, vout, amount as u64, spending_txid));
            }
        }
        result
    }

    /// Get pending balance info: (pending_outgoing_sats, pending_incoming_snicker_sats)
    pub fn get_pending_balance(&self) -> (u64, u64) {
        let conn = self.conn.lock().unwrap();

        // Pending outgoing: sum of all inputs in pending transactions
        let pending_outgoing: i64 = conn.query_row(
            "SELECT COALESCE(SUM(amount_sats), 0) FROM pending_inputs",
            [],
            |row| row.get(0),
        ).unwrap_or(0);

        // Pending incoming SNICKER: UTXOs with block_height IS NULL (broadcast but unconfirmed)
        let pending_incoming_snicker: i64 = conn.query_row(
            "SELECT COALESCE(SUM(amount), 0) FROM snicker_utxos WHERE block_height IS NULL AND status = 'unspent'",
            [],
            |row| row.get(0),
        ).unwrap_or(0);

        (pending_outgoing as u64, pending_incoming_snicker as u64)
    }

    /// Remove a confirmed transaction from pending tracking
    pub fn remove_confirmed_transaction(&self, txid: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        Self::remove_confirmed_transaction_raw(&conn, txid)
    }

    /// Remove a confirmed transaction (raw connection version)
    pub fn remove_confirmed_transaction_raw(conn: &Connection, txid: &str) -> Result<()> {
        // Delete from pending_inputs first (due to foreign key)
        conn.execute(
            "DELETE FROM pending_inputs WHERE spending_txid = ?1",
            [txid],
        )?;

        conn.execute(
            "DELETE FROM pending_transactions WHERE txid = ?1",
            [txid],
        )?;

        tracing::debug!("Removed confirmed transaction {} from pending tracking", txid);
        Ok(())
    }

    /// Get all pending transaction txids
    pub fn get_pending_txids_raw(conn: &Connection) -> Vec<String> {
        let mut stmt = match conn.prepare("SELECT txid FROM pending_transactions") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let mut result = Vec::new();
        let mut rows = match stmt.query([]) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        while let Ok(Some(row)) = rows.next() {
            if let Ok(txid) = row.get::<_, String>(0) {
                result.push(txid);
            }
        }
        result
    }

    /// Get count of pending transactions
    pub fn get_pending_transaction_count(&self) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM pending_transactions",
            [],
            |row| row.get::<_, i64>(0),
        ).unwrap_or(0) as usize
    }

    // ============================================================
    // PROPOSAL PAIRINGS (tracking UTXOs with live proposals)
    // ============================================================

    /// Record that we created a proposal pairing our UTXO with a target UTXO
    pub fn record_proposal_pairing(
        &self,
        our_outpoint: &bdk_wallet::bitcoin::OutPoint,
        target_outpoint: &bdk_wallet::bitcoin::OutPoint,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        conn.execute(
            "INSERT OR IGNORE INTO proposal_pairings (our_txid, our_vout, target_txid, target_vout, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                our_outpoint.txid.to_string(),
                our_outpoint.vout,
                target_outpoint.txid.to_string(),
                target_outpoint.vout,
                timestamp,
            ),
        )?;

        tracing::debug!(
            "Recorded proposal pairing: {}:{} -> {}:{}",
            our_outpoint.txid, our_outpoint.vout,
            target_outpoint.txid, target_outpoint.vout
        );
        Ok(())
    }

    /// Check if our UTXO has any live proposals (for GUI display)
    pub fn has_live_proposals(&self, our_outpoint: &bdk_wallet::bitcoin::OutPoint) -> bool {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT 1 FROM proposal_pairings WHERE our_txid = ? AND our_vout = ? LIMIT 1",
            (our_outpoint.txid.to_string(), our_outpoint.vout),
            |_| Ok(true),
        ).unwrap_or(false)
    }

    /// Delete all pairings where the target UTXO matches (called when target is spent)
    pub fn delete_pairings_for_target(conn: &Connection, target_txid: &str, target_vout: u32) -> usize {
        match conn.execute(
            "DELETE FROM proposal_pairings WHERE target_txid = ? AND target_vout = ?",
            (target_txid, target_vout),
        ) {
            Ok(count) => {
                if count > 0 {
                    tracing::debug!(
                        "Deleted {} proposal pairings for spent target {}:{}",
                        count, target_txid, target_vout
                    );
                }
                count
            }
            Err(e) => {
                tracing::warn!("Failed to delete proposal pairings: {}", e);
                0
            }
        }
    }

    /// Delete all pairings where our UTXO matches (called when our UTXO is spent)
    pub fn delete_pairings_for_our_utxo(conn: &Connection, our_txid: &str, our_vout: u32) -> usize {
        match conn.execute(
            "DELETE FROM proposal_pairings WHERE our_txid = ? AND our_vout = ?",
            (our_txid, our_vout),
        ) {
            Ok(count) => {
                if count > 0 {
                    tracing::debug!(
                        "Deleted {} proposal pairings for spent UTXO {}:{}",
                        count, our_txid, our_vout
                    );
                }
                count
            }
            Err(e) => {
                tracing::warn!("Failed to delete proposal pairings: {}", e);
                0
            }
        }
    }

    // ============================================================
    // AUTOMATION STATE
    // ============================================================

    /// Get the current automation state from database
    /// Returns default state (Proposer, height 0) if no state exists
    pub fn get_automation_state(&self) -> AutomationState {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT mode, last_coinjoin_height FROM automation_state WHERE id = 1",
            [],
            |row| {
                let mode_str: String = row.get(0)?;
                let height: u32 = row.get(1)?;
                let role = mode_str.parse::<AutomationRole>().unwrap_or(AutomationRole::Proposer);
                Ok(AutomationState {
                    role,
                    last_coinjoin_height: height,
                })
            },
        ).unwrap_or_default()
    }

    /// Set the automation state in database
    pub fn set_automation_state(&self, state: &AutomationState) -> Result<()> {
        {
            let conn = self.conn.lock().unwrap();
            Self::set_automation_state_static(&conn, state)?;
        } // Drop lock before flush_db
        self.flush_db()?;
        Ok(())
    }

    /// Initialize automation state if it doesn't exist
    /// Sets to Proposer role with the given initial height
    /// Returns true if state was initialized, false if it already existed
    pub fn initialize_automation_state(&self, initial_height: u32) -> Result<bool> {
        let state = self.get_automation_state();
        if state.last_coinjoin_height == 0 {
            // No state exists, initialize with Proposer role
            let new_state = AutomationState {
                role: AutomationRole::Proposer,
                last_coinjoin_height: initial_height,
            };
            self.set_automation_state(&new_state)?;
            tracing::info!(
                "Initialized automation state: Proposer mode, base height {}",
                initial_height
            );
            Ok(true)
        } else {
            tracing::debug!(
                "Automation state already exists: {:?} at height {}",
                state.role, state.last_coinjoin_height
            );
            Ok(false)
        }
    }

    /// Get automation state (static version for use with raw connection)
    pub fn get_automation_state_static(conn: &Connection) -> AutomationState {
        conn.query_row(
            "SELECT mode, last_coinjoin_height FROM automation_state WHERE id = 1",
            [],
            |row| {
                let mode_str: String = row.get(0)?;
                let height: u32 = row.get(1)?;
                let role = mode_str.parse::<AutomationRole>().unwrap_or(AutomationRole::Proposer);
                Ok(AutomationState {
                    role,
                    last_coinjoin_height: height,
                })
            },
        ).unwrap_or_default()
    }

    /// Set automation state (static version for use with raw connection)
    pub fn set_automation_state_static(conn: &Connection, state: &AutomationState) -> Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        conn.execute(
            "INSERT INTO automation_state (id, mode, last_coinjoin_height, updated_at)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                mode = excluded.mode,
                last_coinjoin_height = excluded.last_coinjoin_height,
                updated_at = excluded.updated_at",
            (state.role.as_str(), state.last_coinjoin_height, timestamp),
        )?;

        tracing::info!(
            "Updated automation state: role={}, last_coinjoin_height={}",
            state.role, state.last_coinjoin_height
        );

        Ok(())
    }

    /// Perform coin flip and update state after a successful coinjoin
    /// Returns the new role
    pub fn on_coinjoin_confirmed(&self, block_height: u32) -> Result<AutomationRole> {
        let new_role = AutomationRole::coin_flip();
        let new_state = AutomationState {
            role: new_role,
            last_coinjoin_height: block_height,
        };

        self.set_automation_state(&new_state)?;
        tracing::info!(
            "Coinjoin confirmed at height {}. Coin flip result: {}",
            block_height, new_role
        );

        Ok(new_role)
    }

    /// Check if receiver timeout has elapsed and reroll if needed
    /// Returns Some(new_role) if reroll occurred, None otherwise
    pub fn check_receiver_timeout(&self, current_height: u32, timeout_blocks: u32) -> Result<Option<AutomationRole>> {
        let state = self.get_automation_state();

        // Only applies when in Receiver mode
        if state.role != AutomationRole::Receiver {
            return Ok(None);
        }

        let blocks_since_coinjoin = current_height.saturating_sub(state.last_coinjoin_height);

        if blocks_since_coinjoin >= timeout_blocks {
            let new_role = AutomationRole::coin_flip();
            let new_state = AutomationState {
                role: new_role,
                last_coinjoin_height: state.last_coinjoin_height, // Don't update height on timeout
            };

            self.set_automation_state(&new_state)?;
            tracing::info!(
                "Receiver timeout after {} blocks (threshold: {}). Coin flip result: {}",
                blocks_since_coinjoin, timeout_blocks, new_role
            );

            Ok(Some(new_role))
        } else {
            tracing::debug!(
                "Receiver mode: {} blocks since last coinjoin (timeout at {})",
                blocks_since_coinjoin, timeout_blocks
            );
            Ok(None)
        }
    }

    /// Get the number of outstanding proposals (for maintaining N proposals)
    pub fn count_outstanding_proposals(&self) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(DISTINCT our_txid || ':' || our_vout) FROM proposal_pairings",
            [],
            |row| row.get::<_, i64>(0),
        ).map(|c| c as usize).unwrap_or(0)
    }

    // ============================================================
    // COINJOIN SPENDING TRACKING
    // ============================================================

    /// Record a completed coinjoin and its delta (sats spent/received)
    /// delta_sats > 0 means we paid sats, < 0 means we received sats
    pub fn record_coinjoin_spending(
        &self,
        delta_sats: i64,
        role: &str,
        txid: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        conn.execute(
            "INSERT INTO coinjoin_spending (timestamp, delta_sats, role, txid)
             VALUES (?1, ?2, ?3, ?4)",
            (timestamp, delta_sats, role, txid),
        )?;

        tracing::info!(
            "Recorded coinjoin spending: {} sats (role: {}, txid: {})",
            delta_sats, role, txid
        );
        Ok(())
    }

    /// Record coinjoin spending (static version for use with raw connection)
    pub fn record_coinjoin_spending_static(
        conn: &Connection,
        delta_sats: i64,
        role: &str,
        txid: &str,
    ) -> Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        conn.execute(
            "INSERT INTO coinjoin_spending (timestamp, delta_sats, role, txid)
             VALUES (?1, ?2, ?3, ?4)",
            (timestamp, delta_sats, role, txid),
        )?;

        tracing::info!(
            "Recorded coinjoin spending: {} sats (role: {}, txid: {})",
            delta_sats, role, txid
        );
        Ok(())
    }

    /// Get total sats spent on coinjoins in the last N seconds
    /// Only counts positive deltas (where we paid sats)
    pub fn get_spending_since(&self, seconds: u64) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64 - seconds as i64;

        let spent: i64 = conn.query_row(
            "SELECT COALESCE(SUM(CASE WHEN delta_sats > 0 THEN delta_sats ELSE 0 END), 0)
             FROM coinjoin_spending
             WHERE timestamp >= ?1",
            [cutoff],
            |row| row.get(0),
        )?;

        Ok(spent.max(0) as u64)
    }

    /// Get spending for the last 24 hours
    pub fn get_spending_last_day(&self) -> Result<u64> {
        self.get_spending_since(86400) // 24 * 60 * 60
    }

    /// Get spending for the last 7 days
    pub fn get_spending_last_week(&self) -> Result<u64> {
        self.get_spending_since(604800) // 7 * 24 * 60 * 60
    }

    /// Check if a proposed coinjoin would exceed spending limits
    /// Returns Ok(true) if within limits, Ok(false) if would exceed
    pub fn check_spending_limits(
        &self,
        delta_sats: i64,
        max_per_coinjoin: u64,
        max_per_day: u64,
        max_per_week: u64,
    ) -> Result<bool> {
        // Only count positive deltas (where we're paying)
        if delta_sats <= 0 {
            return Ok(true); // No cost, always allowed
        }

        let delta_u64 = delta_sats as u64;

        // Check per-coinjoin limit
        if delta_u64 > max_per_coinjoin {
            tracing::info!(
                "Coinjoin delta {} sats exceeds per-coinjoin limit of {} sats",
                delta_u64, max_per_coinjoin
            );
            return Ok(false);
        }

        // Check daily limit
        let spent_today = self.get_spending_last_day()?;
        if spent_today + delta_u64 > max_per_day {
            tracing::info!(
                "Would exceed daily limit: {} + {} > {} sats",
                spent_today, delta_u64, max_per_day
            );
            return Ok(false);
        }

        // Check weekly limit
        let spent_week = self.get_spending_last_week()?;
        if spent_week + delta_u64 > max_per_week {
            tracing::info!(
                "Would exceed weekly limit: {} + {} > {} sats",
                spent_week, delta_u64, max_per_week
            );
            return Ok(false);
        }

        Ok(true)
    }

    // ============================================================
    // AUTOMATION & RATE LIMITING
    // ============================================================

    /// Log an automation action
    pub async fn log_automation_action(
        &self,
        action_type: &str,
        tag: Option<&[u8; 8]>,
        txid: Option<&bdk_wallet::bitcoin::Txid>,
        delta: Option<i64>,
        success: bool,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        conn.execute(
            "INSERT INTO automation_log (timestamp, action_type, tag, txid, delta, success)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                timestamp,
                action_type,
                tag.map(|t| t.to_vec()),
                txid.map(|t| t.to_string()),
                delta,
                success,
            ),
        )?;

        tracing::debug!("📝 Logged automation action: {} (success={})", action_type, success);
        Ok(())
    }

    /// Get count of successful actions of a specific type in the last N seconds
    pub async fn get_action_count_since(
        &self,
        action_type: &str,
        seconds_ago: i64,
    ) -> Result<u32> {
        let conn = self.conn.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let cutoff = now - seconds_ago;

        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM automation_log
             WHERE action_type = ?1 AND timestamp >= ?2 AND success = 1",
            (action_type, cutoff),
            |row| row.get(0),
        )?;

        Ok(count as u32)
    }

    /// Check if we're within rate limit for a specific action
    pub async fn check_rate_limit(
        &self,
        action_type: &str,
        max_per_day: u32,
    ) -> Result<bool> {
        let count = self.get_action_count_since(action_type, 86400).await?;  // 24 hours
        Ok(count < max_per_day)
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
    /// * `our_utxos` - Our wallet's UTXOs to use as proposer inputs (all UTXOs considered)
    /// * `candidates` - Candidate UTXOs from partial_utxo_set (already filtered by size)
    ///
    /// # Algorithm
    /// 1. Sort our UTXOs by value descending
    /// 2. For each UTXO:
    ///    - Filter candidates where output value < our UTXO value
    ///    - Add ALL matches to results list
    /// 3. Return complete list of opportunities
    pub fn find_opportunities(
        &self,
        our_utxos: &[crate::wallet_node::WalletUtxo],
        candidates: &[(Txid, u32, u32, u64, bdk_wallet::bitcoin::ScriptBuf)],
    ) -> Result<Vec<ProposalOpportunity>> {
        // 1. Sort our UTXOs by value descending
        let mut sorted_utxos: Vec<_> = our_utxos.to_vec();
        sorted_utxos.sort_by(|a, b| b.value().cmp(&a.value()));

        if sorted_utxos.is_empty() {
            tracing::info!("⚠️  No UTXOs available for SNICKER proposals");
            return Ok(Vec::new());
        }

        tracing::info!("🔍 Found {} UTXOs for SNICKER", sorted_utxos.len());

        // 2. Check candidates (now passed as parameter from partial_utxo_set query)

        if candidates.is_empty() {
            tracing::info!("⚠️  No SNICKER candidates in database.");
            return Ok(Vec::new());
        }

        tracing::info!("🔍 Scanning {} candidates against {} UTXOs",
              candidates.len(), sorted_utxos.len());

        // 3. For each UTXO, find ALL matching candidates
        let mut opportunities = Vec::new();

        for our_utxo in &sorted_utxos {
            let our_value = our_utxo.value();
            let our_outpoint = our_utxo.outpoint();
            let mut matches_for_this_utxo = 0;

            // Find all candidates where output value is in range [min_utxo_sats, our_value)
            // Candidates are now individual UTXOs (not full transactions)
            for (txid, vout, _height, amount, script_pubkey) in candidates {
                let candidate_outpoint = OutPoint {
                    txid: *txid,
                    vout: *vout,
                };

                // Skip if this is one of our own UTXOs
                if our_utxos.iter().any(|u| u.outpoint() == candidate_outpoint) {
                    continue;
                }

                // Skip if both UTXOs are from the same transaction
                // They're already in the same anonymity set, so proposing would be wasteful
                if our_outpoint.txid == candidate_outpoint.txid {
                    continue;
                }

                let candidate_amount = bdk_wallet::bitcoin::Amount::from_sat(*amount);

                // Only consider candidates smaller than our UTXO
                // (min amount and P2TR checks already done when querying candidates)
                if candidate_amount < our_value {
                    let candidate_txout = TxOut {
                        value: candidate_amount,
                        script_pubkey: script_pubkey.clone(),
                    };

                    opportunities.push(ProposalOpportunity {
                        our_outpoint,
                        our_value,
                        target_outpoint: candidate_outpoint,
                        target_txout: candidate_txout,
                    });
                    matches_for_this_utxo += 1;
                }
            }

            if matches_for_this_utxo > 0 {
                tracing::info!("  UTXO {}:{} ({} sats) → {} opportunities",
                      our_outpoint.txid, our_outpoint.vout,
                      our_value.to_sat(), matches_for_this_utxo);
            }
        }

        // Sort opportunities by our value (desc), then target value (desc)
        opportunities.sort_by(|a, b| {
            b.our_value.cmp(&a.our_value)
                .then(b.target_txout.value.cmp(&a.target_txout.value))
        });

        tracing::info!("🎯 Found {} total SNICKER opportunities", opportunities.len());

        Ok(opportunities)
    }

}

/// Opportunity for creating a SNICKER proposal
#[derive(Debug, Clone)]
pub struct ProposalOpportunity {
    /// Our UTXO to use as input
    pub our_outpoint: OutPoint,
    /// Our UTXO value
    pub our_value: bdk_wallet::bitcoin::Amount,
    /// Target (receiver's) UTXO outpoint
    pub target_outpoint: OutPoint,
    /// Target (receiver's) UTXO TxOut (amount + script)
    pub target_txout: TxOut,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::{
        Transaction, TxOut, Amount, ScriptBuf,
        transaction::Version, locktime::absolute::LockTime,
    };
    use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn create_test_snicker() -> Snicker {
        let db_path = std::env::temp_dir().join(format!(
            "test_snicker_{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Snicker::new_from_path(&db_path, Network::Regtest).unwrap()
    }

    fn create_test_transaction() -> Transaction {
        create_test_transaction_with_seed(2)
    }

    fn create_test_transaction_with_seed(seed: u64) -> Transaction {
        use bdk_wallet::bitcoin::secp256k1::rand::SeedableRng;

        let secp = Secp256k1::new();

        // Create a seeded RNG to generate valid keys deterministically
        let mut rng = bdk_wallet::bitcoin::secp256k1::rand::rngs::StdRng::seed_from_u64(seed);
        let secret_key = SecretKey::new(&mut rng);
        let public_key = secret_key.public_key(&secp);
        let internal_key = public_key.x_only_public_key().0;

        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![
                TxOut {
                    value: Amount::from_sat(50000),
                    script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
                }
            ],
        }
    }

    #[test]
    fn test_snicker_struct_creation() {
        let snicker = create_test_snicker();
        assert_eq!(snicker._network, Network::Regtest);
    }

    // ============================================================
    // CANDIDATE STORAGE TESTS - REMOVED
    // ============================================================
    // These tests were removed because candidates are no longer stored in a separate table.
    // Candidates are now queried directly from partial_utxo_set on-demand via
    // Manager::get_snicker_candidates() which filters by amount range and transaction type.

    // ============================================================
    // PROPOSAL STORAGE TESTS
    // ============================================================

    #[tokio::test]
    async fn test_store_created_proposal() {
        let snicker = create_test_snicker();
        let secp = Secp256k1::new();
        let mut rng = bdk_wallet::bitcoin::secp256k1::rand::thread_rng();

        let ephemeral_key = SecretKey::new(&mut rng);
        let ephemeral_pubkey = ephemeral_key.public_key(&secp);

        let proposal = EncryptedProposal {
            ephemeral_pubkey,
            tag: [0xAA; 8],
            version: SNICKER_VERSION_V1,
            encrypted_data: vec![1, 2, 3, 4, 5],
        };

        // Store created proposal (proposer side)
        snicker.store_created_proposal(&proposal).await.unwrap();

        // Note: Created proposals are stored for reference but not retrieved via get_all.
        // They're tracked in the database for the proposer to monitor their proposals.
    }

    #[tokio::test]
    async fn test_store_multiple_created_proposals() {
        let snicker = create_test_snicker();
        let secp = Secp256k1::new();
        let mut rng = bdk_wallet::bitcoin::secp256k1::rand::thread_rng();

        // Store 3 different created proposals (proposer side)
        for i in 0..3 {
            let ephemeral_key = SecretKey::new(&mut rng);
            let ephemeral_pubkey = ephemeral_key.public_key(&secp);

            let proposal = EncryptedProposal {
                ephemeral_pubkey,
                tag: [i as u8; 8],
                version: SNICKER_VERSION_V1,
                encrypted_data: vec![i as u8; 10],
            };

            snicker.store_created_proposal(&proposal).await.unwrap();
        }

        // Created proposals are stored but not retrieved en masse
        // They're for proposer-side tracking
    }

    #[tokio::test]
    async fn test_clear_proposals() {
        let snicker = create_test_snicker();

        // Clear any existing proposals (should return 0 for empty database)
        let count = snicker.clear_snicker_proposals().await.unwrap();
        assert_eq!(count, 0);

        // Note: Created proposals are not stored in the database
        // (store_created_proposal is a no-op), so we can't test clearing them.
        // Only decrypted proposals are stored and can be cleared.
    }

    #[tokio::test]
    async fn test_get_decrypted_proposals_empty_database() {
        let snicker = create_test_snicker();
        // Get decrypted proposals with a wide delta range
        let proposals = snicker.get_decrypted_proposals_by_delta_range(-10000, 10000, "pending").await.unwrap();
        assert_eq!(proposals.len(), 0);
    }

    // ============================================================
    // SNICKER UTXO STORAGE TESTS
    // ============================================================

    #[tokio::test]
    async fn test_store_and_retrieve_snicker_utxo() {
        let snicker = create_test_snicker();
        let secp = Secp256k1::new();
        let mut rng = bdk_wallet::bitcoin::secp256k1::rand::thread_rng();

        let txid = "0000000000000000000000000000000000000000000000000000000000000000"
            .parse().unwrap();
        let vout = 0;
        let amount = 50000;
        let internal_key = bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey::from_slice(&[2u8; 32])
            .unwrap();
        let script_pubkey = ScriptBuf::new_p2tr(&secp, internal_key, None);
        let tweaked_privkey = SecretKey::new(&mut rng);
        let snicker_shared_secret = [0xBB; 32];

        // Store UTXO
        snicker.store_snicker_utxo(
            txid,
            vout,
            amount,
            &script_pubkey,
            &tweaked_privkey,
            &snicker_shared_secret,
            Some(100),
        ).await.unwrap();

        // Retrieve UTXOs
        let utxos = snicker.list_snicker_utxos().await.unwrap();

        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].outpoint.txid, txid);
        assert_eq!(utxos[0].outpoint.vout, vout);
        assert_eq!(utxos[0].amount, amount);
        assert_eq!(utxos[0].script_pubkey, script_pubkey);
        assert_eq!(utxos[0].tweaked_privkey.secret_bytes(), tweaked_privkey.secret_bytes());
        assert_eq!(utxos[0].snicker_shared_secret, snicker_shared_secret);
        assert_eq!(utxos[0].block_height, Some(100));
    }

    #[tokio::test]
    async fn test_snicker_balance_calculation() {
        let snicker = create_test_snicker();
        let secp = Secp256k1::new();
        let mut rng = bdk_wallet::bitcoin::secp256k1::rand::thread_rng();

        let internal_key = bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey::from_slice(&[2u8; 32])
            .unwrap();
        let script_pubkey = ScriptBuf::new_p2tr(&secp, internal_key, None);
        let tweaked_privkey = SecretKey::new(&mut rng);
        let snicker_shared_secret = [0xCC; 32];

        // Store 3 UTXOs with different amounts
        let amounts = [10000, 20000, 30000];
        for (i, &amount) in amounts.iter().enumerate() {
            snicker.store_snicker_utxo(
                format!("{:064x}", i).parse().unwrap(),
                i as u32,
                amount,
                &script_pubkey,
                &tweaked_privkey,
                &snicker_shared_secret,
                None,
            ).await.unwrap();
        }

        // Check balance
        let balance = snicker.get_snicker_balance().await.unwrap();
        assert_eq!(balance, 60000); // Sum of all amounts
    }

    #[tokio::test]
    async fn test_snicker_balance_empty() {
        let snicker = create_test_snicker();
        let balance = snicker.get_snicker_balance().await.unwrap();
        assert_eq!(balance, 0);
    }

    #[tokio::test]
    async fn test_list_snicker_utxos_empty() {
        let snicker = create_test_snicker();
        let utxos = snicker.list_snicker_utxos().await.unwrap();
        assert_eq!(utxos.len(), 0);
    }

    #[tokio::test]
    async fn test_mark_snicker_utxo_spent() {
        let snicker = create_test_snicker();
        let secp = Secp256k1::new();
        let mut rng = bdk_wallet::bitcoin::secp256k1::rand::thread_rng();

        let txid = "0000000000000000000000000000000000000000000000000000000000000000"
            .parse().unwrap();
        let vout = 0;
        let internal_key = bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey::from_slice(&[2u8; 32])
            .unwrap();
        let script_pubkey = ScriptBuf::new_p2tr(&secp, internal_key, None);

        // Store UTXO
        snicker.store_snicker_utxo(
            txid,
            vout,
            50000,
            &script_pubkey,
            &SecretKey::new(&mut rng),
            &[0xDD; 32],
            Some(100),
        ).await.unwrap();

        // Mark as spent (need to provide the spending txid)
        let spending_txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap();
        snicker.mark_snicker_utxo_spent(txid, vout, spending_txid).await.unwrap();

        // list_snicker_utxos filters out spent UTXOs (WHERE status = 'unspent')
        let utxos = snicker.list_snicker_utxos().await.unwrap();
        assert_eq!(utxos.len(), 0, "Spent UTXOs should be filtered out");

        // Balance should now be 0 (spent UTXOs excluded)
        let balance = snicker.get_snicker_balance().await.unwrap();
        assert_eq!(balance, 0);
    }

    #[tokio::test]
    async fn test_small_change_dropped() {
        use bdk_wallet::bitcoin::{Network, FeeRate, Amount, TxOut, Address, OutPoint, Transaction, TxIn, Witness};
        use bdk_wallet::bitcoin::secp256k1::{Secp256k1, rand};
        use bdk_wallet::bitcoin::transaction::Version;
        use bdk_wallet::bitcoin::locktime::absolute::LockTime;
        use bdk_wallet::bitcoin::Sequence;

        let snicker = create_test_snicker();
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();

        // Create a receiver UTXO (10000 sats)
        let receiver_internal_key = bdk_wallet::bitcoin::secp256k1::SecretKey::new(&mut rng).x_only_public_key(&secp).0;
        let receiver_script = ScriptBuf::new_p2tr(&secp, receiver_internal_key, None);
        let receiver_output = TxOut {
            value: Amount::from_sat(10000),
            script_pubkey: receiver_script.clone(),
        };

        // Create receiver's target transaction
        let target_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![receiver_output.clone()],
        };

        // Set delta such that equal outputs are 9000 sats (10000 - 1000)
        let delta_sats = 1000i64;
        let equal_output_sats = 10000 - delta_sats; // = 9000 sats

        // Fee rate: 10 sat/vB
        // Fee for 2 inputs + 3 outputs = 255 vB × 10 = 2550 sats
        // Fee for 2 inputs + 2 outputs = 212 vB × 10 = 2120 sats
        let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
        let fee_3_outputs = 255 * 10; // 2550 sats
        let fee_2_outputs = 212 * 10; // 2120 sats

        // Calculate proposer UTXO size needed to create change between 546 and 2730
        // Total out (2 equal outputs) = 2 × 9000 = 18000
        // Total in = receiver (10000) + proposer_amount
        // Change = total_in - total_out - fee_3_outputs
        //        = 10000 + proposer_amount - 18000 - 2550
        //        = proposer_amount - 10550
        // We want: 546 ≤ change < 2730
        // So: 546 ≤ proposer_amount - 10550 < 2730
        //     11096 ≤ proposer_amount < 13280
        // Let's use 11500, which gives change = 950 sats
        let proposer_amount = Amount::from_sat(11500);
        let expected_change_3_outputs = 10000 + 11500 - 18000 - fee_3_outputs;
        println!("Expected change with 3 outputs: {} sats", expected_change_3_outputs);
        assert!(expected_change_3_outputs >= 546 && expected_change_3_outputs < 2730,
                "Test setup error: change should be between 546 and 2730");

        // Create proposer UTXO and addresses
        let proposer_internal_key = bdk_wallet::bitcoin::secp256k1::SecretKey::new(&mut rng).x_only_public_key(&secp).0;
        let proposer_script = ScriptBuf::new_p2tr(&secp, proposer_internal_key, None);
        let proposer_txout = TxOut {
            value: proposer_amount,
            script_pubkey: proposer_script,
        };

        let proposer_equal_addr = Address::from_script(&receiver_script, Network::Regtest).unwrap();
        let proposer_change_addr = Address::from_script(&receiver_script, Network::Regtest).unwrap();

        // Call build_equal_outputs_structure with min_change_output_size
        let min_change_output_size = crate::config::DEFAULT_MIN_CHANGE_OUTPUT_SIZE;
        let result = Snicker::build_equal_outputs_structure(
            &receiver_output,
            proposer_amount,
            delta_sats,
            fee_rate,
            receiver_output.clone(), // tweaked_output (simplified for test)
            proposer_equal_addr,
            proposer_change_addr,
            min_change_output_size,
        );

        assert!(result.is_ok(), "Should succeed with valid inputs");
        let (outputs, actual_fee) = result.unwrap();

        // Verify: should have only 2 outputs (no change)
        assert_eq!(outputs.len(), 2, "Should have 2 outputs (no change output)");

        // Verify: both outputs are equal-sized (9000 sats each)
        for output in &outputs {
            assert_eq!(output.value.to_sat(), 9000, "Both outputs should be 9000 sats");
        }

        // Verify: actual fee should be approximately fee_2_outputs + change_amount
        // expected_actual_fee = 2120 + 950 = 3070 sats
        let expected_actual_fee = fee_2_outputs + expected_change_3_outputs as u64;
        assert_eq!(actual_fee.to_sat(), expected_actual_fee,
                   "Actual fee should be base fee + dropped change amount");

        println!("✅ Test passed: change output {} sats was dropped, fee bumped to {} sats",
                 expected_change_3_outputs, actual_fee.to_sat());
    }

    // ============================================================
    // VERSIONING TESTS
    // ============================================================

    #[test]
    fn test_magic_bytes_constant() {
        assert_eq!(SNICKER_MAGIC, [0x53, 0x4E, 0x49, 0x43]); // "SNIC"
        assert_eq!(SNICKER_VERSION_V1, 0x01);
    }

    #[test]
    fn test_validate_proposal_header_valid() {
        let mut data = Vec::new();
        data.extend_from_slice(&SNICKER_MAGIC);
        data.push(SNICKER_VERSION_V1);
        data.extend_from_slice(&[0xAA; 10]); // Some encrypted data

        let result = validate_proposal_header(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), SNICKER_VERSION_V1);
    }

    #[test]
    fn test_validate_proposal_header_too_short() {
        let data = vec![0x53, 0x4E, 0x49]; // Only 3 bytes
        let result = validate_proposal_header(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_validate_proposal_header_invalid_magic() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // Wrong magic
        data.push(SNICKER_VERSION_V1);
        data.extend_from_slice(&[0xAA; 10]);

        let result = validate_proposal_header(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid magic bytes"));
    }

    #[test]
    fn test_validate_proposal_header_unknown_version() {
        let mut data = Vec::new();
        data.extend_from_slice(&SNICKER_MAGIC);
        data.push(0x99); // Unknown version
        data.extend_from_slice(&[0xAA; 10]);

        let result = validate_proposal_header(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported proposal version"));
    }

    #[test]
    fn test_extract_proposal_blob() {
        let mut data = Vec::new();
        data.extend_from_slice(&SNICKER_MAGIC);
        data.push(SNICKER_VERSION_V1);
        let encrypted_data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        data.extend_from_slice(&encrypted_data);

        let result = extract_proposal_blob(&data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), encrypted_data);
    }

    #[test]
    fn test_wrap_proposal_blob() {
        let encrypted_data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let wrapped = wrap_proposal_blob(SNICKER_VERSION_V1, &encrypted_data);

        // Should be: magic (4) + version (1) + data (4) = 9 bytes
        assert_eq!(wrapped.len(), 9);
        assert_eq!(&wrapped[0..4], &SNICKER_MAGIC);
        assert_eq!(wrapped[4], SNICKER_VERSION_V1);
        assert_eq!(&wrapped[5..], &encrypted_data[..]);
    }

    #[test]
    fn test_proposal_flags_creation() {
        let flags = ProposalFlags::none();
        assert_eq!(flags.0, 0x00000000);

        let flags = ProposalFlags::new(0x12345678);
        assert_eq!(flags.0, 0x12345678);

        let flags = ProposalFlags(ProposalFlags::NONE);
        assert_eq!(flags.0, 0);
    }

    #[test]
    fn test_round_trip_wrap_extract() {
        let original_data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let wrapped = wrap_proposal_blob(SNICKER_VERSION_V1, &original_data);
        let extracted = extract_proposal_blob(&wrapped).unwrap();

        assert_eq!(extracted, original_data);
    }

    #[test]
    fn test_encrypted_proposal_with_version() {
        use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let mut rng = bdk_wallet::bitcoin::secp256k1::rand::thread_rng();

        let ephemeral_key = SecretKey::new(&mut rng);
        let ephemeral_pubkey = ephemeral_key.public_key(&secp);

        let proposal = EncryptedProposal {
            ephemeral_pubkey,
            tag: [0xAA; 8],
            version: SNICKER_VERSION_V1,
            encrypted_data: vec![1, 2, 3, 4, 5],
        };

        assert_eq!(proposal.version, SNICKER_VERSION_V1);
        assert_eq!(proposal.tag, [0xAA; 8]);
        assert_eq!(proposal.encrypted_data, vec![1, 2, 3, 4, 5]);
    }

}
