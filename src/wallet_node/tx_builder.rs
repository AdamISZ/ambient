//! Transaction building, signing, and broadcasting
//!
//! This module contains all PSBT construction, signing coordination,
//! finalization, and broadcast logic for the wallet.

use anyhow::{anyhow, Result};
use tracing::info;
use zeroize::Zeroizing;

use bdk_wallet::{
    bitcoin::{Address, Amount, FeeRate, Transaction, Txid, psbt::Psbt},
    KeychainKind,
};
use bdk_kyoto::{TxBroadcast, TxBroadcastPolicy};

use super::WalletNode;
use super::coin_selection::SelectedUtxos;

impl WalletNode {
    // ============================================================
    // TRANSACTION BUILDING & SENDING
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
        use bdk_wallet::bitcoin::secp256k1::{Keypair, Secp256k1};

        info!("✍️  Signing PSBT with {} inputs", psbt.inputs.len());

        let secp = Secp256k1::new();

        // Get all our UTXOs to identify which inputs are ours
        let all_utxos = self.get_all_wallet_utxos().await?;

        // Collect prevouts for sighash calculation
        let prevouts: Vec<_> = psbt.inputs.iter()
            .map(|input| input.witness_utxo.clone()
                .ok_or_else(|| anyhow!("Missing witness_utxo")))
            .collect::<Result<Vec<_>>>()?;

        // Collect (input_idx, keypair) for all inputs we can sign
        let mut inputs_to_sign: Vec<(usize, Keypair)> = Vec::new();

        for (input_idx, input) in psbt.inputs.iter().enumerate() {
            // Skip if already signed
            if input.tap_key_sig.is_some() {
                continue;
            }

            let outpoint = psbt.unsigned_tx.input[input_idx].previous_output;

            // Check if this input is one of our UTXOs
            if let Some(utxo) = all_utxos.iter().find(|u| u.outpoint() == outpoint) {
                // Derive private key (works for both Regular and Snicker UTXOs)
                let privkey = match utxo {
                    super::WalletUtxo::Regular(_) => {
                        self.derive_utxo_privkey(utxo).await?
                    }
                    super::WalletUtxo::Snicker { outpoint, .. } => {
                        self.fetch_snicker_key(*outpoint).await?
                    }
                };

                inputs_to_sign.push((input_idx, privkey.keypair(&secp)));
                info!("    ✅ Prepared input {} for signing", input_idx);
            }
        }

        // Sign all collected inputs using the unified signing function
        let inputs_refs: Vec<(usize, &Keypair)> = inputs_to_sign
            .iter()
            .map(|(idx, kp)| (*idx, kp))
            .collect();
        crate::signer::sign_taproot_inputs(psbt, &inputs_refs, &prevouts)?;

        let signed_count = psbt.inputs.iter().filter(|i| i.tap_key_sig.is_some()).count();
        info!("✅ Signed {} of {} inputs", signed_count, psbt.inputs.len());

        // Return false for finalized - we're doing partial signing for multi-party PSBTs
        Ok(false)
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

    /// Send funds with automatic fee estimation (6-block target)
    ///
    /// Estimates optimal fee rate from mempool.space (or static defaults for regtest).
    /// Returns error if estimation fails - user must specify manual fee rate.
    pub async fn send_to_address_auto(&mut self, address_str: &str, amount_sats: u64) -> Result<Txid> {
        // Estimate fee rate for 6 blocks
        let fee_rate = self.fee_estimator.estimate(6).await
            .map_err(|e| anyhow!(
                "Fee estimation failed: {}.\nPlease specify a manual fee rate using: send <address> <amount> <fee_rate_sat_vb>",
                e
            ))? as f32;

        info!("📊 Using estimated fee rate: {:.2} sat/vB for ~6 blocks", fee_rate);
        self.send_to_address(address_str, amount_sats, fee_rate).await
    }

    /// Convenience method: Build, sign, finalize, and broadcast a transaction in one step with manual fee rate.
    /// This is the simple "send" interface for basic usage.
    ///
    /// HYBRID VERSION: Uses SNICKER UTXOs up to available amount, then fills remainder with regular UTXOs
    pub async fn send_to_address(
        &mut self,
        address_str: &str,
        amount_sats: u64,
        fee_rate_sat_vb: f32,
    ) -> Result<Txid> {
        // Use hybrid approach: SNICKER UTXOs first, then regular UTXOs as needed
        info!("💰 Using hybrid UTXO selection (SNICKER + regular as needed)");

        // Build and sign transaction
        let (tx, selected) = self.build_and_sign_hybrid_tx(address_str, amount_sats, fee_rate_sat_vb).await?;
        let txid = tx.compute_txid();

        // Broadcast transaction
        info!("Broadcasting transaction...");
        self.broadcast_transaction(tx.clone()).await?;

        // Store pending transaction for tracking (confirmed vs pending balance)
        let inputs: Vec<(String, u32, u64)> = {
            let mut inputs = Vec::new();
            // Add SNICKER inputs
            for (txid_str, vout, amount, _, _) in &selected.snicker_utxos {
                inputs.push((txid_str.clone(), *vout, *amount));
            }
            // Add regular inputs
            for utxo in &selected.regular_utxos {
                inputs.push((
                    utxo.outpoint.txid.to_string(),
                    utxo.outpoint.vout,
                    utxo.txout.value.to_sat(),
                ));
            }
            inputs
        };
        let total_output_sats: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        {
            let snicker_conn = self.snicker_conn.lock().unwrap();
            // Use the Snicker methods directly on the connection
            crate::snicker::Snicker::store_pending_transaction_raw(
                &snicker_conn,
                &txid.to_string(),
                &inputs,
                total_output_sats,
            )?;
        }
        info!("Tracking pending transaction {} with {} inputs", txid, inputs.len());

        // Update database state after successful broadcast
        // Mark SNICKER UTXOs as PENDING (not spent yet - waiting for confirmation)
        // Spend detection happens via block scanning (see background_sync)
        if !selected.snicker_utxos.is_empty() {
            for (txid_str, vout, _, _, _) in &selected.snicker_utxos {
                self.mark_snicker_utxo_pending(
                    txid_str,
                    *vout,
                    &txid.to_string(),
                ).await?;
            }
            info!("Marked {} SNICKER UTXOs as pending (awaiting confirmation)", selected.snicker_utxos.len());
        }

        // Persist wallet state (for regular UTXO tracking)
        if !selected.regular_utxos.is_empty() {
            let mut wallet = self.wallet.lock().await;
            let mut conn = self.conn.lock().await;
            wallet.persist(&mut conn)?;
            drop(conn);
            drop(wallet);
        }

        info!("Transaction broadcast successful");
        Ok(txid)
    }

    /// Calculate the maximum amount that can be sent (total balance minus fee)
    ///
    /// This uses all available UTXOs (both regular and SNICKER) and calculates
    /// the fee based on the transaction size with zero change outputs.
    ///
    /// # Arguments
    /// * `address_str` - Destination address (needed to determine output size)
    /// * `fee_rate_sat_vb` - Fee rate in sats per vbyte
    pub async fn calculate_max_sendable(&self, address_str: &str, fee_rate_sat_vb: f32) -> Result<u64> {
        use std::str::FromStr;

        // Parse and validate destination address
        let address = Address::from_str(address_str)?
            .require_network(self.network)?;

        // Get all available regular UTXOs
        let regular_utxos = {
            let wallet = self.wallet.lock().await;
            wallet.list_unspent().collect::<Vec<_>>()
        };

        // Get all available SNICKER UTXOs
        let snicker_utxos: Vec<(String, u32, u64)> = {
            let conn = self.snicker_conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT txid, vout, amount FROM snicker_utxos WHERE block_height IS NOT NULL AND status = 'unspent'"
            )?;
            let mut rows = stmt.query([])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                result.push((
                    row.get(0)?, row.get(1)?, row.get(2)?,
                ));
            }
            result
        };

        // Calculate total input amount
        let regular_total: u64 = regular_utxos.iter().map(|u| u.txout.value.to_sat()).sum();
        let snicker_total: u64 = snicker_utxos.iter().map(|(_, _, amount)| amount).sum();
        let total_input = regular_total + snicker_total;

        if total_input == 0 {
            return Ok(0);
        }

        // Calculate output size based on destination address type
        let script_pubkey = address.script_pubkey();
        let output_size = 8 + script_pubkey.len(); // 8 bytes for amount + script length

        // Calculate transaction size in vbytes
        // Taproot inputs: ~57.5 vbytes each (outpoint: 36, script: 1, sequence: 4, witness: ~65/4)
        let num_inputs = regular_utxos.len() + snicker_utxos.len();
        let base_size = 4 + 1 + 1 + 4; // version + input_count + output_count + locktime
        let input_size = num_inputs as f32 * 57.5; // Each Taproot input
        let total_vbytes = base_size as f32 + input_size + output_size as f32;

        // Calculate fee
        let fee = (total_vbytes * fee_rate_sat_vb).ceil() as u64;

        // Maximum sendable is total input minus fee
        if fee >= total_input {
            Ok(0)
        } else {
            Ok(total_input - fee)
        }
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
        use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey};
        
        use std::str::FromStr;

        // Parse address
        let address = Address::from_str(address_str)?
            .require_network(self.network)?;

        // Get available SNICKER UTXOs
        // Note: tweaked_privkey is wrapped in Zeroizing to ensure it's zeroed on drop
        let snicker_utxos: Vec<(String, u32, u64, Vec<u8>, Zeroizing<Vec<u8>>)> = {
            let conn = self.snicker_conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT txid, vout, amount, script_pubkey, tweaked_privkey FROM snicker_utxos WHERE block_height IS NOT NULL AND status = 'unspent'"
            )?;
            let mut rows = stmt.query([])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                result.push((
                    row.get(0)?, row.get(1)?, row.get(2)?,
                    row.get(3)?, Zeroizing::new(row.get(4)?),
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
        use bdk_wallet::bitcoin::secp256k1::{Keypair, PublicKey, XOnlyPublicKey};
        let secp = Secp256k1::new();

        // Collect keypairs and run sanity checks
        let mut inputs_to_sign: Vec<(usize, Keypair)> = Vec::new();

        for (i, (_, _, _, script_pubkey, tweaked_privkey_bytes)) in selected_utxos.iter().enumerate() {
            // Deserialize tweaked private key (SecretKey implements secure drop)
            let tweaked_seckey = SecretKey::from_slice(tweaked_privkey_bytes)?;
            let tweaked_keypair = Keypair::from_secret_key(&secp, &tweaked_seckey);

            // SANITY CHECK: Verify that tweaked_seckey * G = expected_pubkey
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
            inputs_to_sign.push((i, tweaked_keypair));
        }

        // Sign all inputs using the unified signing function
        let inputs_refs: Vec<(usize, &Keypair)> = inputs_to_sign
            .iter()
            .map(|(idx, kp)| (*idx, kp))
            .collect();
        crate::signer::sign_taproot_inputs(&mut psbt, &inputs_refs, &prevouts_for_sighash)?;

        for i in 0..inputs_to_sign.len() {
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

    /// Sign SNICKER inputs in a PSBT using their tweaked private keys
    /// Assumes SNICKER inputs are at indices [start_idx..start_idx+snicker_utxos.len())
    ///
    /// # Security Note
    /// This function handles sensitive private key material. The secp256k1::SecretKey type
    /// implements secure drop (zeroization) automatically when it goes out of scope.
    /// We ensure keys are dropped as soon as signing is complete by using tight scoping.
    /// The tweaked_privkey bytes are wrapped in Zeroizing to ensure they're zeroed on drop.
    pub(crate) fn sign_snicker_inputs(
        psbt: &mut bdk_wallet::bitcoin::psbt::Psbt,
        snicker_utxos: &[(String, u32, u64, Vec<u8>, Zeroizing<Vec<u8>>)],
        prevouts: &[bdk_wallet::bitcoin::TxOut],
        start_idx: usize,
    ) -> Result<()> {
        use bdk_wallet::bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

        let secp = Secp256k1::new();

        // Collect keypairs for all SNICKER inputs
        let mut inputs_to_sign: Vec<(usize, Keypair)> = Vec::new();

        for (i, (_, _, _, _script_pubkey, tweaked_privkey_bytes)) in snicker_utxos.iter().enumerate() {
            let input_idx = start_idx + i;
            let tweaked_seckey = SecretKey::from_slice(tweaked_privkey_bytes)?;
            let tweaked_keypair = Keypair::from_secret_key(&secp, &tweaked_seckey);
            inputs_to_sign.push((input_idx, tweaked_keypair));
        }

        // Sign all inputs using the unified signing function
        let inputs_refs: Vec<(usize, &Keypair)> = inputs_to_sign
            .iter()
            .map(|(idx, kp)| (*idx, kp))
            .collect();
        crate::signer::sign_taproot_inputs(psbt, &inputs_refs, prevouts)?;

        for (input_idx, _) in &inputs_to_sign {
            info!("✍️  Signed SNICKER input {}", input_idx);
        }

        Ok(())
    }

    /// Build and sign a transaction using hybrid UTXO selection
    /// Uses SNICKER UTXOs up to available amount, then fills remainder with regular UTXOs
    /// Returns the signed transaction ready for broadcast (does not broadcast)
    pub(crate) async fn build_and_sign_hybrid_tx(
        &mut self,
        address_str: &str,
        amount_sats: u64,
        fee_rate_sat_vb: f32,
    ) -> Result<(bdk_wallet::bitcoin::Transaction, SelectedUtxos)> {
        use bdk_wallet::bitcoin::{
            psbt::Psbt, transaction::Version, ScriptBuf, Sequence, TxIn, TxOut,
            OutPoint, Witness, absolute::LockTime, Network,
        };
        use std::str::FromStr;

        // Parse address
        let address = Address::from_str(address_str)?
            .require_network(self.network)?;

        // Step 1: Select UTXOs using hybrid selection algorithm
        let selected = self.select_utxos_hybrid(amount_sats, fee_rate_sat_vb).await?;
        let total_input = selected.total_snicker + selected.total_regular;

        // Step 2: Build transaction inputs
        let mut tx_inputs = Vec::new();
        let mut prevouts_for_sighash = Vec::new();

        // Add SNICKER inputs
        for (txid_str, vout, amount, script_pubkey, _) in &selected.snicker_utxos {
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

        // Add regular inputs
        for utxo in &selected.regular_utxos {
            tx_inputs.push(TxIn {
                previous_output: utxo.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });
            prevouts_for_sighash.push(utxo.txout.clone());
        }

        // Calculate fee and change
        let num_inputs = tx_inputs.len() as u64;
        let num_outputs = 2; // payment + change
        let estimated_vsize = 11 + (num_inputs * 57) + (num_outputs * 43);
        let estimated_fee = estimated_vsize * fee_rate_sat_vb as u64;
        let change_amount = total_input.saturating_sub(amount_sats + estimated_fee);

        info!("📊 Transaction: {} inputs ({} SNICKER + {} regular), total input {} sats, amount {} sats, fee {} sats, change {} sats",
              num_inputs, selected.snicker_utxos.len(), selected.regular_utxos.len(),
              total_input, amount_sats, estimated_fee, change_amount);

        // Build outputs
        let mut tx_outputs = vec![TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: address.script_pubkey(),
        }];

        // Add change output if any
        if change_amount > 0 {
            let mut wallet = self.wallet.lock().await;
            let mut conn = self.conn.lock().await;
            let change_addr = wallet.reveal_next_address(KeychainKind::Internal);
            wallet.persist(&mut conn)?;
            drop(conn);
            drop(wallet);
            tx_outputs.push(TxOut {
                value: Amount::from_sat(change_amount),
                script_pubkey: change_addr.script_pubkey(),
            });
            info!("💸 Change output: {} sats to {}", change_amount, change_addr.address);
        }

        // Create unsigned transaction
        let unsigned_tx = bdk_wallet::bitcoin::Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_inputs,
            output: tx_outputs,
        };

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

        // Step 3: Fill in witness_utxo for all inputs
        for (i, prevout) in prevouts_for_sighash.iter().enumerate() {
            psbt.inputs[i].witness_utxo = Some(prevout.clone());
        }

        // Step 3b: Fill in tap_key_origins for regular inputs so Signer can derive keys
        // Regular inputs start after SNICKER inputs
        let regular_start_idx = selected.snicker_utxos.len();
        let coin_type = if self.network == Network::Bitcoin { 0 } else { 1 };

        for (i, utxo) in selected.regular_utxos.iter().enumerate() {
            let input_idx = regular_start_idx + i;

            // Build full derivation path: m/86h/<cointype>h/0h/<change>/<index>
            let change = match utxo.keychain {
                KeychainKind::External => 0,
                KeychainKind::Internal => 1,
            };
            let full_path_str = format!("m/86h/{}h/0h/{}/{}", coin_type, change, utxo.derivation_index);
            let full_path = bdk_wallet::bitcoin::bip32::DerivationPath::from_str(&full_path_str)?;

            // Extract x-only public key from P2TR script_pubkey
            // P2TR script is: OP_1 <32-byte-xonly-pubkey>
            let script_bytes = utxo.txout.script_pubkey.as_bytes();
            if script_bytes.len() == 34 && script_bytes[0] == 0x51 && script_bytes[1] == 0x20 {
                let xonly_bytes: [u8; 32] = script_bytes[2..34].try_into()?;
                let xonly_pubkey = bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey::from_slice(&xonly_bytes)?;

                // Use dummy fingerprint - signer only needs the path
                let fingerprint = bdk_wallet::bitcoin::bip32::Fingerprint::default();

                psbt.inputs[input_idx].tap_key_origins.insert(
                    xonly_pubkey,
                    (vec![], (fingerprint, full_path)),
                );
            }
        }

        // Step 4: Sign SNICKER inputs using helper function
        if !selected.snicker_utxos.is_empty() {
            Self::sign_snicker_inputs(&mut psbt, &selected.snicker_utxos, &prevouts_for_sighash, 0)?;
        }

        // Step 5: Sign regular inputs using Signer abstraction
        // (tap_key_origins were populated above so signer can derive keys)
        if !selected.regular_utxos.is_empty() {
            info!("✍️  Signing {} regular inputs with Signer...", selected.regular_utxos.len());
            self.signer.sign_psbt(&mut psbt).await?;
            info!("✅ Regular inputs signed");
        }

        // Step 6: Finalize all inputs (move tap_key_sig to final_script_witness)
        for i in 0..psbt.inputs.len() {
            if let Some(sig) = &psbt.inputs[i].tap_key_sig {
                psbt.inputs[i].final_script_witness = Some(Witness::from_slice(&[sig.to_vec()]));
                psbt.inputs[i].tap_key_sig = None;
            }
        }

        // Verify all inputs are finalized
        let unsigned_count = psbt.inputs.iter()
            .filter(|input| input.final_script_witness.is_none())
            .count();
        if unsigned_count > 0 {
            return Err(anyhow!("Failed to finalize PSBT - {} inputs not fully signed", unsigned_count));
        }

        // Extract transaction
        let tx = psbt.extract_tx()?;
        let txid = tx.compute_txid();
        info!("✅ Hybrid transaction built and signed, txid: {}", txid);
        info!("   {} SNICKER + {} regular UTXOs",
              selected.snicker_utxos.len(), selected.regular_utxos.len());

        Ok((tx, selected))
    }
}
