//! Utility functions for debugging, diagnostics, and transaction weight estimation

use bdk_wallet::bitcoin::psbt::Psbt;
use tracing::debug;

// ============================================================
// TRANSACTION WEIGHT ESTIMATION
// ============================================================

/// Estimate vbytes for a P2TR-only transaction (e.g., SNICKER coinjoins).
/// All inputs and outputs are P2TR.
///
/// Weight breakdown:
/// - Overhead: version(4) + locktime(4) + counts(2) = 10 bytes * 4 = 40 WU, + segwit marker(2) = 42 WU
/// - Per P2TR input: outpoint(36) + scriptsig_len(1) + sequence(4) = 41 * 4 = 164 WU + witness(66) = 230 WU
/// - Per P2TR output: amount(8) + script_len(1) + scriptpubkey(34) = 43 * 4 = 172 WU
pub fn estimate_p2tr_tx_vbytes(num_inputs: usize, num_outputs: usize) -> u64 {
    const OVERHEAD_WU: u64 = 42;
    const INPUT_WU: u64 = 230;
    const OUTPUT_WU: u64 = 172;

    let weight = OVERHEAD_WU + (INPUT_WU * num_inputs as u64) + (OUTPUT_WU * num_outputs as u64);
    (weight + 3) / 4 // round up
}

/// Estimate vbytes for a spend transaction with P2TR inputs and arbitrary output type.
/// Used for calculating max sendable amount, fee estimation for sends.
///
/// Takes the destination script length to calculate output weight accurately
/// for any address type (P2TR, P2WPKH, P2PKH, etc.)
pub fn estimate_spend_tx_vbytes(num_p2tr_inputs: usize, output_script_len: usize) -> u64 {
    const OVERHEAD_WU: u64 = 42;
    const INPUT_WU: u64 = 230;

    // Output weight: (amount(8) + script_len_varint(1) + script) * 4
    let output_wu = (8 + 1 + output_script_len as u64) * 4;

    let weight = OVERHEAD_WU + (INPUT_WU * num_p2tr_inputs as u64) + output_wu;
    (weight + 3) / 4
}

/// Dump complete PSBT state for debugging
///
/// Logs detailed information about all inputs and outputs in a PSBT,
/// useful for debugging signing issues.
#[allow(dead_code)]
pub fn dump_psbt_state(psbt: &Psbt, label: &str) {
    debug!("========== PSBT STATE: {} ==========", label);
    debug!("Transaction inputs: {}", psbt.unsigned_tx.input.len());
    debug!("Transaction outputs: {}", psbt.unsigned_tx.output.len());

    for (i, input) in psbt.inputs.iter().enumerate() {
        debug!("--- Input {} ---", i);
        debug!("  witness_utxo: {}", input.witness_utxo.is_some());
        if let Some(ref utxo) = input.witness_utxo {
            debug!("    value: {} sats", utxo.value.to_sat());
            debug!("    script: {}", utxo.script_pubkey);
        }
        debug!("  non_witness_utxo: {}", input.non_witness_utxo.is_some());
        debug!("  sighash_type: {:?}", input.sighash_type);
        debug!("  tap_internal_key: {:?}", input.tap_internal_key);
        debug!("  tap_merkle_root: {:?}", input.tap_merkle_root);
        debug!("  tap_key_sig: {:?}", input.tap_key_sig);
        debug!("  tap_script_sigs: {}", input.tap_script_sigs.len());
        debug!("  tap_key_origins: {}", input.tap_key_origins.len());
        for (xonly, (leaf_hashes, (fingerprint, path))) in &input.tap_key_origins {
            debug!("    xonly: {}", xonly);
            debug!("    fingerprint: {}", fingerprint);
            debug!("    path: {}", path);
            debug!("    leaf_hashes: {} entries", leaf_hashes.len());
        }
        debug!("  bip32_derivation: {}", input.bip32_derivation.len());
        debug!("  partial_sigs: {}", input.partial_sigs.len());
        debug!("  final_script_witness: {}", input.final_script_witness.is_some());
    }

    for (i, output) in psbt.outputs.iter().enumerate() {
        debug!("--- Output {} ---", i);
        debug!("  tap_internal_key: {:?}", output.tap_internal_key);
        debug!("  tap_key_origins: {}", output.tap_key_origins.len());
    }
    debug!("========================================");
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        absolute::LockTime,
        consensus::encode::serialize_hex,
        hashes::Hash,
        secp256k1::{Secp256k1, SecretKey, Message},
        sighash::{Prevouts, SighashCache, TapSighashType},
        taproot::Signature as TaprootSignature,
        XOnlyPublicKey,
    };

    /// Create a dummy P2TR scriptPubKey from a 32-byte x-only pubkey
    fn p2tr_script(xonly_bytes: &[u8; 32]) -> ScriptBuf {
        let mut script = vec![0x51, 0x20]; // OP_1 PUSH32
        script.extend_from_slice(xonly_bytes);
        ScriptBuf::from_bytes(script)
    }

    /// Create a dummy P2WPKH scriptPubKey (22 bytes)
    fn p2wpkh_script() -> ScriptBuf {
        // OP_0 PUSH20 <20-byte hash>
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&[0xaa; 20]);
        ScriptBuf::from_bytes(script)
    }

    /// Create a dummy P2PKH scriptPubKey (25 bytes)
    fn p2pkh_script() -> ScriptBuf {
        // OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&[0xbb; 20]);
        script.extend_from_slice(&[0x88, 0xac]);
        ScriptBuf::from_bytes(script)
    }

    /// Build a signed P2TR transaction with specified inputs and outputs
    fn build_signed_p2tr_tx(num_inputs: usize, output_scripts: Vec<ScriptBuf>) -> Transaction {
        let secp = Secp256k1::new();

        // Create deterministic secret keys for signing
        let secret_keys: Vec<SecretKey> = (0..num_inputs)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[31] = (i + 1) as u8;
                SecretKey::from_slice(&bytes).unwrap()
            })
            .collect();

        // Get x-only pubkeys
        let xonly_keys: Vec<XOnlyPublicKey> = secret_keys
            .iter()
            .map(|sk| {
                let pk = sk.public_key(&secp);
                XOnlyPublicKey::from(pk)
            })
            .collect();

        // Create inputs
        let inputs: Vec<TxIn> = (0..num_inputs)
            .map(|i| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_slice(&[i as u8; 32]).unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect();

        // Create outputs
        let outputs: Vec<TxOut> = output_scripts
            .iter()
            .map(|script| TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: script.clone(),
            })
            .collect();

        let mut tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        // Create prevouts for signing
        let prevouts: Vec<TxOut> = xonly_keys
            .iter()
            .map(|xonly| TxOut {
                value: Amount::from_sat(100000),
                script_pubkey: p2tr_script(&xonly.serialize()),
            })
            .collect();

        // Sign each input
        let prevouts_ref: Vec<&TxOut> = prevouts.iter().collect();
        for i in 0..num_inputs {
            let mut sighash_cache = SighashCache::new(&tx);
            let sighash = sighash_cache
                .taproot_key_spend_signature_hash(
                    i,
                    &Prevouts::All(&prevouts_ref),
                    TapSighashType::Default,
                )
                .unwrap();

            let msg = Message::from_digest(sighash.to_byte_array());
            let keypair = secret_keys[i].keypair(&secp);
            let sig = secp.sign_schnorr(&msg, &keypair);

            let taproot_sig = TaprootSignature {
                signature: sig,
                sighash_type: TapSighashType::Default,
            };

            tx.input[i].witness.push(taproot_sig.to_vec());
        }

        tx
    }

    #[test]
    fn test_weight_estimation_accuracy() {
        println!("\n========== TX WEIGHT ESTIMATION TEST ==========\n");

        // Test 1: SNICKER-like 2 inputs, 2 P2TR outputs
        let xonly1 = [0x11u8; 32];
        let xonly2 = [0x22u8; 32];
        let tx_2in_2out = build_signed_p2tr_tx(2, vec![p2tr_script(&xonly1), p2tr_script(&xonly2)]);
        let hex_2in_2out = serialize_hex(&tx_2in_2out);
        let actual_weight_2in_2out = tx_2in_2out.weight().to_wu();
        let actual_vbytes_2in_2out = (actual_weight_2in_2out + 3) / 4;
        let estimated_vbytes_2in_2out = estimate_p2tr_tx_vbytes(2, 2);

        println!("Test 1: 2 P2TR inputs, 2 P2TR outputs (SNICKER no-change)");
        println!("  Estimated vbytes: {}", estimated_vbytes_2in_2out);
        println!("  Actual weight:    {} WU", actual_weight_2in_2out);
        println!("  Actual vbytes:    {}", actual_vbytes_2in_2out);
        println!("  Raw hex ({} bytes):", hex_2in_2out.len() / 2);
        println!("  {}\n", hex_2in_2out);

        // Test 2: SNICKER-like 2 inputs, 3 P2TR outputs
        let xonly3 = [0x33u8; 32];
        let tx_2in_3out = build_signed_p2tr_tx(2, vec![
            p2tr_script(&xonly1),
            p2tr_script(&xonly2),
            p2tr_script(&xonly3),
        ]);
        let hex_2in_3out = serialize_hex(&tx_2in_3out);
        let actual_weight_2in_3out = tx_2in_3out.weight().to_wu();
        let actual_vbytes_2in_3out = (actual_weight_2in_3out + 3) / 4;
        let estimated_vbytes_2in_3out = estimate_p2tr_tx_vbytes(2, 3);

        println!("Test 2: 2 P2TR inputs, 3 P2TR outputs (SNICKER with change)");
        println!("  Estimated vbytes: {}", estimated_vbytes_2in_3out);
        println!("  Actual weight:    {} WU", actual_weight_2in_3out);
        println!("  Actual vbytes:    {}", actual_vbytes_2in_3out);
        println!("  Raw hex ({} bytes):", hex_2in_3out.len() / 2);
        println!("  {}\n", hex_2in_3out);

        // Test 3: Spend to P2WPKH (1 input, 1 output)
        let tx_1in_p2wpkh = build_signed_p2tr_tx(1, vec![p2wpkh_script()]);
        let hex_1in_p2wpkh = serialize_hex(&tx_1in_p2wpkh);
        let actual_weight_1in_p2wpkh = tx_1in_p2wpkh.weight().to_wu();
        let actual_vbytes_1in_p2wpkh = (actual_weight_1in_p2wpkh + 3) / 4;
        let estimated_vbytes_1in_p2wpkh = estimate_spend_tx_vbytes(1, p2wpkh_script().len());

        println!("Test 3: 1 P2TR input, 1 P2WPKH output (spend to segwit)");
        println!("  P2WPKH script len: {}", p2wpkh_script().len());
        println!("  Estimated vbytes:  {}", estimated_vbytes_1in_p2wpkh);
        println!("  Actual weight:     {} WU", actual_weight_1in_p2wpkh);
        println!("  Actual vbytes:     {}", actual_vbytes_1in_p2wpkh);
        println!("  Raw hex ({} bytes):", hex_1in_p2wpkh.len() / 2);
        println!("  {}\n", hex_1in_p2wpkh);

        // Test 4: Spend to P2PKH (1 input, 1 output)
        let tx_1in_p2pkh = build_signed_p2tr_tx(1, vec![p2pkh_script()]);
        let hex_1in_p2pkh = serialize_hex(&tx_1in_p2pkh);
        let actual_weight_1in_p2pkh = tx_1in_p2pkh.weight().to_wu();
        let actual_vbytes_1in_p2pkh = (actual_weight_1in_p2pkh + 3) / 4;
        let estimated_vbytes_1in_p2pkh = estimate_spend_tx_vbytes(1, p2pkh_script().len());

        println!("Test 4: 1 P2TR input, 1 P2PKH output (spend to legacy)");
        println!("  P2PKH script len: {}", p2pkh_script().len());
        println!("  Estimated vbytes: {}", estimated_vbytes_1in_p2pkh);
        println!("  Actual weight:    {} WU", actual_weight_1in_p2pkh);
        println!("  Actual vbytes:    {}", actual_vbytes_1in_p2pkh);
        println!("  Raw hex ({} bytes):", hex_1in_p2pkh.len() / 2);
        println!("  {}\n", hex_1in_p2pkh);

        println!("=================================================\n");

        // Assert estimates are close to actual (within a few vbytes)
        assert!((estimated_vbytes_2in_2out as i64 - actual_vbytes_2in_2out as i64).abs() <= 2,
            "2-in 2-out estimate off by more than 2 vbytes");
        assert!((estimated_vbytes_2in_3out as i64 - actual_vbytes_2in_3out as i64).abs() <= 2,
            "2-in 3-out estimate off by more than 2 vbytes");
        assert!((estimated_vbytes_1in_p2wpkh as i64 - actual_vbytes_1in_p2wpkh as i64).abs() <= 2,
            "P2WPKH estimate off by more than 2 vbytes");
        assert!((estimated_vbytes_1in_p2pkh as i64 - actual_vbytes_1in_p2pkh as i64).abs() <= 2,
            "P2PKH estimate off by more than 2 vbytes");
    }
}
