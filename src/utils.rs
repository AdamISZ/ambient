//! Utility functions for debugging and diagnostics

use bdk_wallet::bitcoin::psbt::Psbt;
use tracing::info;

/// Dump complete PSBT state for debugging
///
/// Logs detailed information about all inputs and outputs in a PSBT,
/// useful for debugging signing issues.
#[allow(dead_code)]
pub fn dump_psbt_state(psbt: &Psbt, label: &str) {
    info!("========== PSBT STATE: {} ==========", label);
    info!("Transaction inputs: {}", psbt.unsigned_tx.input.len());
    info!("Transaction outputs: {}", psbt.unsigned_tx.output.len());

    for (i, input) in psbt.inputs.iter().enumerate() {
        info!("--- Input {} ---", i);
        info!("  witness_utxo: {}", input.witness_utxo.is_some());
        if let Some(ref utxo) = input.witness_utxo {
            info!("    value: {} sats", utxo.value.to_sat());
            info!("    script: {}", utxo.script_pubkey);
        }
        info!("  non_witness_utxo: {}", input.non_witness_utxo.is_some());
        info!("  sighash_type: {:?}", input.sighash_type);
        info!("  tap_internal_key: {:?}", input.tap_internal_key);
        info!("  tap_merkle_root: {:?}", input.tap_merkle_root);
        info!("  tap_key_sig: {:?}", input.tap_key_sig);
        info!("  tap_script_sigs: {}", input.tap_script_sigs.len());
        info!("  tap_key_origins: {}", input.tap_key_origins.len());
        for (xonly, (leaf_hashes, (fingerprint, path))) in &input.tap_key_origins {
            info!("    xonly: {}", xonly);
            info!("    fingerprint: {}", fingerprint);
            info!("    path: {}", path);
            info!("    leaf_hashes: {} entries", leaf_hashes.len());
        }
        info!("  bip32_derivation: {}", input.bip32_derivation.len());
        info!("  partial_sigs: {}", input.partial_sigs.len());
        info!("  final_script_witness: {}", input.final_script_witness.is_some());
    }

    for (i, output) in psbt.outputs.iter().enumerate() {
        info!("--- Output {} ---", i);
        info!("  tap_internal_key: {:?}", output.tap_internal_key);
        info!("  tap_key_origins: {}", output.tap_key_origins.len());
    }
    info!("========================================");
}
