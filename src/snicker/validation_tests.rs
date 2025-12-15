//! Tests for SNICKER protocol validation functions
//!
//! This module contains tests for:
//! - Transaction filtering (is_snicker_candidate)
//! - Amount validation (validate_amounts)
//! - Input validation (validate_inputs)
//! - Tweak validation (validate_tweak)
//! - PSBT construction

use super::*;
use bdk_wallet::bitcoin::{
    Amount, OutPoint, ScriptBuf, Transaction, TxOut,
    locktime::absolute::LockTime,
    psbt::Psbt,
    secp256k1::{Secp256k1, SecretKey, PublicKey, XOnlyPublicKey, Keypair},
};
use tempfile::TempDir;

// ============================================================
// TEST HELPERS
// ============================================================

fn create_test_snicker() -> Snicker {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_snicker.db");
    Snicker::new_from_path(&db_path, bdk_wallet::bitcoin::Network::Regtest).unwrap()
}

fn create_mock_local_output(
    outpoint: OutPoint,
    value: u64,
    keychain: bdk_wallet::KeychainKind,
    derivation_index: u32,
) -> bdk_wallet::LocalOutput {
    let secp = Secp256k1::new();
    let internal_key = XOnlyPublicKey::from_slice(&[2u8; 32])
        .unwrap();

    bdk_wallet::LocalOutput {
        outpoint,
        txout: TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
        },
        keychain,
        is_spent: false,
        derivation_index,
        chain_position: bdk_wallet::chain::ChainPosition::Unconfirmed {
            first_seen: Some(0),
            last_seen: Some(0)
        },
    }
}

fn create_test_psbt(
    receiver_outpoint: OutPoint,
    receiver_value: u64,
    proposer_outpoint: OutPoint,
    proposer_value: u64,
    output_values: Vec<u64>,
) -> (Psbt, ScriptBuf) {
    let secp = Secp256k1::new();

    // Generate valid keys from secret keys for different purposes
    let receiver_seckey = SecretKey::from_slice(&[0x01; 32])
        .unwrap();
    let receiver_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &receiver_seckey)
    ).0;

    let proposer_seckey = SecretKey::from_slice(&[0x02; 32])
        .unwrap();
    let proposer_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &proposer_seckey)
    ).0;

    let tweaked_seckey = SecretKey::from_slice(&[0x03; 32])
        .unwrap();
    let tweaked_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &tweaked_seckey)
    ).0;

    let change_seckey = SecretKey::from_slice(&[0x04; 32])
        .unwrap();
    let change_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &change_seckey)
    ).0;

    let receiver_txout = TxOut {
        value: Amount::from_sat(receiver_value),
        script_pubkey: ScriptBuf::new_p2tr(&secp, receiver_key, None),
    };

    let proposer_txout = TxOut {
        value: Amount::from_sat(proposer_value),
        script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
    };

    // First output is tweaked (receiver's), second is equal (proposer's), third is change
    let tweaked_script = ScriptBuf::new_p2tr(&secp, tweaked_key, None);
    let outputs: Vec<TxOut> = output_values.iter().enumerate().map(|(i, &val)| {
        let script = match i {
            0 => tweaked_script.clone(), // Receiver's tweaked output
            1 => ScriptBuf::new_p2tr(&secp, proposer_key, None), // Proposer's equal output
            _ => ScriptBuf::new_p2tr(&secp, change_key, None),   // Change output
        };
        TxOut {
            value: Amount::from_sat(val),
            script_pubkey: script,
        }
    }).collect();

    let tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            bdk_wallet::bitcoin::TxIn {
                previous_output: receiver_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::new(),
            },
            bdk_wallet::bitcoin::TxIn {
                previous_output: proposer_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::new(),
            },
        ],
        output: outputs,
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(receiver_txout);
    psbt.inputs[1].witness_utxo = Some(proposer_txout);

    (psbt, tweaked_script)
}

// ============================================================
// TRANSACTION FILTERING TESTS
// ============================================================

#[test]
fn test_is_snicker_candidate_with_valid_p2tr() {
    let secp = Secp256k1::new();
    let internal_key = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
    let script = ScriptBuf::new_p2tr(&secp, internal_key, None);

    let tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![
            TxOut {
                value: Amount::from_sat(100_000), // Within range
                script_pubkey: script.clone(),
            },
            TxOut {
                value: Amount::from_sat(200_000), // Within range
                script_pubkey: script,
            },
        ],
    };

    assert!(is_snicker_candidate(&tx, 50_000, 500_000));
}

#[test]
fn test_is_snicker_candidate_rejects_too_small() {
    let secp = Secp256k1::new();
    let internal_key = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
    let script = ScriptBuf::new_p2tr(&secp, internal_key, None);

    let tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![
            TxOut {
                value: Amount::from_sat(10_000), // Too small
                script_pubkey: script,
            },
        ],
    };

    assert!(!is_snicker_candidate(&tx, 50_000, 500_000));
}

#[test]
fn test_is_snicker_candidate_rejects_too_large() {
    let secp = Secp256k1::new();
    let internal_key = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
    let script = ScriptBuf::new_p2tr(&secp, internal_key, None);

    let tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![
            TxOut {
                value: Amount::from_sat(1_000_000), // Too large
                script_pubkey: script,
            },
        ],
    };

    assert!(!is_snicker_candidate(&tx, 50_000, 500_000));
}

#[test]
fn test_is_snicker_candidate_rejects_non_p2tr() {
    use bdk_wallet::bitcoin::hashes::Hash;

    // Create P2WPKH output
    let secp = Secp256k1::new();
    let seckey = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let pubkey = PublicKey::from_secret_key(&secp, &seckey);
    let wpkh = bdk_wallet::bitcoin::WPubkeyHash::hash(&pubkey.serialize());
    let script = ScriptBuf::new_p2wpkh(&wpkh);

    let tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: script,
            },
        ],
    };

    assert!(!is_snicker_candidate(&tx, 50_000, 500_000));
}

#[test]
fn test_is_snicker_candidate_mixed_outputs() {
    let secp = Secp256k1::new();
    let internal_key = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
    let p2tr_script = ScriptBuf::new_p2tr(&secp, internal_key, None);

    // P2WPKH script
    use bdk_wallet::bitcoin::hashes::Hash;
    let seckey = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let pubkey = PublicKey::from_secret_key(&secp, &seckey);
    let wpkh = bdk_wallet::bitcoin::WPubkeyHash::hash(&pubkey.serialize());
    let p2wpkh_script = ScriptBuf::new_p2wpkh(&wpkh);

    let tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: p2tr_script.clone(), // Valid P2TR
            },
            TxOut {
                value: Amount::from_sat(200_000),
                script_pubkey: p2wpkh_script, // P2WPKH
            },
            TxOut {
                value: Amount::from_sat(150_000),
                script_pubkey: p2tr_script, // Valid P2TR
            },
        ],
    };

    // Should return true because at least one output qualifies
    assert!(is_snicker_candidate(&tx, 50_000, 500_000));
}

// ============================================================
// AMOUNT VALIDATION TESTS
// ============================================================

#[test]
fn test_validate_amounts_correct_delta() {
    let snicker = create_test_snicker();

    let receiver_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000002"
            .parse().unwrap(),
        vout: 0,
    };

    let (psbt, tweaked_script) = create_test_psbt(
        receiver_outpoint,
        50_000,
        proposer_outpoint,
        100_000,
        vec![49_000, 49_000, 50_000],
    );

    let tweak_info = TweakInfo {
        original_output: TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: tweaked_script.clone(),
        },
        tweaked_output: TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: tweaked_script.clone(),
        },
        proposer_pubkey: PublicKey::from_slice(
            &[0x02; 33]
        ).unwrap(),
    };

    let our_utxos = vec![crate::wallet_node::WalletUtxo::Regular(create_mock_local_output(
        receiver_outpoint,
        50_000,
        bdk_wallet::KeychainKind::External,
        0,
    ))];

    // Delta is 1000 sats (within 0-5000 range)
    let result = snicker.validate_amounts(
        &psbt,
        &tweak_info,
        &our_utxos,
        (0, 5000),
    );

    assert!(result.is_ok(), "Valid delta within range should be accepted: {:?}", result.err());
}

#[test]
fn test_validate_amounts_rejects_high_delta() {
    let snicker = create_test_snicker();

    let receiver_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000002"
            .parse().unwrap(),
        vout: 0,
    };

    // Receiver has 50k, pays 10k delta (too high!), gets 40k output
    let (psbt, tweaked_script) = create_test_psbt(
        receiver_outpoint,
        50_000,
        proposer_outpoint,
        100_000,
        vec![40_000, 40_000, 68_000], // receiver gets 40k (lost 10k!)
    );

    let tweak_info = TweakInfo {
        original_output: TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: tweaked_script.clone(),
        },
        tweaked_output: TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: tweaked_script.clone(),
        },
        proposer_pubkey: PublicKey::from_slice(
            &[0x02; 33]
        ).unwrap(),
    };

    let our_utxos = vec![crate::wallet_node::WalletUtxo::Regular(create_mock_local_output(
        receiver_outpoint,
        50_000,
        bdk_wallet::KeychainKind::External,
        0,
    ))];

    // Delta is 10000 sats, should be rejected (max is 5000)
    let result = snicker.validate_amounts(
        &psbt,
        &tweak_info,
        &our_utxos,
        (0, 5000),
    );

    assert!(result.is_err(), "Delta above maximum should be rejected");
    assert!(result.unwrap_err().to_string().contains("Unacceptable delta"));
}

#[test]
fn test_validate_amounts_rejects_low_delta() {
    let snicker = create_test_snicker();

    let receiver_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000002"
            .parse().unwrap(),
        vout: 0,
    };

    // Receiver has 50k, gets PAID 3k (negative delta), receives 53k output
    let (psbt, tweaked_script) = create_test_psbt(
        receiver_outpoint,
        50_000,
        proposer_outpoint,
        100_000,
        vec![53_000, 53_000, 42_000], // receiver gets 53k (gained 3k!)
    );

    let tweak_info = TweakInfo {
        original_output: TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: tweaked_script.clone(),
        },
        tweaked_output: TxOut {
            value: Amount::from_sat(53_000),
            script_pubkey: tweaked_script.clone(),
        },
        proposer_pubkey: PublicKey::from_slice(
            &[0x02; 33]
        ).unwrap(),
    };

    let our_utxos = vec![crate::wallet_node::WalletUtxo::Regular(create_mock_local_output(
        receiver_outpoint,
        50_000,
        bdk_wallet::KeychainKind::External,
        0,
    ))];

    // Delta is -3000 sats (proposer pays us), should be rejected if min delta is 0
    let result = snicker.validate_amounts(
        &psbt,
        &tweak_info,
        &our_utxos,
        (0, 5000), // min delta is 0, so negative delta rejected
    );

    assert!(result.is_err(), "Negative delta below minimum should be rejected");
    assert!(result.unwrap_err().to_string().contains("Unacceptable delta"));
}

#[test]
fn test_validate_amounts_rejects_low_fee_rate() {
    let snicker = create_test_snicker();

    let receiver_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000002"
            .parse().unwrap(),
        vout: 0,
    };

    // Total input: 150k, total output: 149.9k, fee: only 100 sats (too low!)
    let (psbt, tweaked_script) = create_test_psbt(
        receiver_outpoint,
        50_000,
        proposer_outpoint,
        100_000,
        vec![49_000, 49_000, 51_900], // leaves only 100 sats for fees
    );

    let tweak_info = TweakInfo {
        original_output: TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: tweaked_script.clone(),
        },
        tweaked_output: TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: tweaked_script.clone(),
        },
        proposer_pubkey: PublicKey::from_slice(
            &[0x02; 33]
        ).unwrap(),
    };

    let our_utxos = vec![crate::wallet_node::WalletUtxo::Regular(create_mock_local_output(
        receiver_outpoint,
        50_000,
        bdk_wallet::KeychainKind::External,
        0,
    ))];

    let result = snicker.validate_amounts(
        &psbt,
        &tweak_info,
        &our_utxos,
        (0, 5000),
    );

    assert!(result.is_err(), "Transaction with fee rate < 1 sat/vb should be rejected");
    assert!(result.unwrap_err().to_string().contains("Fee rate too low"));
}

#[test]
fn test_validate_amounts_rejects_multiple_receiver_inputs() {
    let snicker = create_test_snicker();

    let receiver_outpoint1 = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let receiver_outpoint2 = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 1,
    };

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000002"
            .parse().unwrap(),
        vout: 0,
    };

    // Malicious PSBT with TWO receiver inputs
    let secp = Secp256k1::new();
    let receiver_seckey = SecretKey::from_slice(&[0x01; 32])
        .unwrap();
    let receiver_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &receiver_seckey)
    ).0;

    let proposer_seckey = SecretKey::from_slice(&[0x02; 32])
        .unwrap();
    let proposer_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &proposer_seckey)
    ).0;

    let tweaked_seckey = SecretKey::from_slice(&[0x03; 32])
        .unwrap();
    let tweaked_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &tweaked_seckey)
    ).0;

    let receiver_txout1 = TxOut {
        value: Amount::from_sat(30_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, receiver_key, None),
    };

    let receiver_txout2 = TxOut {
        value: Amount::from_sat(20_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, receiver_key, None),
    };

    let proposer_txout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
    };

    let tweaked_script = ScriptBuf::new_p2tr(&secp, tweaked_key, None);

    let tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            bdk_wallet::bitcoin::TxIn {
                previous_output: receiver_outpoint1,
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::new(),
            },
            bdk_wallet::bitcoin::TxIn {
                previous_output: receiver_outpoint2, // SECOND receiver input!
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::new(),
            },
            bdk_wallet::bitcoin::TxIn {
                previous_output: proposer_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::new(),
            },
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: tweaked_script.clone(),
            },
            TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
            },
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
            },
        ],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(receiver_txout1);
    psbt.inputs[1].witness_utxo = Some(receiver_txout2);
    psbt.inputs[2].witness_utxo = Some(proposer_txout);

    let tweak_info = TweakInfo {
        original_output: TxOut {
            value: Amount::from_sat(30_000),
            script_pubkey: tweaked_script.clone(),
        },
        tweaked_output: TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: tweaked_script.clone(),
        },
        proposer_pubkey: PublicKey::from_slice(
            &[0x02; 33]
        ).unwrap(),
    };

    // Claim BOTH outputs are ours
    let our_utxos = vec![
        crate::wallet_node::WalletUtxo::Regular(create_mock_local_output(
            receiver_outpoint1,
            30_000,
            bdk_wallet::KeychainKind::External,
            0,
        )),
        crate::wallet_node::WalletUtxo::Regular(create_mock_local_output(
            receiver_outpoint2,
            20_000,
            bdk_wallet::KeychainKind::External,
            1,
        )),
    ];

    let result = snicker.validate_amounts(
        &psbt,
        &tweak_info,
        &our_utxos,
        (0, 5000),
    );

    assert!(result.is_err(), "Multiple receiver inputs should be rejected");
    assert!(result.unwrap_err().to_string().contains("Multiple receiver inputs"));
}

// Continuing in next message due to size...

#[test]
fn test_validate_amounts_rejects_missing_tweaked_output() {
    let snicker = create_test_snicker();

    let receiver_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000002"
            .parse().unwrap(),
        vout: 0,
    };

    // Create PSBT but without the tweaked output
    let secp = Secp256k1::new();
    let receiver_seckey = SecretKey::from_slice(&[0x01; 32])
        .unwrap();
    let receiver_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &receiver_seckey)
    ).0;

    let proposer_seckey = SecretKey::from_slice(&[0x02; 32])
        .unwrap();
    let proposer_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &proposer_seckey)
    ).0;

    let tweaked_seckey = SecretKey::from_slice(&[0x03; 32])
        .unwrap();
    let tweaked_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &tweaked_seckey)
    ).0;

    let different_seckey = SecretKey::from_slice(&[0x05; 32])
        .unwrap();
    let different_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &different_seckey)
    ).0;

    let receiver_txout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, receiver_key, None),
    };

    let proposer_txout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
    };

    let tweaked_script = ScriptBuf::new_p2tr(&secp, tweaked_key, None);

    let tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            bdk_wallet::bitcoin::TxIn {
                previous_output: receiver_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::new(),
            },
            bdk_wallet::bitcoin::TxIn {
                previous_output: proposer_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::new(),
            },
        ],
        // Outputs do NOT include the expected tweaked script!
        output: vec![
            TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::new_p2tr(&secp, different_key, None), // Wrong key!
            },
            TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
            },
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
            },
        ],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(receiver_txout);
    psbt.inputs[1].witness_utxo = Some(proposer_txout);

    let tweak_info = TweakInfo {
        original_output: TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: tweaked_script.clone(),
        },
        tweaked_output: TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: tweaked_script.clone(), // This script is NOT in outputs!
        },
        proposer_pubkey: PublicKey::from_slice(
            &[0x02; 33]
        ).unwrap(),
    };

    let our_utxos = vec![crate::wallet_node::WalletUtxo::Regular(create_mock_local_output(
        receiver_outpoint,
        50_000,
        bdk_wallet::KeychainKind::External,
        0,
    ))];

    let result = snicker.validate_amounts(
        &psbt,
        &tweak_info,
        &our_utxos,
        (0, 5000),
    );

    assert!(result.is_err(), "Missing tweaked output should be rejected");
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[test]
fn test_validate_amounts_rejects_duplicate_tweaked_output() {
    let snicker = create_test_snicker();

    let receiver_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000002"
            .parse().unwrap(),
        vout: 0,
    };

    // Create PSBT with DUPLICATE tweaked outputs (malicious)
    let secp = Secp256k1::new();
    let receiver_seckey = SecretKey::from_slice(&[0x01; 32])
        .unwrap();
    let receiver_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &receiver_seckey)
    ).0;

    let proposer_seckey = SecretKey::from_slice(&[0x02; 32])
        .unwrap();
    let proposer_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &proposer_seckey)
    ).0;

    let tweaked_seckey = SecretKey::from_slice(&[0x03; 32])
        .unwrap();
    let tweaked_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &tweaked_seckey)
    ).0;

    let receiver_txout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, receiver_key, None),
    };

    let proposer_txout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
    };

    let tweaked_script = ScriptBuf::new_p2tr(&secp, tweaked_key, None);

    let tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            bdk_wallet::bitcoin::TxIn {
                previous_output: receiver_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::new(),
            },
            bdk_wallet::bitcoin::TxIn {
                previous_output: proposer_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::new(),
            },
        ],
        // TWO outputs with same tweaked script (malicious)
        output: vec![
            TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: tweaked_script.clone(), // DUPLICATE!
            },
            TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: tweaked_script.clone(), // DUPLICATE!
            },
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
            },
        ],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(receiver_txout);
    psbt.inputs[1].witness_utxo = Some(proposer_txout);

    let tweak_info = TweakInfo {
        original_output: TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: tweaked_script.clone(),
        },
        tweaked_output: TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: tweaked_script.clone(),
        },
        proposer_pubkey: PublicKey::from_slice(
            &[0x02; 33]
        ).unwrap(),
    };

    let our_utxos = vec![crate::wallet_node::WalletUtxo::Regular(create_mock_local_output(
        receiver_outpoint,
        50_000,
        bdk_wallet::KeychainKind::External,
        0,
    ))];

    let result = snicker.validate_amounts(
        &psbt,
        &tweak_info,
        &our_utxos,
        (0, 5000),
    );

    assert!(result.is_err(), "Duplicate tweaked outputs should be rejected");
    assert!(result.unwrap_err().to_string().contains("Multiple outputs match"));
}

// ============================================================
// INPUT VALIDATION TESTS
// ============================================================

#[test]
fn test_validate_inputs_all_p2tr() {
    let snicker = create_test_snicker();

    let receiver_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000002"
            .parse().unwrap(),
        vout: 0,
    };

    let (psbt, _tweaked_script) = create_test_psbt(
        receiver_outpoint,
        50_000,
        proposer_outpoint,
        100_000,
        vec![49_000, 49_000, 50_000],
    );

    let secp = Secp256k1::new();

    // Extract the proposer's pubkey from the PSBT to match what's actually in there
    let proposer_psbt_input = &psbt.inputs[1]; // Proposer is second input
    let proposer_prevout = proposer_psbt_input.witness_utxo.as_ref().unwrap();
    let proposer_xonly = tweak::extract_taproot_pubkey(proposer_prevout).unwrap();

    // Convert to full pubkey (assume even parity)
    let mut proposer_pubkey_bytes = [0u8; 33];
    proposer_pubkey_bytes[0] = 0x02;
    proposer_pubkey_bytes[1..].copy_from_slice(&proposer_xonly);
    let proposer_pubkey = PublicKey::from_slice(&proposer_pubkey_bytes)
        .unwrap();

    let receiver_seckey = SecretKey::from_slice(&[0x01; 32])
        .unwrap();
    let receiver_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &receiver_seckey)
    ).0;
    let receiver_script = ScriptBuf::new_p2tr(&secp, receiver_key, None);

    let tweaked_seckey = SecretKey::from_slice(&[0x03; 32])
        .unwrap();
    let tweaked_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &tweaked_seckey)
    ).0;
    let tweaked_script = ScriptBuf::new_p2tr(&secp, tweaked_key, None);

    let tweak_info = TweakInfo {
        original_output: TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: receiver_script.clone(),
        },
        tweaked_output: TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: tweaked_script.clone(),
        },
        proposer_pubkey,
    };

    let our_utxos = vec![crate::wallet_node::WalletUtxo::Regular(create_mock_local_output(
        receiver_outpoint,
        50_000,
        bdk_wallet::KeychainKind::External,
        0,
    ))];

    let result = snicker.validate_inputs(&psbt, &tweak_info, &our_utxos);
    assert!(result.is_ok(), "All P2TR inputs with matching proposer key should be accepted");
}

#[test]
fn test_validate_inputs_rejects_mixed_types() {
    let snicker = create_test_snicker();

    let receiver_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000002"
            .parse().unwrap(),
        vout: 0,
    };

    // Create a PSBT with one P2WPKH input (receiver) and one P2TR input (proposer)
    let secp = Secp256k1::new();
    let receiver_seckey = SecretKey::from_slice(&[0x01; 32])
        .unwrap();
    let receiver_full_pubkey = PublicKey::from_secret_key(&secp, &receiver_seckey);

    let proposer_seckey = SecretKey::from_slice(&[0x02; 32])
        .unwrap();
    let proposer_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &proposer_seckey)
    ).0;

    let tweaked_seckey = SecretKey::from_slice(&[0x03; 32])
        .unwrap();
    let tweaked_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &tweaked_seckey)
    ).0;

    // Create P2WPKH script for receiver (LEGACY!)
    use bdk_wallet::bitcoin::hashes::Hash;
    let receiver_wpkh = bdk_wallet::bitcoin::WPubkeyHash::hash(&receiver_full_pubkey.serialize());
    let receiver_script = ScriptBuf::new_p2wpkh(&receiver_wpkh);

    let receiver_txout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: receiver_script.clone(),
    };

    let proposer_txout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
    };

    let tweaked_script = ScriptBuf::new_p2tr(&secp, tweaked_key, None);

    let tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            bdk_wallet::bitcoin::TxIn {
                previous_output: receiver_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::new(),
            },
            bdk_wallet::bitcoin::TxIn {
                previous_output: proposer_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::new(),
            },
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: tweaked_script.clone(),
            },
            TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
            },
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
            },
        ],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(receiver_txout);
    psbt.inputs[1].witness_utxo = Some(proposer_txout.clone());

    // Extract the actual proposer pubkey from the PSBT to match
    let proposer_xonly = tweak::extract_taproot_pubkey(&proposer_txout).unwrap();
    let mut actual_proposer_bytes = [0u8; 33];
    actual_proposer_bytes[0] = 0x02;
    actual_proposer_bytes[1..].copy_from_slice(&proposer_xonly);
    let actual_proposer_pubkey = PublicKey::from_slice(&actual_proposer_bytes)
        .unwrap();

    let tweak_info = TweakInfo {
        original_output: TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: receiver_script.clone(),
        },
        tweaked_output: TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: tweaked_script.clone(),
        },
        proposer_pubkey: actual_proposer_pubkey,
    };

    let our_utxos = vec![crate::wallet_node::WalletUtxo::Regular(create_mock_local_output(
        receiver_outpoint,
        50_000,
        bdk_wallet::KeychainKind::External,
        0,
    ))];

    let result = snicker.validate_inputs(&psbt, &tweak_info, &our_utxos);
    assert!(result.is_err(), "Mixed P2WPKH and P2TR inputs should be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("not P2TR") || err_msg.contains("Proposer input is not P2TR"));
}

#[test]
fn test_validate_inputs_verifies_proposer_key() {
    // This is essentially the same as test_validate_inputs_all_p2tr
    // but explicitly verifying the proposer key check
    let snicker = create_test_snicker();

    let receiver_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000002"
            .parse().unwrap(),
        vout: 0,
    };

    let (psbt, _tweaked_script) = create_test_psbt(
        receiver_outpoint,
        50_000,
        proposer_outpoint,
        100_000,
        vec![49_000, 49_000, 50_000],
    );

    let secp = Secp256k1::new();

    // Extract the ACTUAL proposer's pubkey from the PSBT
    let proposer_psbt_input = &psbt.inputs[1];
    let proposer_prevout = proposer_psbt_input.witness_utxo.as_ref().unwrap();
    let proposer_xonly = tweak::extract_taproot_pubkey(proposer_prevout).unwrap();

    let mut proposer_pubkey_bytes = [0u8; 33];
    proposer_pubkey_bytes[0] = 0x02;
    proposer_pubkey_bytes[1..].copy_from_slice(&proposer_xonly);
    let proposer_pubkey = PublicKey::from_slice(&proposer_pubkey_bytes)
        .unwrap();

    let receiver_seckey = SecretKey::from_slice(&[0x01; 32])
        .unwrap();
    let receiver_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &receiver_seckey)
    ).0;
    let receiver_script = ScriptBuf::new_p2tr(&secp, receiver_key, None);

    let tweaked_seckey = SecretKey::from_slice(&[0x03; 32])
        .unwrap();
    let tweaked_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &tweaked_seckey)
    ).0;
    let tweaked_script = ScriptBuf::new_p2tr(&secp, tweaked_key, None);

    let tweak_info = TweakInfo {
        original_output: TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: receiver_script.clone(),
        },
        tweaked_output: TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: tweaked_script.clone(),
        },
        proposer_pubkey, // This matches the actual proposer input key
    };

    let our_utxos = vec![crate::wallet_node::WalletUtxo::Regular(create_mock_local_output(
        receiver_outpoint,
        50_000,
        bdk_wallet::KeychainKind::External,
        0,
    ))];

    let result = snicker.validate_inputs(&psbt, &tweak_info, &our_utxos);
    assert!(result.is_ok(), "Proposer key matching input key should be accepted");
}

#[test]
fn test_validate_inputs_rejects_key_mismatch() {
    let snicker = create_test_snicker();

    let receiver_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000002"
            .parse().unwrap(),
        vout: 0,
    };

    let (psbt, _tweaked_script) = create_test_psbt(
        receiver_outpoint,
        50_000,
        proposer_outpoint,
        100_000,
        vec![49_000, 49_000, 50_000],
    );

    let secp = Secp256k1::new();

    // Use a DIFFERENT key than what's actually in the PSBT
    let wrong_seckey = SecretKey::from_slice(&[0x06; 32])
        .unwrap();
    let wrong_proposer_pubkey = PublicKey::from_secret_key(
        &secp,
        &wrong_seckey
    );

    let receiver_seckey = SecretKey::from_slice(&[0x01; 32])
        .unwrap();
    let receiver_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &receiver_seckey)
    ).0;
    let receiver_script = ScriptBuf::new_p2tr(&secp, receiver_key, None);

    let tweaked_seckey = SecretKey::from_slice(&[0x03; 32])
        .unwrap();
    let tweaked_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &tweaked_seckey)
    ).0;
    let tweaked_script = ScriptBuf::new_p2tr(&secp, tweaked_key, None);

    let tweak_info = TweakInfo {
        original_output: TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: receiver_script.clone(),
        },
        tweaked_output: TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: tweaked_script.clone(),
        },
        proposer_pubkey: wrong_proposer_pubkey, // WRONG KEY!
    };

    let our_utxos = vec![crate::wallet_node::WalletUtxo::Regular(create_mock_local_output(
        receiver_outpoint,
        50_000,
        bdk_wallet::KeychainKind::External,
        0,
    ))];

    let result = snicker.validate_inputs(&psbt, &tweak_info, &our_utxos);
    assert!(result.is_err(), "Proposer key mismatch should be rejected");
    assert!(result.unwrap_err().to_string().contains("mismatch"));
}

// ============================================================
// TWEAK VALIDATION TESTS
// ============================================================

#[test]
fn test_validate_tweak_correct() {
    let snicker = create_test_snicker();
    let secp = Secp256k1::new();

    // Create receiver's key (our wallet)
    let receiver_seckey = SecretKey::from_slice(&[0x01; 32])
        .unwrap();
    let receiver_keypair = Keypair::from_secret_key(&secp, &receiver_seckey);
    let receiver_xonly = XOnlyPublicKey::from_keypair(&receiver_keypair).0;

    // Create proposer's key
    let proposer_seckey = SecretKey::from_slice(&[0x02; 32])
        .unwrap();
    let proposer_pubkey = PublicKey::from_secret_key(&secp, &proposer_seckey);

    // Create original output (receiver's BIP86 taproot output)
    let original_script = ScriptBuf::new_p2tr(&secp, receiver_xonly, None);
    let original_output = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: original_script.clone(),
    };

    // Create tweaked output using the correct tweak
    let (tweaked_output, _shared_secret) = tweak::create_tweaked_output(
        &original_output,
        &proposer_seckey,
        &PublicKey::from_secret_key(&secp, &receiver_seckey)
    ).unwrap();

    let tweak_info = TweakInfo {
        original_output: original_output.clone(),
        tweaked_output,
        proposer_pubkey,
    };

    let receiver_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let our_utxos = vec![crate::wallet_node::WalletUtxo::Regular(bdk_wallet::LocalOutput {
        outpoint: receiver_outpoint,
        txout: original_output,
        keychain: bdk_wallet::KeychainKind::External,
        is_spent: false,
        derivation_index: 0,
        chain_position: bdk_wallet::chain::ChainPosition::Unconfirmed {
            first_seen: Some(0),
            last_seen: Some(0)
        },
    })];

    // Mock derive_privkey function that returns our receiver key
    let derive_privkey = |_utxo: &crate::wallet_node::WalletUtxo| {
        Ok(receiver_seckey)
    };

    let result = snicker.validate_tweak(&tweak_info, &our_utxos, &derive_privkey);
    assert!(result.is_ok(), "Valid tweak should be accepted: {:?}", result.err());
}

#[test]
fn test_validate_tweak_wrong_proposer_key() {
    let snicker = create_test_snicker();
    let secp = Secp256k1::new();

    // Create receiver's key
    let receiver_seckey = SecretKey::from_slice(&[0x01; 32])
        .unwrap();
    let receiver_keypair = Keypair::from_secret_key(&secp, &receiver_seckey);
    let receiver_xonly = XOnlyPublicKey::from_keypair(&receiver_keypair).0;

    // Create proposer's key
    let proposer_seckey = SecretKey::from_slice(&[0x02; 32])
        .unwrap();

    // Create WRONG proposer key for verification
    let wrong_proposer_seckey = SecretKey::from_slice(&[0x03; 32])
        .unwrap();
    let wrong_proposer_pubkey = PublicKey::from_secret_key(&secp, &wrong_proposer_seckey);

    // Create original output
    let original_script = ScriptBuf::new_p2tr(&secp, receiver_xonly, None);
    let original_output = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: original_script.clone(),
    };

    // Create tweaked output using the CORRECT proposer key
    let (tweaked_output, _shared_secret) = tweak::create_tweaked_output(
        &original_output,
        &proposer_seckey,
        &PublicKey::from_secret_key(&secp, &receiver_seckey)
    ).unwrap();

    // But claim it was created with the WRONG proposer key
    let tweak_info = TweakInfo {
        original_output: original_output.clone(),
        tweaked_output,
        proposer_pubkey: wrong_proposer_pubkey,
    };

    let receiver_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let our_utxos = vec![crate::wallet_node::WalletUtxo::Regular(bdk_wallet::LocalOutput {
        outpoint: receiver_outpoint,
        txout: original_output,
        keychain: bdk_wallet::KeychainKind::External,
        is_spent: false,
        derivation_index: 0,
        chain_position: bdk_wallet::chain::ChainPosition::Unconfirmed {
            first_seen: Some(0),
            last_seen: Some(0)
        },
    })];

    let derive_privkey = |_utxo: &crate::wallet_node::WalletUtxo| {
        Ok(receiver_seckey)
    };

    let result = snicker.validate_tweak(&tweak_info, &our_utxos, &derive_privkey);
    assert!(result.is_err(), "Wrong proposer key should be rejected");
    assert!(result.unwrap_err().to_string().contains("mismatch"));
}

#[test]
fn test_validate_tweak_wrong_receiver_key() {
    let snicker = create_test_snicker();
    let secp = Secp256k1::new();

    // Create receiver's key
    let receiver_seckey = SecretKey::from_slice(&[0x01; 32])
        .unwrap();
    let receiver_keypair = Keypair::from_secret_key(&secp, &receiver_seckey);
    let receiver_xonly = XOnlyPublicKey::from_keypair(&receiver_keypair).0;

    // Create proposer's key
    let proposer_seckey = SecretKey::from_slice(&[0x02; 32])
        .unwrap();
    let proposer_pubkey = PublicKey::from_secret_key(&secp, &proposer_seckey);

    // Create original output
    let original_script = ScriptBuf::new_p2tr(&secp, receiver_xonly, None);
    let original_output = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: original_script.clone(),
    };

    // Create tweaked output using the correct keys
    let (tweaked_output, _shared_secret) = tweak::create_tweaked_output(
        &original_output,
        &proposer_seckey,
        &PublicKey::from_secret_key(&secp, &receiver_seckey)
    ).unwrap();

    let tweak_info = TweakInfo {
        original_output: original_output.clone(),
        tweaked_output,
        proposer_pubkey,
    };

    let receiver_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let our_utxos = vec![crate::wallet_node::WalletUtxo::Regular(bdk_wallet::LocalOutput {
        outpoint: receiver_outpoint,
        txout: original_output,
        keychain: bdk_wallet::KeychainKind::External,
        is_spent: false,
        derivation_index: 0,
        chain_position: bdk_wallet::chain::ChainPosition::Unconfirmed {
            first_seen: Some(0),
            last_seen: Some(0)
        },
    })];

    // Mock derive_privkey that returns WRONG key
    let wrong_receiver_seckey = SecretKey::from_slice(&[0x04; 32])
        .unwrap();
    let derive_privkey = |_utxo: &crate::wallet_node::WalletUtxo| {
        Ok(wrong_receiver_seckey)
    };

    let result = snicker.validate_tweak(&tweak_info, &our_utxos, &derive_privkey);
    assert!(result.is_err(), "Wrong receiver key should be rejected");
    assert!(result.unwrap_err().to_string().contains("mismatch"));
}

#[test]
fn test_validate_tweak_non_p2tr_output() {
    let snicker = create_test_snicker();
    let secp = Secp256k1::new();

    // Create receiver's key
    let receiver_seckey = SecretKey::from_slice(&[0x01; 32])
        .unwrap();
    let receiver_pubkey = PublicKey::from_secret_key(&secp, &receiver_seckey);

    // Create proposer's key
    let proposer_seckey = SecretKey::from_slice(&[0x02; 32])
        .unwrap();
    let proposer_pubkey_full = PublicKey::from_secret_key(&secp, &proposer_seckey);

    // Create P2WPKH output (NOT P2TR!)
    use bdk_wallet::bitcoin::hashes::Hash;
    let receiver_wpkh = bdk_wallet::bitcoin::WPubkeyHash::hash(&receiver_pubkey.serialize());
    let original_script = ScriptBuf::new_p2wpkh(&receiver_wpkh);
    let original_output = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: original_script.clone(),
    };

    // Create a P2TR tweaked output
    let tweaked_seckey = SecretKey::from_slice(&[0x03; 32])
        .unwrap();
    let tweaked_keypair = Keypair::from_secret_key(&secp, &tweaked_seckey);
    let tweaked_xonly = XOnlyPublicKey::from_keypair(&tweaked_keypair).0;
    let tweaked_script = ScriptBuf::new_p2tr(&secp, tweaked_xonly, None);
    let tweaked_output = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: tweaked_script,
    };

    let tweak_info = TweakInfo {
        original_output: original_output.clone(),
        tweaked_output,
        proposer_pubkey: proposer_pubkey_full,
    };

    let receiver_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let our_utxos = vec![crate::wallet_node::WalletUtxo::Regular(bdk_wallet::LocalOutput {
        outpoint: receiver_outpoint,
        txout: original_output,
        keychain: bdk_wallet::KeychainKind::External,
        is_spent: false,
        derivation_index: 0,
        chain_position: bdk_wallet::chain::ChainPosition::Unconfirmed {
            first_seen: Some(0),
            last_seen: Some(0)
        },
    })];

    let derive_privkey = |_utxo: &crate::wallet_node::WalletUtxo| {
        Ok(receiver_seckey)
    };

    let result = snicker.validate_tweak(&tweak_info, &our_utxos, &derive_privkey);
    assert!(result.is_err(), "Non-P2TR original output should be rejected");
    assert!(result.unwrap_err().to_string().contains("not P2TR"));
}

// ============================================================
// PSBT CONSTRUCTION TESTS
// ============================================================

#[test]
fn test_build_psbt_correct_structure() {
    let snicker = create_test_snicker();
    let secp = Secp256k1::new();

    // Create a target transaction with receiver's output
    let receiver_seckey = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let receiver_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &receiver_seckey)
    ).0;
    let receiver_script = ScriptBuf::new_p2tr(&secp, receiver_key, None);

    let target_tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: receiver_script.clone(),
            },
        ],
    };

    // Create proposer's UTXO
    let proposer_seckey = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let proposer_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &proposer_seckey)
    ).0;
    let proposer_script = ScriptBuf::new_p2tr(&secp, proposer_key, None);

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let proposer_txout = TxOut {
        value: Amount::from_sat(200_000),
        script_pubkey: proposer_script.clone(),
    };

    // Create tweaked output
    let tweaked_seckey = SecretKey::from_slice(&[0x03; 32]).unwrap();
    let tweaked_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &tweaked_seckey)
    ).0;
    let tweaked_script = ScriptBuf::new_p2tr(&secp, tweaked_key, None);
    let tweaked_output = TxOut {
        value: Amount::from_sat(99_000), // After 1000 sat delta
        script_pubkey: tweaked_script,
    };

    // Create addresses for proposer
    let proposer_equal_addr = bdk_wallet::bitcoin::Address::p2tr(
        &secp,
        proposer_key,
        None,
        bdk_wallet::bitcoin::Network::Regtest,
    );
    let proposer_change_addr = bdk_wallet::bitcoin::Address::p2tr(
        &secp,
        proposer_key,
        None,
        bdk_wallet::bitcoin::Network::Regtest,
    );

    let psbt = snicker.build_psbt(
        &target_tx,
        0,
        tweaked_output,
        proposer_outpoint,
        proposer_txout,
        proposer_equal_addr,
        proposer_change_addr,
        1_000, // delta
        bdk_wallet::bitcoin::FeeRate::from_sat_per_vb(2).unwrap(),
    ).unwrap();

    // Verify structure
    assert_eq!(psbt.unsigned_tx.input.len(), 2, "PSBT should have 2 inputs");
    assert_eq!(psbt.unsigned_tx.output.len(), 3, "PSBT should have 3 outputs");
}

#[test]
fn test_build_psbt_correct_order() {
    let snicker = create_test_snicker();
    let secp = Secp256k1::new();

    // Create a target transaction with receiver's output
    let receiver_seckey = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let receiver_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &receiver_seckey)
    ).0;
    let receiver_script = ScriptBuf::new_p2tr(&secp, receiver_key, None);

    let target_tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: receiver_script.clone(),
            },
        ],
    };

    let proposer_seckey = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let proposer_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &proposer_seckey)
    ).0;

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let proposer_txout = TxOut {
        value: Amount::from_sat(200_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
    };

    let tweaked_seckey = SecretKey::from_slice(&[0x03; 32]).unwrap();
    let tweaked_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &tweaked_seckey)
    ).0;
    let tweaked_output = TxOut {
        value: Amount::from_sat(99_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, tweaked_key, None),
    };

    let proposer_equal_addr = bdk_wallet::bitcoin::Address::p2tr(
        &secp,
        proposer_key,
        None,
        bdk_wallet::bitcoin::Network::Regtest,
    );
    let proposer_change_addr = bdk_wallet::bitcoin::Address::p2tr(
        &secp,
        proposer_key,
        None,
        bdk_wallet::bitcoin::Network::Regtest,
    );

    let psbt = snicker.build_psbt(
        &target_tx,
        0,
        tweaked_output,
        proposer_outpoint,
        proposer_txout.clone(),
        proposer_equal_addr,
        proposer_change_addr,
        1_000,
        bdk_wallet::bitcoin::FeeRate::from_sat_per_vb(2).unwrap(),
    ).unwrap();

    // Verify input order: receiver first, proposer second
    let receiver_outpoint = OutPoint {
        txid: target_tx.compute_txid(),
        vout: 0,
    };
    assert_eq!(
        psbt.unsigned_tx.input[0].previous_output,
        receiver_outpoint,
        "First input should be receiver's"
    );
    assert_eq!(
        psbt.unsigned_tx.input[1].previous_output,
        proposer_outpoint,
        "Second input should be proposer's"
    );
}

#[test]
fn test_build_psbt_includes_witness_utxos() {
    let snicker = create_test_snicker();
    let secp = Secp256k1::new();

    let receiver_seckey = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let receiver_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &receiver_seckey)
    ).0;
    let receiver_script = ScriptBuf::new_p2tr(&secp, receiver_key, None);

    let target_tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: receiver_script.clone(),
            },
        ],
    };

    let proposer_seckey = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let proposer_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &proposer_seckey)
    ).0;

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let proposer_txout = TxOut {
        value: Amount::from_sat(200_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
    };

    let tweaked_seckey = SecretKey::from_slice(&[0x03; 32]).unwrap();
    let tweaked_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &tweaked_seckey)
    ).0;
    let tweaked_output = TxOut {
        value: Amount::from_sat(99_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, tweaked_key, None),
    };

    let proposer_equal_addr = bdk_wallet::bitcoin::Address::p2tr(
        &secp,
        proposer_key,
        None,
        bdk_wallet::bitcoin::Network::Regtest,
    );
    let proposer_change_addr = bdk_wallet::bitcoin::Address::p2tr(
        &secp,
        proposer_key,
        None,
        bdk_wallet::bitcoin::Network::Regtest,
    );

    let psbt = snicker.build_psbt(
        &target_tx,
        0,
        tweaked_output,
        proposer_outpoint,
        proposer_txout.clone(),
        proposer_equal_addr,
        proposer_change_addr,
        1_000,
        bdk_wallet::bitcoin::FeeRate::from_sat_per_vb(2).unwrap(),
    ).unwrap();

    // Verify both inputs have witness_utxo set
    assert!(
        psbt.inputs[0].witness_utxo.is_some(),
        "Receiver input should have witness_utxo"
    );
    assert!(
        psbt.inputs[1].witness_utxo.is_some(),
        "Proposer input should have witness_utxo"
    );

    // Verify the witness_utxo values match what we expect
    assert_eq!(
        psbt.inputs[0].witness_utxo.as_ref().unwrap().value,
        Amount::from_sat(100_000),
        "Receiver witness_utxo value should match"
    );
    assert_eq!(
        psbt.inputs[1].witness_utxo.as_ref().unwrap().value,
        Amount::from_sat(200_000),
        "Proposer witness_utxo value should match"
    );
}

#[test]
fn test_build_equal_outputs_dust_prevention() {
    let snicker = create_test_snicker();
    let secp = Secp256k1::new();

    let receiver_seckey = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let receiver_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &receiver_seckey)
    ).0;
    let receiver_script = ScriptBuf::new_p2tr(&secp, receiver_key, None);

    // Receiver has only 1000 sats (very small UTXO)
    let target_tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: receiver_script.clone(),
            },
        ],
    };

    let proposer_seckey = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let proposer_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &proposer_seckey)
    ).0;

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let proposer_txout = TxOut {
        value: Amount::from_sat(200_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
    };

    let tweaked_seckey = SecretKey::from_slice(&[0x03; 32]).unwrap();
    let tweaked_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &tweaked_seckey)
    ).0;
    // After 500 sat delta, equal output would be 500 sats (below 546 dust limit!)
    let tweaked_output = TxOut {
        value: Amount::from_sat(500),
        script_pubkey: ScriptBuf::new_p2tr(&secp, tweaked_key, None),
    };

    let proposer_equal_addr = bdk_wallet::bitcoin::Address::p2tr(
        &secp,
        proposer_key,
        None,
        bdk_wallet::bitcoin::Network::Regtest,
    );
    let proposer_change_addr = bdk_wallet::bitcoin::Address::p2tr(
        &secp,
        proposer_key,
        None,
        bdk_wallet::bitcoin::Network::Regtest,
    );

    let result = snicker.build_psbt(
        &target_tx,
        0,
        tweaked_output,
        proposer_outpoint,
        proposer_txout,
        proposer_equal_addr,
        proposer_change_addr,
        500, // delta that would create dust
        bdk_wallet::bitcoin::FeeRate::from_sat_per_vb(2).unwrap(),
    );

    assert!(result.is_err(), "Should reject when equal output would be dust");
    assert!(result.unwrap_err().to_string().contains("dust"));
}

#[test]
fn test_build_equal_outputs_insufficient_funds() {
    let snicker = create_test_snicker();
    let secp = Secp256k1::new();

    let receiver_seckey = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let receiver_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &receiver_seckey)
    ).0;
    let receiver_script = ScriptBuf::new_p2tr(&secp, receiver_key, None);

    let target_tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: receiver_script.clone(),
            },
        ],
    };

    let proposer_seckey = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let proposer_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &proposer_seckey)
    ).0;

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    // Proposer has barely enough to cover one equal output (insufficient!)
    // Total in: 100,000 + 98,500 = 198,500
    // Total out: 99,000 + 99,000 = 198,000
    // Fee: ~410 sats
    // Change: 198,500 - 198,000 - 410 = 90 sats (below 546 dust limit!)
    let proposer_txout = TxOut {
        value: Amount::from_sat(98_900), // Change: 198,900-198,000-410 = 490 sats (below 546)
        script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
    };

    let tweaked_seckey = SecretKey::from_slice(&[0x03; 32]).unwrap();
    let tweaked_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &tweaked_seckey)
    ).0;
    let tweaked_output = TxOut {
        value: Amount::from_sat(99_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, tweaked_key, None),
    };

    let proposer_equal_addr = bdk_wallet::bitcoin::Address::p2tr(
        &secp,
        proposer_key,
        None,
        bdk_wallet::bitcoin::Network::Regtest,
    );
    let proposer_change_addr = bdk_wallet::bitcoin::Address::p2tr(
        &secp,
        proposer_key,
        None,
        bdk_wallet::bitcoin::Network::Regtest,
    );

    let result = snicker.build_psbt(
        &target_tx,
        0,
        tweaked_output,
        proposer_outpoint,
        proposer_txout,
        proposer_equal_addr,
        proposer_change_addr,
        1_000,
        bdk_wallet::bitcoin::FeeRate::from_sat_per_vb(2).unwrap(),
    );

    assert!(result.is_err(), "Should reject when proposer has insufficient funds");
    assert!(result.unwrap_err().to_string().contains("Insufficient"));
}

// ============================================================
// ERROR HANDLING AND EDGE CASES TESTS
// ============================================================

#[test]
fn test_propose_invalid_output_index() {
    let snicker = create_test_snicker();
    let secp = Secp256k1::new();

    // Create a target transaction with only 1 output
    let receiver_seckey = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let receiver_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &receiver_seckey)
    ).0;
    let receiver_script = ScriptBuf::new_p2tr(&secp, receiver_key, None);

    let target_tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: receiver_script.clone(),
            },
        ],
    };

    let proposer_seckey = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let proposer_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &proposer_seckey)
    ).0;

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let proposer_txout = TxOut {
        value: Amount::from_sat(200_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
    };

    let tweaked_seckey = SecretKey::from_slice(&[0x03; 32]).unwrap();
    let tweaked_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &tweaked_seckey)
    ).0;
    let tweaked_output = TxOut {
        value: Amount::from_sat(99_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, tweaked_key, None),
    };

    let proposer_equal_addr = bdk_wallet::bitcoin::Address::p2tr(
        &secp,
        proposer_key,
        None,
        bdk_wallet::bitcoin::Network::Regtest,
    );
    let proposer_change_addr = bdk_wallet::bitcoin::Address::p2tr(
        &secp,
        proposer_key,
        None,
        bdk_wallet::bitcoin::Network::Regtest,
    );

    // Try to access output index 5, but transaction only has 1 output (index 0)
    let result = snicker.build_psbt(
        &target_tx,
        5, // OUT OF BOUNDS!
        tweaked_output,
        proposer_outpoint,
        proposer_txout,
        proposer_equal_addr,
        proposer_change_addr,
        1_000,
        bdk_wallet::bitcoin::FeeRate::from_sat_per_vb(2).unwrap(),
    );

    assert!(result.is_err(), "Should reject invalid output index");
    assert!(result.unwrap_err().to_string().contains("out of bounds"));
}

#[test]
fn test_receive_missing_witness_utxo() {
    let snicker = create_test_snicker();

    let receiver_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse().unwrap(),
        vout: 0,
    };

    let proposer_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000002"
            .parse().unwrap(),
        vout: 0,
    };

    // Create PSBT but WITHOUT setting witness_utxo for the receiver input
    let secp = Secp256k1::new();
    let receiver_seckey = SecretKey::from_slice(&[0x01; 32])
        .unwrap();
    let receiver_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &receiver_seckey)
    ).0;

    let proposer_seckey = SecretKey::from_slice(&[0x02; 32])
        .unwrap();
    let proposer_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &proposer_seckey)
    ).0;

    let tweaked_seckey = SecretKey::from_slice(&[0x03; 32])
        .unwrap();
    let tweaked_key = XOnlyPublicKey::from_keypair(
        &Keypair::from_secret_key(&secp, &tweaked_seckey)
    ).0;

    let receiver_txout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, receiver_key, None),
    };

    let proposer_txout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
    };

    let tweaked_script = ScriptBuf::new_p2tr(&secp, tweaked_key, None);

    let tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            bdk_wallet::bitcoin::TxIn {
                previous_output: receiver_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::new(),
            },
            bdk_wallet::bitcoin::TxIn {
                previous_output: proposer_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bdk_wallet::bitcoin::Witness::new(),
            },
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: tweaked_script.clone(),
            },
            TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
            },
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new_p2tr(&secp, proposer_key, None),
            },
        ],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    // INTENTIONALLY NOT setting witness_utxo for receiver input!
    // psbt.inputs[0].witness_utxo = Some(receiver_txout.clone());
    psbt.inputs[1].witness_utxo = Some(proposer_txout.clone());

    // Extract proposer pubkey
    let proposer_xonly = tweak::extract_taproot_pubkey(&proposer_txout).unwrap();
    let mut proposer_pubkey_bytes = [0u8; 33];
    proposer_pubkey_bytes[0] = 0x02;
    proposer_pubkey_bytes[1..].copy_from_slice(&proposer_xonly);
    let proposer_pubkey = PublicKey::from_slice(&proposer_pubkey_bytes)
        .unwrap();

    let tweak_info = TweakInfo {
        original_output: receiver_txout.clone(),
        tweaked_output: TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: tweaked_script.clone(),
        },
        proposer_pubkey,
    };

    let our_utxos = vec![crate::wallet_node::WalletUtxo::Regular(create_mock_local_output(
        receiver_outpoint,
        50_000,
        bdk_wallet::KeychainKind::External,
        0,
    ))];

    let result = snicker.validate_inputs(&psbt, &tweak_info, &our_utxos);
    assert!(result.is_err(), "Should reject PSBT with missing witness_utxo");
    assert!(result.unwrap_err().to_string().contains("missing witness_utxo"));
}

#[tokio::test]
async fn test_db_concurrent_access() {
    use std::sync::Arc;
    use tokio::task::JoinSet;

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("concurrent_test.db");
    let snicker = Arc::new(
        Snicker::new_from_path(&db_path, bdk_wallet::bitcoin::Network::Regtest).unwrap()
    );

    // Spawn multiple tasks that access the database concurrently
    let mut tasks = JoinSet::new();

    for i in 0..10u32 {
        let snicker_clone = Arc::clone(&snicker);
        tasks.spawn(async move {
            let secp = Secp256k1::new();
            let seckey = SecretKey::from_slice(&[i as u8 + 1; 32])
                .unwrap();
            let key = XOnlyPublicKey::from_keypair(
                &Keypair::from_secret_key(&secp, &seckey)
            ).0;

            // Create a unique transaction for this task
            let tx = Transaction {
                version: bdk_wallet::bitcoin::transaction::Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![],
                output: vec![
                    TxOut {
                        value: Amount::from_sat(100_000 + (i as u64) * 1000),
                        script_pubkey: ScriptBuf::new_p2tr(&secp, key, None),
                    },
                ],
            };

            // Store candidate
            snicker_clone.store_candidate(i, &tx).await.unwrap();
        });
    }

    // Wait for all tasks to complete
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }

    // Verify all candidates were stored
    let candidates = snicker.get_snicker_candidates().await.unwrap();
    assert_eq!(candidates.len(), 10, "All concurrent writes should succeed");
}

#[tokio::test]
async fn test_db_corrupt_candidate() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("corrupt_test.db");
    let snicker = Snicker::new_from_path(&db_path, bdk_wallet::bitcoin::Network::Regtest).unwrap();

    // Manually insert corrupted data directly into the database
    {
        let conn = snicker.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO snicker_candidates (block_height, txid, tx_data) VALUES (?1, ?2, ?3)",
            (
                12345u32,
                "0000000000000000000000000000000000000000000000000000000000000001",
                vec![0xFF, 0xFF, 0xFF], // CORRUPTED DATA!
            ),
        ).unwrap();
    }

    // Try to retrieve candidates - should error on deserialization
    let result = snicker.get_snicker_candidates().await;

    assert!(result.is_err(), "Should error when deserializing corrupted data");
    // The error should be from bitcoin deserialization
}
