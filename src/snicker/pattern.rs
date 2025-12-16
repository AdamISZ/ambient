//! SNICKER transaction pattern detection
//!
//! Heuristics to identify transactions that are likely SNICKER coinjoins

use bdk_wallet::bitcoin::Transaction;

/// Detect if a transaction matches SNICKER pattern
///
/// A SNICKER transaction must have:
/// - At least 2 inputs (all P2TR taproot)
/// - Exactly 3 outputs (all P2TR taproot)
/// - Exactly 2 outputs with equal values (the coinjoin outputs for privacy)
/// - 1 output with different value (proposer's change)
///
/// Note: Output ordering is not considered as it is randomized.
pub fn is_likely_snicker_transaction(tx: &Transaction) -> bool {
    // Must have at least 2 inputs and exactly 3 outputs
    if tx.input.len() < 2 || tx.output.len() != 3 {
        return false;
    }

    // All outputs must be P2TR
    if !tx.output.iter().all(|out| out.script_pubkey.is_p2tr()) {
        return false;
    }

    // Check that exactly 2 outputs have equal values (essential for privacy)
    let mut output_values: Vec<u64> = tx.output.iter().map(|o| o.value.to_sat()).collect();
    output_values.sort();

    // In sorted order [a, b, c], we need exactly one pair equal:
    // Either a==b and b!=c, or a!=b and b==c
    let has_exactly_two_equal =
        (output_values[0] == output_values[1] && output_values[1] != output_values[2]) ||
        (output_values[0] != output_values[1] && output_values[1] == output_values[2]);

    has_exactly_two_equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::{
        Transaction, TxIn, TxOut, ScriptBuf, Amount, OutPoint, Txid,
    };

    fn create_p2tr_output(value_sats: u64) -> TxOut {
        // Create a dummy P2TR script (51 = OP_1, 20 = push 32 bytes, then 32 bytes of key)
        let script = ScriptBuf::from_hex(
            "51200000000000000000000000000000000000000000000000000000000000000000"
        ).unwrap();

        TxOut {
            value: Amount::from_sat(value_sats),
            script_pubkey: script,
        }
    }

    fn create_p2wpkh_output(value_sats: u64) -> TxOut {
        // Create a dummy P2WPKH script
        let script = ScriptBuf::from_hex(
            "001400000000000000000000000000000000000000"
        ).unwrap();

        TxOut {
            value: Amount::from_sat(value_sats),
            script_pubkey: script,
        }
    }

    fn dummy_input() -> TxIn {
        use bdk_wallet::bitcoin::hashes::Hash;
        TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: bdk_wallet::bitcoin::Sequence::MAX,
            witness: bdk_wallet::bitcoin::Witness::new(),
        }
    }

    #[test]
    fn test_perfect_snicker_pattern() {
        let tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![dummy_input(), dummy_input()],
            output: vec![
                create_p2tr_output(100_000),  // Equal output 1
                create_p2tr_output(100_000),  // Equal output 2
                create_p2tr_output(50_000),   // Change output
            ],
        };

        assert!(is_likely_snicker_transaction(&tx));
    }

    #[test]
    fn test_all_equal_outputs_not_snicker() {
        // All 3 outputs equal is not a SNICKER pattern (should be 2 equal + 1 different)
        let tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![dummy_input(), dummy_input()],
            output: vec![
                create_p2tr_output(100_000),
                create_p2tr_output(100_000),
                create_p2tr_output(100_000), // All equal - not SNICKER
            ],
        };

        assert!(!is_likely_snicker_transaction(&tx));
    }

    #[test]
    fn test_wrong_output_count() {
        // Only 2 outputs - should be 3
        let tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![dummy_input(), dummy_input()],
            output: vec![
                create_p2tr_output(100_000),
                create_p2tr_output(100_000),
            ],
        };

        assert!(!is_likely_snicker_transaction(&tx));
    }

    #[test]
    fn test_not_all_taproot() {
        let tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![dummy_input(), dummy_input()],
            output: vec![
                create_p2tr_output(100_000),
                create_p2tr_output(100_000),
                create_p2wpkh_output(50_000), // Not taproot
            ],
        };

        assert!(!is_likely_snicker_transaction(&tx));
    }

    #[test]
    fn test_no_equal_outputs() {
        // All outputs different - no equal pair
        let tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![dummy_input(), dummy_input()],
            output: vec![
                create_p2tr_output(100_000),
                create_p2tr_output(110_000),
                create_p2tr_output(50_000), // All different - not SNICKER
            ],
        };

        assert!(!is_likely_snicker_transaction(&tx));
    }

    #[test]
    fn test_large_equal_outputs() {
        // Test with larger values
        let tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![dummy_input(), dummy_input()],
            output: vec![
                create_p2tr_output(10_000_000),  // Equal output 1
                create_p2tr_output(10_000_000),  // Equal output 2
                create_p2tr_output(5_000_000),   // Change output
            ],
        };

        assert!(is_likely_snicker_transaction(&tx));
    }

    #[test]
    fn test_with_more_than_two_inputs() {
        // More than 2 inputs is allowed
        let tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![dummy_input(), dummy_input(), dummy_input()],
            output: vec![
                create_p2tr_output(100_000),
                create_p2tr_output(100_000),
                create_p2tr_output(50_000),
            ],
        };

        assert!(is_likely_snicker_transaction(&tx));
    }

    #[test]
    fn test_only_one_input() {
        // Only 1 input - should fail
        let tx = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![dummy_input()],
            output: vec![
                create_p2tr_output(100_000),
                create_p2tr_output(100_000),
                create_p2tr_output(50_000),
            ],
        };

        assert!(!is_likely_snicker_transaction(&tx));
    }
}
