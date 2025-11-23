//! Key tweaking logic for SNICKER using Diffie-Hellman shared secrets

use anyhow::{anyhow, Result};
use bdk_wallet::bitcoin::{
    secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, ecdh::SharedSecret},
    TxOut, ScriptBuf, hashes::{Hash, sha256},
};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};

/// Calculate Diffie-Hellman shared secret between our secret key and their public key
///
/// Both parties can independently derive the same shared secret:
/// - Proposer: `SharedSecret::new(&receiver_pubkey, &proposer_seckey)`
/// - Receiver: `SharedSecret::new(&proposer_pubkey, &receiver_seckey)`
///
/// # Returns
/// 32-byte shared secret (SHA256 hash of the ECDH point)
pub fn calculate_dh_shared_secret(
    our_seckey: &SecretKey,
    their_pubkey: &PublicKey,
) -> [u8; 32] {
    let shared = SharedSecret::new(their_pubkey, our_seckey);
    shared.secret_bytes()
}

/// Extract the taproot internal public key from a P2TR output
///
/// # Arguments
/// * `output` - The P2TR transaction output
///
/// # Returns
/// The 32-byte x-only public key
pub fn extract_taproot_pubkey(output: &TxOut) -> Result<[u8; 32]> {
    if !output.script_pubkey.is_p2tr() {
        return Err(anyhow!("Output is not P2TR"));
    }

    // P2TR format: OP_1 <32-byte-x-only-pubkey>
    let script_bytes = output.script_pubkey.as_bytes();

    if script_bytes.len() != 34 {
        return Err(anyhow!("Invalid P2TR script length: {}", script_bytes.len()));
    }

    if script_bytes[0] != 0x51 || script_bytes[1] != 0x20 {
        return Err(anyhow!("Invalid P2TR script format"));
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&script_bytes[2..34]);

    Ok(pubkey)
}

/// Apply a 32-byte tweak to a taproot public key
///
/// Creates a new tweaked public key by adding the tweak as a scalar.
/// tweaked_pubkey = original_pubkey + tweak*G
///
/// # Arguments
/// * `original_pubkey_xonly` - The original 32-byte x-only public key
/// * `tweak` - The 32-byte tweak (e.g., DH shared secret)
///
/// # Returns
/// The tweaked 32-byte x-only public key
pub fn apply_taproot_tweak(
    original_pubkey_xonly: &[u8; 32],
    tweak: &[u8; 32],
) -> Result<[u8; 32]> {
    let secp = Secp256k1::new();

    // Convert x-only pubkey to a full public key
    // For x-only keys, we assume even parity (standard in BIP340/Taproot)
    let mut pubkey_bytes = [0u8; 33];
    pubkey_bytes[0] = 0x02; // Even parity
    pubkey_bytes[1..].copy_from_slice(original_pubkey_xonly);

    let pubkey = PublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| anyhow!("Invalid public key: {}", e))?;

    // Convert tweak to scalar
    let tweak_scalar = Scalar::from_be_bytes(*tweak)
        .map_err(|_| anyhow!("Invalid tweak scalar"))?;

    // Add tweak to public key: tweaked_pubkey = pubkey + tweak*G
    let tweaked_pubkey = pubkey.add_exp_tweak(&secp, &tweak_scalar)?;

    // Extract x-only coordinate
    let tweaked_bytes = tweaked_pubkey.serialize();
    let mut tweaked_xonly = [0u8; 32];
    tweaked_xonly.copy_from_slice(&tweaked_bytes[1..33]);

    Ok(tweaked_xonly)
}

/// Create a tweaked P2TR output using DH shared secret
///
/// This is the core SNICKER operation for the proposer: given the receiver's
/// original output and the proposer's secret key, create a new output with the tweaked key.
///
/// # Arguments
/// * `original_output` - The receiver's original P2TR output
/// * `proposer_seckey` - The proposer's secret key
/// * `receiver_pubkey` - The receiver's public key (full, not x-only)
///
/// # Returns
/// The tweaked output and the shared secret used
pub fn create_tweaked_output(
    original_output: &TxOut,
    proposer_seckey: &SecretKey,
    receiver_pubkey: &PublicKey,
) -> Result<(TxOut, [u8; 32])> {
    // Extract receiver's x-only pubkey from the output
    let receiver_pubkey_xonly = extract_taproot_pubkey(original_output)?;

    // Calculate DH shared secret (proposer's perspective)
    let shared_secret = calculate_dh_shared_secret(proposer_seckey, receiver_pubkey);

    // Apply tweak to create new pubkey
    let tweaked_pubkey_xonly = apply_taproot_tweak(&receiver_pubkey_xonly, &shared_secret)?;

    // Create new P2TR scriptPubkey with tweaked key
    let tweaked_script = create_p2tr_script(&tweaked_pubkey_xonly);

    // Create new output with same value
    let tweaked_output = TxOut {
        value: original_output.value,
        script_pubkey: tweaked_script,
    };

    Ok((tweaked_output, shared_secret))
}

/// Verify a tweaked output (for receiver)
///
/// The receiver verifies that the tweaked output was correctly created
/// using their key and the proposer's public key.
///
/// # Arguments
/// * `original_output` - Their original output
/// * `tweaked_output` - The proposed tweaked output
/// * `receiver_seckey` - Their secret key
/// * `proposer_pubkey` - The proposer's public key (extracted from PSBT)
///
/// # Returns
/// The shared secret if valid, error otherwise
pub fn verify_tweaked_output(
    original_output: &TxOut,
    tweaked_output: &TxOut,
    receiver_seckey: &SecretKey,
    proposer_pubkey: &PublicKey,
) -> Result<[u8; 32]> {
    // Extract original pubkey
    let original_pubkey_xonly = extract_taproot_pubkey(original_output)?;

    // Calculate DH shared secret (receiver's perspective)
    let shared_secret = calculate_dh_shared_secret(receiver_seckey, proposer_pubkey);

    // Apply tweak to original pubkey
    let expected_tweaked_pubkey = apply_taproot_tweak(&original_pubkey_xonly, &shared_secret)?;

    // Verify the tweaked output has the expected pubkey
    let actual_tweaked_pubkey = extract_taproot_pubkey(tweaked_output)?;

    if expected_tweaked_pubkey != actual_tweaked_pubkey {
        return Err(anyhow!("Tweaked output pubkey mismatch"));
    }

    // Verify value is the same
    if original_output.value != tweaked_output.value {
        return Err(anyhow!("Tweaked output value mismatch"));
    }

    Ok(shared_secret)
}

/// Apply a tweak to a secret key with proper parity handling for x-only keys
///
/// When tweaking a secret key, the resulting public key may have odd parity.
/// Since x-only keys in BIP340/Taproot always have even parity, we must negate
/// the secret key if the resulting public key has odd parity.
///
/// This ensures: XOnlyPublicKey::from(tweaked_seckey) == expected_xonly_pubkey
///
/// # Arguments
/// * `seckey` - The secret key to tweak
/// * `tweak` - The tweak as a scalar
///
/// # Returns
/// The tweaked secret key with even-parity public key
pub fn apply_tweak_to_seckey_with_parity(
    seckey: &SecretKey,
    tweak: &Scalar,
) -> Result<SecretKey> {
    let secp = Secp256k1::new();

    // Apply tweak: tweaked_seckey = seckey + tweak
    let mut tweaked = seckey.add_tweak(tweak)?;

    // Check parity of resulting public key
    let pubkey = PublicKey::from_secret_key(&secp, &tweaked);
    let has_odd_y = pubkey.serialize()[0] == 0x03;

    // If odd parity, negate to match x-only (even parity) convention
    if has_odd_y {
        tweaked = tweaked.negate();
    }

    Ok(tweaked)
}

/// Calculate the tweaked secret key (for receiver to sign)
///
/// The receiver needs to derive their tweaked private key to sign
/// the SNICKER transaction with the tweaked output.
///
/// tweaked_seckey = original_seckey + tweak
///
/// # Arguments
/// * `receiver_seckey` - Their original secret key
/// * `shared_secret` - The DH shared secret (as tweak)
///
/// # Returns
/// The tweaked secret key
pub fn derive_tweaked_seckey(
    receiver_seckey: &SecretKey,
    shared_secret: &[u8; 32],
) -> Result<SecretKey> {
    // Convert shared secret to scalar
    let tweak_scalar = Scalar::from_be_bytes(*shared_secret)
        .map_err(|_| anyhow!("Invalid tweak scalar"))?;

    // Add tweak to secret key: tweaked_seckey = seckey + tweak
    let tweaked_seckey = receiver_seckey.add_tweak(&tweak_scalar)?;

    Ok(tweaked_seckey)
}

/// Create a P2TR scriptPubkey from an x-only public key
fn create_p2tr_script(xonly_pubkey: &[u8; 32]) -> ScriptBuf {
    // P2TR format: OP_1 (0x51) followed by 0x20 (32 bytes) and the pubkey
    let mut script_bytes = Vec::with_capacity(34);
    script_bytes.push(0x51); // OP_1
    script_bytes.push(0x20); // Push 32 bytes
    script_bytes.extend_from_slice(xonly_pubkey);

    ScriptBuf::from_bytes(script_bytes)
}

/// Calculate the taproot tweak scalar for a given internal public key
///
/// Uses the BIP341 formula: t = tagged_hash("TapTweak", pubkey)
/// with no merkle root (for BIP86 keypath-only spending).
///
/// # Arguments
/// * `internal_pubkey_xonly` - The 32-byte x-only internal public key
///
/// # Returns
/// The taproot tweak as a Scalar
pub fn calculate_taproot_tweak_scalar(internal_pubkey_xonly: &[u8; 32]) -> Result<Scalar> {
    use bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey;
    use bdk_wallet::bitcoin::key::{TapTweak, UntweakedPublicKey};
    use bdk_wallet::bitcoin::taproot::TapTweakHash;

    // Convert to XOnlyPublicKey
    let internal_key = XOnlyPublicKey::from_slice(internal_pubkey_xonly)?;

    // Calculate the taproot tweak hash (no merkle root for BIP86)
    let tweak_hash = TapTweakHash::from_key_and_tweak(
        UntweakedPublicKey::from(internal_key),
        None
    );

    // Convert to scalar
    let scalar = tweak_hash.to_scalar();
    Ok(scalar)
}

// ============================================================
// PROPOSAL ENCRYPTION / DECRYPTION
// ============================================================

/// Compute an 8-byte tag from the shared secret for efficient proposal matching
///
/// The tag allows receivers to quickly check if a proposal might be for them
/// without performing full decryption.
pub fn compute_proposal_tag(shared_secret: &[u8; 32]) -> [u8; 8] {
    // Hash the shared secret with a domain separator
    let mut preimage = Vec::with_capacity(32 + 21);
    preimage.extend_from_slice(shared_secret);
    preimage.extend_from_slice(b"snicker_proposal_tag");

    let hash = sha256::Hash::hash(&preimage);
    let hash_bytes = hash.to_byte_array();

    // Take first 8 bytes
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&hash_bytes[0..8]);
    tag
}

/// Encrypt a serialized proposal using ChaCha20-Poly1305
///
/// Uses the DH shared secret as the encryption key. The nonce is randomly
/// generated and prepended to the ciphertext.
///
/// # Arguments
/// * `plaintext` - The serialized proposal data
/// * `shared_secret` - The 32-byte DH shared secret
///
/// # Returns
/// Encrypted data with format: [12-byte nonce || ciphertext || 16-byte tag]
pub fn encrypt_proposal(plaintext: &[u8], shared_secret: &[u8; 32]) -> Result<Vec<u8>> {
    // Create cipher from shared secret
    let cipher = ChaCha20Poly1305::new(shared_secret.into());

    // Generate random nonce using AeadCore trait
    let nonce = ChaCha20Poly1305::generate_nonce(OsRng);

    // Encrypt
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt a proposal using ChaCha20-Poly1305
///
/// # Arguments
/// * `encrypted` - The encrypted data (nonce || ciphertext || tag)
/// * `shared_secret` - The 32-byte DH shared secret
///
/// # Returns
/// The decrypted proposal data
pub fn decrypt_proposal(encrypted: &[u8], shared_secret: &[u8; 32]) -> Result<Vec<u8>> {
    // Check minimum length (12-byte nonce + 16-byte tag)
    if encrypted.len() < 28 {
        return Err(anyhow!("Encrypted data too short"));
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Create cipher from shared secret
    let cipher = ChaCha20Poly1305::new(shared_secret.into());

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::secp256k1::rand::thread_rng;
    use bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey;
    use bdk_wallet::bitcoin::key::{TapTweak, UntweakedPublicKey};

    /// Test BIP86 key derivation using test vectors
    ///
    /// This verifies we correctly apply the taproot tweak to create P2TR outputs.
    /// Tests the formula: Q = P + H(P)*G where P is internal key, Q is output key.
    #[test]
    fn test_bip86_taproot_derivation() {
        let secp = Secp256k1::new();

        // BIP86 test vector: first receiving address m/86'/0'/0'/0/0
        // Internal key (P)
        let internal_key_hex = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115";
        let internal_key_bytes = hex::decode(internal_key_hex).unwrap();
        let internal_key = XOnlyPublicKey::from_slice(&internal_key_bytes).unwrap();

        // Expected output key (Q)
        let expected_output_key_hex = "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c";

        // Expected scriptPubKey
        let expected_script_hex = "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c";

        // Apply taproot tweak (no merkle root for BIP86)
        let untweaked = UntweakedPublicKey::from(internal_key);
        let (tweaked_key, _parity) = untweaked.tap_tweak(&secp, None);

        // Verify output key matches
        let output_key_bytes = tweaked_key.to_x_only_public_key().serialize();
        assert_eq!(
            hex::encode(&output_key_bytes),
            expected_output_key_hex,
            "Output key mismatch"
        );

        // Verify scriptPubKey matches
        let script = create_p2tr_script(&output_key_bytes);
        assert_eq!(
            hex::encode(script.as_bytes()),
            expected_script_hex,
            "ScriptPubKey mismatch"
        );

        println!("✅ BIP86 test vector passed!");
    }

    #[test]
    fn test_dh_shared_secret_symmetry() {
        let secp = Secp256k1::new();
        let mut rng = thread_rng();

        // Generate two key pairs
        let seckey_a = SecretKey::new(&mut rng);
        let pubkey_a = PublicKey::from_secret_key(&secp, &seckey_a);

        let seckey_b = SecretKey::new(&mut rng);
        let pubkey_b = PublicKey::from_secret_key(&secp, &seckey_b);

        // Calculate shared secret from both sides
        let shared_a = calculate_dh_shared_secret(&seckey_a, &pubkey_b);
        let shared_b = calculate_dh_shared_secret(&seckey_b, &pubkey_a);

        // They should be equal (ECDH symmetry property)
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn test_tweak_changes_pubkey() {
        // Use a real internal key from BIP86 test vectors
        let internal_key_hex = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115";
        let original_pubkey = hex::decode(internal_key_hex).unwrap();
        let mut original_xonly = [0u8; 32];
        original_xonly.copy_from_slice(&original_pubkey);

        // Apply a SNICKER tweak
        let snicker_tweak = [0xAA; 32];
        let tweaked = apply_taproot_tweak(&original_xonly, &snicker_tweak).unwrap();

        // Tweaked should be different from original
        assert_ne!(tweaked, original_xonly);
    }

    /// Test that secret key and public key tweaking give consistent results
    ///
    /// This simulates the full SNICKER flow with taproot:
    /// 1. Start with internal keypair (p, P)
    /// 2. Apply taproot tweak to get (q_tap, Q_tap)
    /// 3. Apply SNICKER tweak to get (q_final, Q_final)
    /// 4. Verify pubkey derived from q_final matches Q_final
    #[test]
    fn test_tweaked_seckey_derivation() {
        let secp = Secp256k1::new();
        let mut rng = thread_rng();

        // Step 1: Create internal keypair
        let mut internal_seckey = SecretKey::new(&mut rng);
        let internal_pubkey_full = PublicKey::from_secret_key(&secp, &internal_seckey);

        // BIP340: x-only keys must have even y-coordinate
        // If our pubkey has odd y, negate the secret key
        let has_odd_y = internal_pubkey_full.serialize()[0] == 0x03;
        if has_odd_y {
            internal_seckey = internal_seckey.negate();
        }

        // Get x-only internal pubkey (now guaranteed even parity)
        let internal_pubkey_xonly = {
            let pubkey = PublicKey::from_secret_key(&secp, &internal_seckey);
            let bytes = pubkey.serialize();
            assert_eq!(bytes[0], 0x02, "Internal pubkey should have even y");
            let mut xonly = [0u8; 32];
            xonly.copy_from_slice(&bytes[1..33]);
            xonly
        };

        // Step 2: Calculate taproot tweak
        let taproot_tweak_scalar = calculate_taproot_tweak_scalar(&internal_pubkey_xonly).unwrap();

        // Apply taproot tweak to secret key with parity handling
        let taproot_tweaked_seckey = apply_tweak_to_seckey_with_parity(
            &internal_seckey,
            &taproot_tweak_scalar
        ).unwrap();

        // Step 3: Apply SNICKER tweak
        let snicker_tweak = [0xBB; 32];
        let snicker_tweak_scalar = Scalar::from_be_bytes(snicker_tweak).unwrap();

        // Apply SNICKER tweak to get final secret key with parity handling
        let final_seckey = apply_tweak_to_seckey_with_parity(
            &taproot_tweaked_seckey,
            &snicker_tweak_scalar
        ).unwrap();

        // Derive public key from final secret key
        let final_pubkey_from_seckey = PublicKey::from_secret_key(&secp, &final_seckey);
        let final_xonly_from_seckey = {
            let bytes = final_pubkey_from_seckey.serialize();
            let mut xonly = [0u8; 32];
            xonly.copy_from_slice(&bytes[1..33]);
            xonly
        };

        // Step 4: Apply both tweaks to public key directly
        // First taproot tweak
        let taproot_tweaked_pubkey_xonly = apply_taproot_tweak(
            &internal_pubkey_xonly,
            &taproot_tweak_scalar.to_be_bytes()
        ).unwrap();

        // Then SNICKER tweak
        let final_pubkey_xonly = apply_taproot_tweak(
            &taproot_tweaked_pubkey_xonly,
            &snicker_tweak
        ).unwrap();

        // They should match
        assert_eq!(
            final_xonly_from_seckey,
            final_pubkey_xonly,
            "Pubkey from tweaked seckey should match directly tweaked pubkey"
        );
    }
}
