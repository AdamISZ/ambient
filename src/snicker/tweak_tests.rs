// Unit tests for ECDH and tag computation in SNICKER protocol
use super::tweak::*;
use anyhow::Result;
use bdk_wallet::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

#[test]
fn test_ecdh_shared_secret_symmetry() -> Result<()> {
    let secp = Secp256k1::new();

    // Proposer generates ephemeral keypair
    let proposer_seckey = SecretKey::from_slice(&[0x01; 32])?;
    let proposer_pubkey = PublicKey::from_secret_key(&secp, &proposer_seckey);

    // Receiver has a keypair
    let receiver_seckey = SecretKey::from_slice(&[0x02; 32])?;
    let receiver_pubkey = PublicKey::from_secret_key(&secp, &receiver_seckey);

    // Proposer calculates: proposer_seckey * receiver_pubkey
    let proposer_shared = calculate_dh_shared_secret(&proposer_seckey, &receiver_pubkey);

    // Receiver calculates: receiver_seckey * proposer_pubkey
    let receiver_shared = calculate_dh_shared_secret(&receiver_seckey, &proposer_pubkey);

    // They should match
    assert_eq!(
        proposer_shared,
        receiver_shared,
        "ECDH shared secrets should match"
    );

    println!("✅ ECDH shared secret symmetry verified");
    println!("   Proposer shared: {}", hex::encode(proposer_shared));
    println!("   Receiver shared: {}", hex::encode(receiver_shared));

    Ok(())
}

#[test]
fn test_proposal_tag_computation() -> Result<()> {
    let secp = Secp256k1::new();

    // Proposer generates ephemeral keypair
    let proposer_seckey = SecretKey::from_slice(&[0x01; 32])?;
    let proposer_pubkey = PublicKey::from_secret_key(&secp, &proposer_seckey);

    // Receiver has a keypair
    let receiver_seckey = SecretKey::from_slice(&[0x02; 32])?;
    let receiver_pubkey = PublicKey::from_secret_key(&secp, &receiver_seckey);

    // Both parties calculate shared secret
    let proposer_shared = calculate_dh_shared_secret(&proposer_seckey, &receiver_pubkey);
    let receiver_shared = calculate_dh_shared_secret(&receiver_seckey, &proposer_pubkey);

    // Both compute tag from the same shared secret
    let proposer_tag = compute_proposal_tag(&proposer_shared);
    let receiver_tag = compute_proposal_tag(&receiver_shared);

    // Tags should match
    assert_eq!(
        proposer_tag,
        receiver_tag,
        "Proposal tags should match"
    );

    println!("✅ Proposal tag computation verified");
    println!("   Shared secret: {}", hex::encode(proposer_shared));
    println!("   Tag:           {}", hex::encode(&proposer_tag));

    Ok(())
}

#[test]
fn test_encrypt_decrypt_roundtrip() -> Result<()> {
    let secp = Secp256k1::new();

    // Generate proposer ephemeral keypair
    let proposer_seckey = SecretKey::from_slice(&[0x01; 32])?;
    let proposer_pubkey = PublicKey::from_secret_key(&secp, &proposer_seckey);

    // Generate receiver keypair
    let receiver_seckey = SecretKey::from_slice(&[0x02; 32])?;
    let receiver_pubkey = PublicKey::from_secret_key(&secp, &receiver_seckey);

    // Calculate shared secrets (should be identical)
    let proposer_shared = calculate_dh_shared_secret(&proposer_seckey, &receiver_pubkey);
    let receiver_shared = calculate_dh_shared_secret(&receiver_seckey, &proposer_pubkey);

    // Test data
    let plaintext = b"SNICKER proposal test data";

    // Proposer encrypts
    let ciphertext = encrypt_proposal(plaintext, &proposer_shared)?;

    // Receiver decrypts
    let decrypted = decrypt_proposal(&ciphertext, &receiver_shared)?;

    // Should match original
    assert_eq!(
        plaintext.to_vec(),
        decrypted,
        "Decrypted data should match original"
    );

    println!("✅ Encrypt/decrypt roundtrip verified");
    println!("   Plaintext:  {}", hex::encode(plaintext));
    println!("   Ciphertext: {} ({} bytes)", hex::encode(&ciphertext[..32.min(ciphertext.len())]), ciphertext.len());
    println!("   Decrypted:  {}", hex::encode(&decrypted));

    Ok(())
}

#[test]
fn test_extract_taproot_pubkey() -> Result<()> {
    use bdk_wallet::bitcoin::{secp256k1::XOnlyPublicKey, ScriptBuf, TxOut, Amount};
    use bdk_wallet::bitcoin::key::TapTweak;

    let secp = Secp256k1::new();

    // Create a test keypair
    let seckey = SecretKey::from_slice(&[0x03; 32])?;
    let pubkey = PublicKey::from_secret_key(&secp, &seckey);
    let xonly = XOnlyPublicKey::from(pubkey);

    // Create a P2TR output using new_p2tr which applies the tweak internally
    // new_p2tr takes the INTERNAL key and applies BIP341 tweak
    let script = ScriptBuf::new_p2tr(&secp, xonly, None);

    let txout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: script,
    };

    // Calculate what the output key should be
    let (expected_output_key, _parity) = xonly.tap_tweak(&secp, None);

    // Extract the pubkey from the script
    let extracted = extract_taproot_pubkey(&txout)?;

    println!("✅ Taproot pubkey extraction verified");
    println!("   Internal key:   {}", hex::encode(xonly.serialize()));
    println!("   Expected output key: {}", hex::encode(expected_output_key.to_inner().serialize()));
    println!("   Extracted:           {}", hex::encode(extracted));

    // The extracted key should match the tweaked output key
    assert_eq!(extracted, expected_output_key.to_inner().serialize());

    Ok(())
}

#[test]
fn test_create_tweaked_output_valid() -> Result<()> {
    use bdk_wallet::bitcoin::{Amount, TxOut, ScriptBuf};

    let secp = Secp256k1::new();

    // Create receiver's keypair
    let receiver_seckey = SecretKey::from_slice(&[0x02; 32])?;
    let receiver_pubkey = PublicKey::from_secret_key(&secp, &receiver_seckey);
    let receiver_xonly = bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey::from(receiver_pubkey);

    // Create receiver's original output
    let original_output = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, receiver_xonly, None),
    };

    // Create proposer's keypair (for SNICKER tweak)
    let proposer_seckey = SecretKey::from_slice(&[0x01; 32])?;
    let proposer_pubkey = PublicKey::from_secret_key(&secp, &proposer_seckey);

    // Create tweaked output
    let (tweaked_output, snicker_shared_secret) = create_tweaked_output(
        &original_output,
        &proposer_seckey,
        &receiver_pubkey
    )?;

    // Verify tweaked output has same value
    assert_eq!(tweaked_output.value, original_output.value);

    // Verify tweaked output is P2TR
    assert!(tweaked_output.script_pubkey.is_p2tr());

    // Verify tweaked output is different from original
    assert_ne!(tweaked_output.script_pubkey, original_output.script_pubkey);

    // Verify shared secret is 32 bytes
    assert_eq!(snicker_shared_secret.len(), 32);

    println!("✅ Created valid tweaked output");
    println!("   Original script: {}", hex::encode(original_output.script_pubkey.as_bytes()));
    println!("   Tweaked script:  {}", hex::encode(tweaked_output.script_pubkey.as_bytes()));

    Ok(())
}

#[test]
fn test_verify_tweaked_output_correct() -> Result<()> {
    use bdk_wallet::bitcoin::{Amount, TxOut, ScriptBuf};

    let secp = Secp256k1::new();

    // Create receiver's keypair
    let receiver_seckey = SecretKey::from_slice(&[0x02; 32])?;
    let receiver_pubkey = PublicKey::from_secret_key(&secp, &receiver_seckey);
    let receiver_xonly = bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey::from(receiver_pubkey);

    // Create receiver's original output
    let original_output = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, receiver_xonly, None),
    };

    // Create proposer's keypair
    let proposer_seckey = SecretKey::from_slice(&[0x01; 32])?;
    let proposer_pubkey = PublicKey::from_secret_key(&secp, &proposer_seckey);

    // Create tweaked output
    let (tweaked_output, _) = create_tweaked_output(
        &original_output,
        &proposer_seckey,
        &receiver_pubkey
    )?;

    // Verify the tweak is correct
    let result = verify_tweaked_output(
        &original_output,
        &tweaked_output,
        &receiver_seckey,
        &proposer_pubkey
    );

    assert!(result.is_ok(), "Valid tweak verification should succeed");

    println!("✅ Tweak verification succeeded for valid tweak");

    Ok(())
}

#[test]
fn test_verify_tweaked_output_wrong_key() -> Result<()> {
    use bdk_wallet::bitcoin::{Amount, TxOut, ScriptBuf};

    let secp = Secp256k1::new();

    // Create receiver's keypair
    let receiver_seckey = SecretKey::from_slice(&[0x02; 32])?;
    let receiver_pubkey = PublicKey::from_secret_key(&secp, &receiver_seckey);
    let receiver_xonly = bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey::from(receiver_pubkey);

    // Create receiver's original output
    let original_output = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, receiver_xonly, None),
    };

    // Create proposer's keypair
    let proposer_seckey = SecretKey::from_slice(&[0x01; 32])?;
    let proposer_pubkey = PublicKey::from_secret_key(&secp, &proposer_seckey);

    // Create tweaked output using proposer's key
    let (tweaked_output, _) = create_tweaked_output(
        &original_output,
        &proposer_seckey,
        &receiver_pubkey
    )?;

    // Try to verify with WRONG proposer key (use a valid but different key)
    let wrong_proposer_seckey = SecretKey::from_slice(&[0x03; 32])?;
    let wrong_proposer_pubkey = PublicKey::from_secret_key(&secp, &wrong_proposer_seckey);

    let result = verify_tweaked_output(
        &original_output,
        &tweaked_output,
        &receiver_seckey,
        &wrong_proposer_pubkey  // Wrong key!
    );

    assert!(result.is_err(), "Tweak verification with wrong key should fail");

    println!("✅ Tweak verification correctly rejected wrong proposer key");

    Ok(())
}

#[test]
fn test_derive_tweaked_seckey_spendable() -> Result<()> {
    use bdk_wallet::bitcoin::{Amount, TxOut, ScriptBuf, secp256k1::XOnlyPublicKey};
    use bdk_wallet::bitcoin::secp256k1::Scalar;

    let secp = Secp256k1::new();

    // Create receiver's INTERNAL keypair
    let mut receiver_internal_seckey = SecretKey::from_slice(&[0x02; 32])?;
    let receiver_internal_pubkey = PublicKey::from_secret_key(&secp, &receiver_internal_seckey);

    // Ensure internal key has even parity (BIP340 requirement)
    let has_odd_y = receiver_internal_pubkey.serialize()[0] == 0x03;
    if has_odd_y {
        receiver_internal_seckey = receiver_internal_seckey.negate();
    }

    let receiver_xonly = XOnlyPublicKey::from(PublicKey::from_secret_key(&secp, &receiver_internal_seckey));

    // Create receiver's original output (this applies taproot tweak internally)
    let original_output = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, receiver_xonly, None),
    };

    // Apply taproot tweak to the internal secret key to get the key that can spend original_output
    let receiver_xonly_bytes = receiver_xonly.serialize();
    let taproot_tweak_scalar = calculate_taproot_tweak_scalar(&receiver_xonly_bytes)?;
    let receiver_taproot_tweaked_seckey = apply_tweak_to_seckey_with_parity(
        &receiver_internal_seckey,
        &taproot_tweak_scalar
    )?;

    // Create proposer's keypair
    let proposer_seckey = SecretKey::from_slice(&[0x01; 32])?;
    let proposer_pubkey = PublicKey::from_secret_key(&secp, &proposer_seckey);

    // Create tweaked output (applies SNICKER tweak on top of taproot tweak)
    let (tweaked_output, _) = create_tweaked_output(
        &original_output,
        &proposer_seckey,
        &PublicKey::from_secret_key(&secp, &receiver_internal_seckey)
    )?;

    // Calculate shared secret
    let snicker_shared_secret = calculate_dh_shared_secret(&receiver_internal_seckey, &proposer_pubkey);

    // Derive final tweaked secret key (applies SNICKER tweak to taproot-tweaked key)
    let final_tweaked_seckey = derive_tweaked_seckey(&receiver_taproot_tweaked_seckey, &snicker_shared_secret)?;

    // Derive public key from final tweaked secret key
    let final_tweaked_pubkey = PublicKey::from_secret_key(&secp, &final_tweaked_seckey);
    let final_tweaked_xonly = XOnlyPublicKey::from(final_tweaked_pubkey);

    // Extract the public key from the tweaked output script
    let extracted_pubkey = extract_taproot_pubkey(&tweaked_output)?;

    // Verify the derived secret key corresponds to the output's public key
    assert_eq!(
        final_tweaked_xonly.serialize(),
        extracted_pubkey,
        "Derived tweaked secret key should correspond to output's public key"
    );

    println!("✅ Derived tweaked secret key can spend the tweaked output");
    println!("   Tweaked pubkey: {}", hex::encode(final_tweaked_xonly.serialize()));
    println!("   Output pubkey:  {}", hex::encode(extracted_pubkey));

    Ok(())
}

// ============================================================
// ENCRYPTION ERROR HANDLING TESTS
// ============================================================

#[test]
fn test_decrypt_with_wrong_key() -> Result<()> {
    let secp = Secp256k1::new();

    // Generate proposer keypair
    let proposer_seckey = SecretKey::from_slice(&[0x01; 32])?;
    let proposer_pubkey = PublicKey::from_secret_key(&secp, &proposer_seckey);

    // Generate receiver keypair
    let receiver_seckey = SecretKey::from_slice(&[0x02; 32])?;
    let receiver_pubkey = PublicKey::from_secret_key(&secp, &receiver_seckey);

    // Generate WRONG keypair for decryption attempt
    let wrong_seckey = SecretKey::from_slice(&[0x03; 32])?;
    let wrong_pubkey = PublicKey::from_secret_key(&secp, &wrong_seckey);

    // Calculate correct shared secret (proposer perspective)
    let correct_shared = calculate_dh_shared_secret(&proposer_seckey, &receiver_pubkey);

    // Calculate WRONG shared secret (using wrong receiver key)
    let wrong_shared = calculate_dh_shared_secret(&proposer_seckey, &wrong_pubkey);

    // Test data
    let plaintext = b"SNICKER proposal test data";

    // Encrypt with correct shared secret
    let ciphertext = encrypt_proposal(plaintext, &correct_shared)?;

    // Try to decrypt with WRONG shared secret
    let decrypt_result = decrypt_proposal(&ciphertext, &wrong_shared);

    // Should fail - wrong key produces authentication error
    assert!(decrypt_result.is_err(), "Decryption with wrong key should fail");

    println!("✅ Decryption correctly rejected wrong shared secret");

    Ok(())
}

#[test]
fn test_decrypt_corrupted_data() -> Result<()> {
    let secp = Secp256k1::new();

    // Generate proposer keypair
    let proposer_seckey = SecretKey::from_slice(&[0x01; 32])?;
    let proposer_pubkey = PublicKey::from_secret_key(&secp, &proposer_seckey);

    // Generate receiver keypair
    let receiver_seckey = SecretKey::from_slice(&[0x02; 32])?;
    let receiver_pubkey = PublicKey::from_secret_key(&secp, &receiver_seckey);

    // Calculate shared secret
    let shared = calculate_dh_shared_secret(&proposer_seckey, &receiver_pubkey);

    // Test data
    let plaintext = b"SNICKER proposal test data";

    // Encrypt
    let mut ciphertext = encrypt_proposal(plaintext, &shared)?;

    // Corrupt the ciphertext (flip some bits)
    if ciphertext.len() > 10 {
        ciphertext[5] ^= 0xFF;  // Flip all bits in one byte
    }

    // Try to decrypt corrupted data
    let decrypt_result = decrypt_proposal(&ciphertext, &shared);

    // Should fail - ChaCha20-Poly1305 authentication should detect corruption
    assert!(decrypt_result.is_err(), "Decryption of corrupted data should fail");

    println!("✅ Decryption correctly rejected corrupted ciphertext");

    Ok(())
}
