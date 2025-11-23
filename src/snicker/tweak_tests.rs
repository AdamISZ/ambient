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
