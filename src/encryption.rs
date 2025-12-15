//! Wallet file encryption using ChaCha20-Poly1305 and Argon2id
//!
//! This module provides encryption for the three critical wallet files:
//! - mnemonic.enc: The BIP39 seed phrase
//! - wallet.sqlite.enc: BDK wallet database
//! - snicker.sqlite.enc: SNICKER private keys database
//!
//! ## Security Features
//! - ChaCha20-Poly1305 AEAD cipher (authenticated encryption)
//! - Argon2id key derivation (memory-hard, GPU-resistant)
//! - Random salt and nonce per encryption
//!
//! ## File Format
//! ```text
//! [Version(1) | Salt(32) | Nonce(12) | Ciphertext | Tag(16)]
//! ```
//!
//! ## Security Note
//! No attempt tracking is implemented as it provides no real security on general-purpose
//! computers where attackers have filesystem access. Security relies on:
//! - Strong password (user responsibility)
//! - Expensive KDF (Argon2id with 64MB memory, 3 iterations)
//!
//! ## TODOs for v2
//! - [ ] Password strength validation/enforcement
//! - [ ] Per-spending-event decryption
//! - [ ] Password change functionality
//! - [ ] In-memory database decryption
//! - [ ] Secure memory zeroing (zeroize crate)

use anyhow::{anyhow, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;

/// Current encryption format version
const VERSION: u8 = 0x01;

/// Argon2id parameters (tuned for security vs performance)
const ARGON2_MEM_COST: u32 = 65536; // 64 MB
const ARGON2_TIME_COST: u32 = 3; // 3 iterations
const ARGON2_PARALLELISM: u32 = 4; // 4 threads
const ARGON2_OUTPUT_LEN: usize = 32; // 32 bytes (256 bits)

/// Salt length for Argon2id
const SALT_LEN: usize = 32;

/// Nonce length for ChaCha20-Poly1305
const NONCE_LEN: usize = 12;

/// Authentication tag length for Poly1305
const TAG_LEN: usize = 16;

/// Wallet file encryption manager
///
/// Handles encryption/decryption of wallet files with password-based key derivation.
pub struct WalletEncryption;

impl WalletEncryption {
    /// Create a new encryption manager
    pub fn new() -> Self {
        Self
    }

    /// Derive encryption key from password using Argon2id
    ///
    /// # Arguments
    /// * `password` - User password
    /// * `salt` - 32-byte salt
    ///
    /// # Returns
    /// 32-byte encryption key
    fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<[u8; ARGON2_OUTPUT_LEN]> {
        let params = Params::new(
            ARGON2_MEM_COST,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(ARGON2_OUTPUT_LEN),
        )
        .map_err(|e| anyhow!("Failed to create Argon2 params: {}", e))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        // Create password hash with the salt
        let salt_string =
            SaltString::encode_b64(salt).map_err(|e| anyhow!("Failed to encode salt: {}", e))?;

        let hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| anyhow!("Failed to hash password: {}", e))?;

        // Extract the raw key bytes from the hash
        let key_bytes = hash
            .hash
            .ok_or_else(|| anyhow!("Password hash missing hash output"))?;

        let mut key = [0u8; ARGON2_OUTPUT_LEN];
        let hash_bytes = key_bytes.as_bytes();
        if hash_bytes.len() != ARGON2_OUTPUT_LEN {
            return Err(anyhow!(
                "Expected {} bytes from Argon2, got {}",
                ARGON2_OUTPUT_LEN,
                hash_bytes.len()
            ));
        }
        key.copy_from_slice(hash_bytes);

        Ok(key)
    }

    /// Encrypt data with password
    ///
    /// # File Format
    /// ```text
    /// [Version(1) | Salt(32) | Nonce(12) | Ciphertext | Tag(16)]
    /// ```
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `password` - Encryption password
    ///
    /// # Returns
    /// Encrypted file bytes
    pub fn encrypt_file(plaintext: &[u8], password: &str) -> Result<Vec<u8>> {
        // Generate random salt
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        // Derive encryption key
        let key = Self::derive_key(password, &salt)?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create cipher
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        // Encrypt plaintext
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Build encrypted file: [version | salt | nonce | ciphertext+tag]
        let mut output = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + ciphertext.len());
        output.push(VERSION);
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        tracing::debug!(
            "Encrypted {} bytes → {} bytes (overhead: {} bytes)",
            plaintext.len(),
            output.len(),
            output.len() - plaintext.len()
        );

        Ok(output)
    }

    /// Decrypt data with password
    ///
    /// # Arguments
    /// * `encrypted` - Encrypted file bytes
    /// * `password` - Decryption password
    ///
    /// # Returns
    /// Decrypted plaintext
    pub fn decrypt_file(encrypted: &[u8], password: &str) -> Result<Vec<u8>> {
        // Parse encrypted file format
        if encrypted.len() < 1 + SALT_LEN + NONCE_LEN + TAG_LEN {
            return Err(anyhow!("Encrypted file too small (corrupted?)"));
        }

        let version = encrypted[0];
        if version != VERSION {
            return Err(anyhow!(
                "Unsupported encryption version: 0x{:02x} (expected 0x{:02x})",
                version,
                VERSION
            ));
        }

        let salt: [u8; SALT_LEN] = encrypted[1..1 + SALT_LEN]
            .try_into()
            .map_err(|_| anyhow!("Failed to parse salt"))?;

        let nonce_bytes: [u8; NONCE_LEN] = encrypted[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN]
            .try_into()
            .map_err(|_| anyhow!("Failed to parse nonce"))?;

        let ciphertext = &encrypted[1 + SALT_LEN + NONCE_LEN..];

        // Derive key from password
        let key = Self::derive_key(password, &salt)?;

        // Create cipher
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        let nonce = Nonce::from_slice(&nonce_bytes);

        // Attempt decryption
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("Wrong password or corrupted file"))?;

        tracing::debug!(
            "Decrypted {} bytes → {} bytes",
            encrypted.len(),
            plaintext.len()
        );

        Ok(plaintext)
    }
}

impl Default for WalletEncryption {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello, World! This is a secret message.";
        let password = "my_secure_password_123";

        // Encrypt
        let encrypted = WalletEncryption::encrypt_file(plaintext, password).unwrap();

        // Should have overhead (version + salt + nonce + tag)
        assert!(encrypted.len() > plaintext.len());

        // Decrypt
        let decrypted = WalletEncryption::decrypt_file(&encrypted, password).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_wrong_password() {
        let plaintext = b"Secret data";
        let password = "correct_password";
        let wrong_password = "wrong_password";

        let encrypted = WalletEncryption::encrypt_file(plaintext, password).unwrap();

        let result = WalletEncryption::decrypt_file(&encrypted, wrong_password);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Wrong password"));
    }

    #[test]
    fn test_different_passwords_produce_different_ciphertexts() {
        let plaintext = b"Same data";
        let password1 = "password1";
        let password2 = "password2";

        let encrypted1 = WalletEncryption::encrypt_file(plaintext, password1).unwrap();
        let encrypted2 = WalletEncryption::encrypt_file(plaintext, password2).unwrap();

        // Different salts/nonces means different ciphertexts
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_version_check() {
        let plaintext = b"Data";
        let password = "pass";

        let mut encrypted = WalletEncryption::encrypt_file(plaintext, password).unwrap();

        // Corrupt version byte
        encrypted[0] = 0xFF;

        let result = WalletEncryption::decrypt_file(&encrypted, password);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));
    }

    #[test]
    fn test_empty_data() {
        let plaintext = b"";
        let password = "password";

        let encrypted = WalletEncryption::encrypt_file(plaintext, password).unwrap();

        let decrypted = WalletEncryption::decrypt_file(&encrypted, password).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_large_data() {
        let plaintext = vec![0x42u8; 1_000_000]; // 1 MB
        let password = "password";

        let encrypted = WalletEncryption::encrypt_file(&plaintext, password).unwrap();

        let decrypted = WalletEncryption::decrypt_file(&encrypted, password).unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
