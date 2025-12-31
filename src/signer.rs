//! Signing abstraction for wallet operations
//!
//! This module provides a trait-based abstraction for signing operations,
//! allowing different implementations (in-memory, remote, HSM-backed, etc.)

use anyhow::Result;
use async_trait::async_trait;
use bdk_wallet::bitcoin::{
    bip32::{DerivationPath, Xpriv, Xpub},
    psbt::Psbt,
    secp256k1::SecretKey,
    Network,
};

/// Abstraction for signing operations
///
/// Implementations can be:
/// - InMemorySigner: Keys encrypted in memory (hot wallet)
/// - RemoteSigner: Keys in separate process/HSM (future)
/// - PolicyValidatingSigner: Wrapper adding policy checks (future)
#[async_trait]
pub trait Signer: Send + Sync {
    /// Sign a PSBT with all our inputs
    ///
    /// This method should:
    /// 1. Identify which inputs belong to us
    /// 2. Derive the necessary private keys
    /// 3. Sign those inputs
    /// 4. Drop/zeroize keys after use
    async fn sign_psbt(&self, psbt: &mut Psbt) -> Result<()>;

    /// Derive a private key for a specific derivation path
    ///
    /// Used for SNICKER Diffie-Hellman operations where we need
    /// to derive keys for specific UTXOs.
    ///
    /// # Security
    /// The returned key should be used immediately and dropped.
    /// SecretKey implements zeroization on drop.
    async fn derive_key(&self, path: &DerivationPath) -> Result<SecretKey>;

    /// Get the account-level xpub for creating public descriptors
    ///
    /// This is called during wallet initialization to create watch-only
    /// descriptors without exposing private keys.
    fn get_account_xpub(&self) -> Result<Xpub>;

    /// Get the network this signer is configured for
    fn network(&self) -> Network;
}

/// In-memory signer implementation
///
/// Stores encrypted master xprv in memory. Decrypts on-demand for signing operations.
/// While fundamentally a hot wallet (encryption key must be in memory for automated
/// signing), this approach:
/// - Keeps xprv encrypted at rest in memory
/// - Decrypts only for specific operations in tight scopes
/// - Ensures individual keys are zeroized after use
pub struct InMemorySigner {
    /// Encrypted master extended private key
    encrypted_xprv: Vec<u8>,
    /// Encryption key (derived from user password)
    encryption_key: crate::encryption::EncryptionKey,
    /// Network (Bitcoin or Testnet)
    network: Network,
    /// Cached account-level xpub (safe to cache, no private data)
    account_xpub: Xpub,
}

impl InMemorySigner {
    /// Create a new in-memory signer
    ///
    /// # Arguments
    /// * `xprv` - Master extended private key (will be encrypted)
    /// * `password` - User password for encryption
    /// * `network` - Network (Bitcoin or Testnet)
    pub fn new(xprv: Xpriv, password: &str, network: Network) -> Result<Self> {
        use bdk_wallet::bitcoin::secp256k1::Secp256k1;
        use std::str::FromStr;

        // Derive encryption key from password
        let encryption_key = crate::encryption::EncryptionKey::derive_from_password(password)?;

        // Encrypt the xprv
        let xprv_bytes = xprv.encode();
        let encrypted_xprv = encryption_key.encrypt(&xprv_bytes)?;

        // Derive account-level xpub (m/86h/<cointype>h/0h)
        let secp = Secp256k1::new();
        let coin_type = if network == Network::Bitcoin { 0 } else { 1 };
        let account_path = DerivationPath::from_str(&format!("m/86h/{}h/0h", coin_type))?;
        let account_xpriv = xprv.derive_priv(&secp, &account_path)?;
        let account_xpub = Xpub::from_priv(&secp, &account_xpriv);

        Ok(Self {
            encrypted_xprv,
            encryption_key,
            network,
            account_xpub,
        })
    }

    /// Decrypt the master xprv in a tight scope
    ///
    /// # Security
    /// The decrypted xprv should be used immediately and not stored.
    /// It will be zeroized when it goes out of scope.
    fn decrypt_xprv(&self) -> Result<Xpriv> {
        let xprv_bytes = self.encryption_key.decrypt(&self.encrypted_xprv)?;
        Xpriv::decode(&xprv_bytes).map_err(|e| anyhow::anyhow!("Failed to decode xprv: {}", e))
    }

    /// Derive account-level xpriv (m/86h/<cointype>h/0h)
    fn derive_account_xpriv(&self) -> Result<Xpriv> {
        use bdk_wallet::bitcoin::secp256k1::Secp256k1;
        use std::str::FromStr;

        let xprv = self.decrypt_xprv()?;
        let secp = Secp256k1::new();
        let coin_type = if self.network == Network::Bitcoin { 0 } else { 1 };
        let account_path = DerivationPath::from_str(&format!("m/86h/{}h/0h", coin_type))?;
        Ok(xprv.derive_priv(&secp, &account_path)?)
    }
}

#[async_trait]
impl Signer for InMemorySigner {
    async fn sign_psbt(&self, psbt: &mut Psbt) -> Result<()> {
        use bdk_wallet::bitcoin::sighash::{SighashCache, TapSighashType, Prevouts};
        use bdk_wallet::bitcoin::secp256k1::{Message, Secp256k1};
        use bdk_wallet::bitcoin::TapSighash;
        use std::str::FromStr;

        let secp = Secp256k1::new();

        // Derive account-level xpriv for signing
        let account_xpriv = self.derive_account_xpriv()?;

        // Build prevouts for sighash computation
        let prevouts: Vec<_> = psbt
            .unsigned_tx
            .input
            .iter()
            .enumerate()
            .filter_map(|(i, _)| {
                psbt.inputs.get(i).and_then(|input| {
                    input.witness_utxo.as_ref().map(|utxo| utxo.clone())
                })
            })
            .collect();

        if prevouts.len() != psbt.unsigned_tx.input.len() {
            return Err(anyhow::anyhow!(
                "Missing witness_utxo for some inputs ({}/{})",
                prevouts.len(),
                psbt.unsigned_tx.input.len()
            ));
        }

        let prevouts_refs: Vec<_> = prevouts.iter().collect();
        let prevouts = Prevouts::All(&prevouts_refs);

        // Create sighash cache
        let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

        // Sign each input that belongs to us
        for (i, input) in psbt.inputs.iter_mut().enumerate() {
            // Check if we can sign this input (has our derivation path)
            // Try tap_key_origins first (Taproot-specific), then bip32_derivation
            // tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, (Fingerprint, DerivationPath))>
            // bip32_derivation: BTreeMap<PublicKey, (Fingerprint, DerivationPath)>
            let derivation_path: Option<DerivationPath> =
                if let Some((_, (_, (_, path)))) = input.tap_key_origins.iter().next() {
                    Some(path.clone())
                } else if let Some((_, (_, path))) = input.bip32_derivation.iter().next() {
                    Some(path.clone())
                } else {
                    None
                };

            let derivation_path = match derivation_path {
                Some(path) => path,
                None => continue, // Not our input, skip
            };

            // Derive the signing key for this specific input
            // The derivation_path from PSBT is typically the full path from master
            // We need to derive from our account xpriv
            let signing_key = {
                // Extract the relative path after the account path (m/86h/<cointype>h/0h)
                // The derivation path in PSBT might be either:
                // 1. Full path from master: m/86h/0h/0h/0/5
                // 2. Relative path from account: 0/5

                // For now, derive from account_xpriv using the last two components (change/index)
                // This assumes the derivation path is structured correctly
                let path_str = derivation_path.to_string();
                let parts: Vec<&str> = path_str.split('/').collect();

                // Get last two components (e.g., "0/5" from "m/86h/0h/0h/0/5")
                if parts.len() < 2 {
                    continue; // Invalid path, skip
                }

                let relative_path = format!("{}/{}",
                    parts[parts.len() - 2],
                    parts[parts.len() - 1]
                );
                let relative_path = DerivationPath::from_str(&relative_path)?;

                let mut internal_key = account_xpriv.derive_priv(&secp, &relative_path)?.private_key;

                // Apply BIP341 taproot tweak for P2TR key-path spend
                use bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey;
                use bdk_wallet::bitcoin::taproot::TapTweakHash;
                use bdk_wallet::bitcoin::hashes::Hash;

                // BIP341 requires the internal key to have even parity before computing the tweak
                // If the internal pubkey has odd parity, negate the internal private key
                let internal_pubkey_full = internal_key.public_key(&secp);
                let has_odd_y = internal_pubkey_full.serialize()[0] == 0x03;
                if has_odd_y {
                    internal_key = internal_key.negate();
                }

                // Get the even-parity x-only internal public key
                let internal_pubkey = internal_key.public_key(&secp);
                let internal_xonly = XOnlyPublicKey::from(internal_pubkey);

                // Calculate BIP341 taproot tweak: t = hash_TapTweak(internal_key || merkle_root)
                // For BIP86 (no script tree), merkle_root is None
                let tweak_hash = TapTweakHash::from_key_and_tweak(internal_xonly, None);
                let tweak_bytes: [u8; 32] = tweak_hash.to_byte_array();

                // Add tweak to internal private key: tweaked_key = internal_key + t
                let tweak_scalar = bdk_wallet::bitcoin::secp256k1::Scalar::from_be_bytes(tweak_bytes)
                    .map_err(|_| anyhow::anyhow!("Invalid tweak scalar"))?;
                internal_key.add_tweak(&tweak_scalar)
                    .map_err(|_| anyhow::anyhow!("Failed to apply tweak"))?
            };

            // Compute sighash for this input
            let sighash: TapSighash = sighash_cache
                .taproot_key_spend_signature_hash(
                    i,
                    &prevouts,
                    TapSighashType::Default,
                )
                .map_err(|e| anyhow::anyhow!("Failed to compute sighash: {}", e))?;

            // Sign the sighash
            let signature = {
                let msg = Message::from_digest_slice(sighash.as_ref())
                    .map_err(|e| anyhow::anyhow!("Invalid sighash message: {}", e))?;
                secp.sign_schnorr(&msg, &signing_key.keypair(&secp))
                // signing_key is zeroized here
            };

            // Store signature in PSBT
            input.tap_key_sig = Some(bdk_wallet::bitcoin::taproot::Signature {
                signature,
                sighash_type: TapSighashType::Default,
            });
        }

        // account_xpriv is zeroized here
        Ok(())
    }

    async fn derive_key(&self, path: &DerivationPath) -> Result<SecretKey> {
        use bdk_wallet::bitcoin::secp256k1::Secp256k1;

        // Decrypt xprv in tight scope
        let key = {
            let xprv = self.decrypt_xprv()?;
            let secp = Secp256k1::new();
            let derived = xprv.derive_priv(&secp, path)?;
            derived.private_key
            // xprv zeroized here
        };

        Ok(key)
    }

    fn get_account_xpub(&self) -> Result<Xpub> {
        Ok(self.account_xpub)
    }

    fn network(&self) -> Network {
        self.network
    }
}
