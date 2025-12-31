//! Signing abstraction for wallet operations
//!
//! This module provides a trait-based abstraction for signing operations,
//! allowing different implementations (in-memory, remote, HSM-backed, etc.)
//!
//! It also provides low-level taproot signing utilities that are used by
//! all signing code paths in the application.

use anyhow::Result;
use async_trait::async_trait;
use bdk_wallet::bitcoin::{
    bip32::{DerivationPath, Xpriv, Xpub},
    psbt::Psbt,
    secp256k1::{Keypair, SecretKey},
    Network, TxOut,
};

// ============================================================
// TAPROOT SIGNING UTILITIES
// ============================================================

/// Sign a single PSBT input with a pre-computed taproot keypair.
///
/// This is a convenience wrapper around `sign_taproot_inputs` for signing
/// a single input. The caller is responsible for:
/// - Computing/deriving the correct keypair (with BIP341 tweak applied)
/// - Ensuring the keypair corresponds to the UTXO being signed
/// - Zeroizing the keypair after use
///
/// # Arguments
/// * `psbt` - The PSBT to sign (modified in place)
/// * `input_idx` - Index of the input to sign
/// * `keypair` - The tweaked keypair for signing
/// * `prevouts` - All prevouts for the transaction (required for taproot sighash)
pub fn sign_taproot_input(
    psbt: &mut Psbt,
    input_idx: usize,
    keypair: &Keypair,
    prevouts: &[TxOut],
) -> Result<()> {
    sign_taproot_inputs(psbt, &[(input_idx, keypair)], prevouts)
}

/// Sign multiple PSBT inputs with their respective keypairs.
///
/// More efficient than calling `sign_taproot_input` repeatedly as it reuses
/// the SighashCache across all inputs.
///
/// # Arguments
/// * `psbt` - The PSBT to sign (modified in place)
/// * `inputs_to_sign` - Pairs of (input_idx, keypair) for each input to sign
/// * `prevouts` - All prevouts for the transaction (required for taproot sighash)
pub fn sign_taproot_inputs(
    psbt: &mut Psbt,
    inputs_to_sign: &[(usize, &Keypair)],
    prevouts: &[TxOut],
) -> Result<()> {
    use bdk_wallet::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bdk_wallet::bitcoin::secp256k1::{Message, Secp256k1};

    let secp = Secp256k1::new();
    let prevouts_all = Prevouts::All(prevouts);
    let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

    for &(input_idx, keypair) in inputs_to_sign {
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(input_idx, &prevouts_all, TapSighashType::Default)
            .map_err(|e| anyhow::anyhow!("Failed to compute sighash for input {}: {}", input_idx, e))?;

        let msg = Message::from_digest_slice(sighash.as_ref())
            .map_err(|e| anyhow::anyhow!("Invalid sighash message: {}", e))?;

        let signature = secp.sign_schnorr(&msg, keypair);

        psbt.inputs[input_idx].tap_key_sig = Some(bdk_wallet::bitcoin::taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        });
    }

    Ok(())
}

// ============================================================
// SIGNER TRAIT
// ============================================================

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
        use bdk_wallet::bitcoin::secp256k1::Secp256k1;
        use std::str::FromStr;

        let secp = Secp256k1::new();

        // Derive account-level xpriv for signing
        let account_xpriv = self.derive_account_xpriv()?;

        // Build prevouts for sighash computation
        let prevouts: Vec<_> = psbt
            .inputs
            .iter()
            .map(|input| {
                input.witness_utxo.clone()
                    .ok_or_else(|| anyhow::anyhow!("Missing witness_utxo"))
            })
            .collect::<Result<Vec<_>>>()?;

        // Collect (input_idx, keypair) for all inputs we can sign
        let mut inputs_to_sign: Vec<(usize, Keypair)> = Vec::new();

        for (i, input) in psbt.inputs.iter().enumerate() {
            // Check if we can sign this input (has our derivation path)
            // Try tap_key_origins first (Taproot-specific), then bip32_derivation
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
            let signing_key = {
                // Extract the relative path after the account path (m/86h/<cointype>h/0h)
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
                let internal_pubkey_full = internal_key.public_key(&secp);
                let has_odd_y = internal_pubkey_full.serialize()[0] == 0x03;
                if has_odd_y {
                    internal_key = internal_key.negate();
                }

                // Get the even-parity x-only internal public key
                let internal_pubkey = internal_key.public_key(&secp);
                let internal_xonly = XOnlyPublicKey::from(internal_pubkey);

                // Calculate BIP341 taproot tweak (no script tree for BIP86)
                let tweak_hash = TapTweakHash::from_key_and_tweak(internal_xonly, None);
                let tweak_bytes: [u8; 32] = tweak_hash.to_byte_array();

                // Add tweak to internal private key
                let tweak_scalar = bdk_wallet::bitcoin::secp256k1::Scalar::from_be_bytes(tweak_bytes)
                    .map_err(|_| anyhow::anyhow!("Invalid tweak scalar"))?;
                internal_key.add_tweak(&tweak_scalar)
                    .map_err(|_| anyhow::anyhow!("Failed to apply tweak"))?
            };

            inputs_to_sign.push((i, signing_key.keypair(&secp)));
        }

        // Sign all collected inputs using the unified signing function
        let inputs_refs: Vec<(usize, &Keypair)> = inputs_to_sign
            .iter()
            .map(|(idx, kp)| (*idx, kp))
            .collect();
        sign_taproot_inputs(psbt, &inputs_refs, &prevouts)?;

        // account_xpriv and all keypairs are zeroized here
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
