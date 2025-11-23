# SNICKER Protocol Implementation

**SNICKER**: Simple Non-Interactive Coinjoin with Keys for Encryption Reused

This document describes the complete end-to-end SNICKER protocol as implemented in RustSnicker.

## Table of Contents

1. [Overview](#overview)
2. [Key Concepts](#key-concepts)
3. [Cryptographic Primitives](#cryptographic-primitives)
4. [Protocol Roles](#protocol-roles)
5. [End-to-End Protocol Flow](#end-to-end-protocol-flow)
6. [Transaction Structure](#transaction-structure)
7. [Recovery Mechanism](#recovery-mechanism)
8. [Security Properties](#security-properties)

---

## Overview

SNICKER enables two parties to create a coinjoin transaction without direct communication. The **proposer** (Bob) creates a partially-signed transaction proposal and encrypts it using the **receiver's** (Alice) public key. The receiver discovers and decrypts proposals meant for them, validates them, and decides whether to sign and broadcast.

### Key Innovation: Recoverable Tweaks

This implementation uses the **proposer's input public key** (not an ephemeral key) for the SNICKER tweak. This critical design choice enables **wallet recovery from seed phrase alone** by allowing receivers to scan spent UTXOs and re-derive tweaked outputs.

### Non-Interactive Property

Once the proposer publishes an encrypted proposal:
- The receiver never communicates back to the proposer
- The receiver simply broadcasts (or doesn't) the completed transaction
- The proposer monitors the blockchain to see if their proposal was accepted

---

## Key Concepts

### 1. BIP86 Taproot Wallets

Both parties use BIP86 (keypath-only) Taproot wallets:
- Derivation path: `m/86'/0'/0'/0/*` (external addresses)
- Output format: P2TR (Pay-to-Taproot)
- Internal key tweaked by: `output_key = internal_key + hash(internal_key)*G`

### 2. Key Tweaking

SNICKER applies an additional tweak on top of the BIP86 taproot tweak:

```
Step 1 (BIP86):  output_key = internal_key + taproot_tweak*G
Step 2 (SNICKER): final_key = output_key + snicker_tweak*G
```

Where:
- `taproot_tweak = SHA256(tag || internal_key)` (BIP341)
- `snicker_tweak = ECDH(proposer_input_seckey, receiver_output_pubkey)`

### 3. Separate Encryption vs. Tweak Keys

The protocol uses **two different key derivations**:

- **Encryption Key**: Ephemeral random keypair
  - Used to encrypt the proposal PSBT data
  - Enables privacy (proposal not linked to proposer's identity)
  - Discarded after receiver decrypts

- **SNICKER Tweak Key**: Proposer's INPUT public key
  - Used to compute the shared secret for output tweaking
  - Enables recovery (deterministic, on-chain visible)
  - Receiver extracts from PSBT witness during validation

### 4. Proposal Structure

**Unencrypted Proposal**:
```rust
struct Proposal {
    psbt: Psbt,              // Partially-signed by proposer
    tweak_info: TweakInfo,   // Tweak metadata
}

struct TweakInfo {
    original_output: TxOut,      // Receiver's original output
    tweaked_output: TxOut,       // Receiver's tweaked output
    proposer_pubkey: PublicKey,  // Proposer's INPUT pubkey
}
```

**Encrypted Proposal**:
```rust
struct EncryptedProposal {
    ephemeral_pubkey: PublicKey,  // For encryption only
    tag: [u8; 8],                 // Fast matching filter
    encrypted_data: Vec<u8>,      // ChaCha20-Poly1305 ciphertext
}
```

---

## Cryptographic Primitives

### ECDH (Elliptic Curve Diffie-Hellman)

Both parties derive the same shared secret:
```
shared_secret = SHA256(bob_seckey * alice_pubkey)
              = SHA256(alice_seckey * bob_pubkey)
```

### ChaCha20-Poly1305 Encryption

Authenticated encryption of proposal data:
- Key: 32-byte ECDH shared secret
- Nonce: 12-byte random (prepended to ciphertext)
- Output: `[nonce || ciphertext || 16-byte auth tag]`

### Proposal Tag

Fast 8-byte filter for efficient proposal matching:
```
tag = first_8_bytes(SHA256(shared_secret || "snicker_proposal_tag"))
```

Receiver computes expected tag for each of their UTXOs to identify potential proposals without full decryption.

---

## Protocol Roles

### Proposer (Bob)

Bob wants to create a coinjoin with someone else's UTXO. He:
1. Scans blockchain for candidate UTXOs
2. Selects a candidate to co-spend with one of his UTXOs
3. Creates a partially-signed PSBT proposing the coinjoin
4. Encrypts and publishes the proposal
5. Monitors blockchain to see if proposal is accepted

### Receiver (Alice)

Alice has UTXOs that Bob might want to coinjoin with. She:
1. Scans stored proposals for ones meant for her UTXOs
2. Decrypts and validates matching proposals
3. Decides whether to accept based on fees and privacy benefit
4. Signs and broadcasts if accepting (or ignores if rejecting)
5. Tracks the resulting SNICKER UTXO separately

---

## End-to-End Protocol Flow

### Phase 1: Setup

**Both parties** have BIP86 Taproot wallets with confirmed UTXOs.

**Example**:
- Alice has 3 UTXOs: 50k, 80k, 120k sats
- Bob has 2 UTXOs: 100k, 200k sats

### Phase 2: Candidate Discovery (Proposer)

**Bob scans the blockchain** looking for potential SNICKER candidates:

```rust
// Scan last N blocks for P2TR outputs in size range
let candidates = bob.scan_for_snicker_candidates(
    num_blocks: 10,
    size_min: 10_000,
    size_max: 150_000,
).await?;
```

**Candidate criteria**:
- Output is P2TR (Taproot)
- Value within specified range (e.g., 10k-150k sats)
- Not already spent

**Database storage**: Candidates stored in `snicker_candidates` table for later use.

### Phase 3: Opportunity Finding (Proposer)

**Bob matches his UTXOs** with stored candidates:

```rust
// Find opportunities where Bob's UTXO can match with candidates
let opportunities = bob.find_snicker_opportunities(
    min_utxo_sats: 75_000,
).await?;
```

**Opportunity criteria**:
- Bob's UTXO ≥ minimum threshold (e.g., 75k sats)
- Candidate UTXO value compatible for creating equal outputs
- Sufficient funds to cover fees and create non-dust outputs

**Output**: List of `ProposalOpportunity` structs:
```rust
struct ProposalOpportunity {
    our_outpoint: OutPoint,        // Bob's UTXO
    our_value: Amount,             // Bob's UTXO value
    target_tx: Transaction,        // Candidate's transaction
    target_output_index: usize,    // Which output to co-spend
    target_value: Amount,          // Candidate's value
}
```

### Phase 4: Proposal Creation (Proposer)

**Bob creates a SNICKER proposal** for a selected opportunity:

```rust
let (signed_psbt, encrypted_proposal) = bob.create_snicker_proposal(
    opportunity,
    delta_sats: 1000,  // Alice pays 1000 sats more
).await?;
```

**Step-by-step process**:

#### 4.1: Extract Proposer's Input Key

```rust
// Bob derives his input private key (will be used for SNICKER tweak)
let proposer_input_seckey = wallet.derive_utxo_privkey(keychain, index)?;
let proposer_input_pubkey = proposer_input_seckey.public_key(&secp);
```

#### 4.2: Calculate SNICKER Tweak

```rust
// Extract Alice's output pubkey (x-only) from her P2TR output
let alice_pubkey_xonly = extract_taproot_pubkey(&alice_output)?;

// Convert to full pubkey (assume even parity)
let alice_pubkey = PublicKey::from_xonly(alice_pubkey_xonly);

// Calculate ECDH shared secret using proposer's INPUT key
let snicker_shared_secret = ECDH(proposer_input_seckey, alice_pubkey);

// Apply tweak to Alice's output key
let alice_tweaked_pubkey = alice_pubkey + snicker_shared_secret*G;
```

#### 4.3: Build Transaction Structure

The PSBT contains:

**Inputs (2)**:
1. Alice's original output (index 0)
2. Bob's selected UTXO (index 1)

**Outputs (3)**:
1. Alice's equal output (tweaked, index 0) - equal_output_amount
2. Bob's equal output (index 1) - equal_output_amount
3. Bob's change output (index 2) - remaining funds

**Fee structure**:
```
equal_output = alice_original - delta
total_in = alice_original + bob_original
total_out = 2 * equal_output + change
fees = total_in - total_out
```

With delta=1000:
- Alice pays: `alice_original - equal_output = delta = 1000` sats
- Bob pays: remaining fees

#### 4.4: Sign Proposer's Input

```rust
// Bob signs his input (index 1) with his wallet
wallet.sign(&mut psbt)?;

// PSBT now has:
// - Input 0 (Alice): unsigned
// - Input 1 (Bob): signed ✓
```

#### 4.5: Encrypt Proposal

```rust
// Generate ephemeral keypair for encryption privacy
let ephemeral_seckey = SecretKey::random();
let ephemeral_pubkey = ephemeral_seckey.public_key();

// Calculate encryption shared secret (separate from SNICKER tweak)
let encryption_shared_secret = ECDH(ephemeral_seckey, alice_pubkey);

// Compute 8-byte tag for fast matching
let tag = SHA256(encryption_shared_secret || "snicker_proposal_tag")[0..8];

// Create proposal struct
let proposal = Proposal {
    psbt: signed_psbt,  // Contains Bob's signature
    tweak_info: TweakInfo {
        original_output: alice_original_output,
        tweaked_output: alice_tweaked_output,
        proposer_pubkey: proposer_input_pubkey,  // Important for recovery!
    }
};

// Serialize and encrypt
let proposal_bytes = serialize(proposal);
let encrypted_data = ChaCha20Poly1305::encrypt(
    proposal_bytes,
    encryption_shared_secret
);

// Package for publication
let encrypted_proposal = EncryptedProposal {
    ephemeral_pubkey,
    tag,
    encrypted_data,
};
```

### Phase 5: Proposal Publication (Proposer)

**Bob publishes the encrypted proposal**:

```rust
bob.store_snicker_proposal(&encrypted_proposal).await?;
```

**Database storage**: Stored in `snicker_proposals` table. In a real deployment, this would be:
- Posted to a bulletin board service
- Broadcast via P2P network
- Uploaded to a coordinator server
- Stored in a distributed hash table (DHT)

### Phase 6: Proposal Discovery (Receiver)

**Alice scans for proposals** meant for her UTXOs:

```rust
let proposals = alice.scan_for_our_proposals(
    acceptable_delta_range: (-2000, 5000)
).await?;
```

**Step-by-step process**:

#### 6.1: Get Encrypted Proposals

```rust
// Fetch all stored encrypted proposals
let encrypted_proposals = db.get_all_snicker_proposals()?;
```

#### 6.2: Try Each UTXO

For each of Alice's UTXOs:

```rust
for utxo in alice_utxos {
    // Derive Alice's private key for this UTXO
    let alice_seckey = wallet.derive_utxo_privkey(
        utxo.keychain,
        utxo.derivation_index
    )?;

    // Try to decrypt each proposal
    for encrypted_proposal in &encrypted_proposals {
        // Compute encryption shared secret with ephemeral key
        let encryption_shared_secret = ECDH(
            alice_seckey,
            encrypted_proposal.ephemeral_pubkey
        );

        // Check tag first (fast rejection)
        let expected_tag = compute_proposal_tag(&encryption_shared_secret);
        if expected_tag != encrypted_proposal.tag {
            continue;  // Not for this UTXO
        }

        // Tag matches - try decryption
        match ChaCha20Poly1305::decrypt(
            encrypted_proposal.encrypted_data,
            encryption_shared_secret
        ) {
            Ok(proposal_bytes) => {
                let proposal = deserialize(proposal_bytes)?;
                // Found a proposal for this UTXO!
                matched_proposals.push(proposal);
            }
            Err(_) => continue,  // False positive tag match
        }
    }
}
```

### Phase 7: Proposal Validation (Receiver)

**Alice validates each matched proposal**:

```rust
let psbt = alice.receive(
    proposal,
    &alice_utxos,
    acceptable_delta_range,
    derive_privkey
)?;
```

**Validation checks**:

#### 7.1: Transaction Structure

```rust
// Must have exactly 2 inputs
assert_eq!(psbt.unsigned_tx.input.len(), 2);

// Must have exactly 3 outputs
assert_eq!(psbt.unsigned_tx.output.len(), 3);

// Find our input (should be index 0)
let our_input_idx = find_our_input(&psbt, our_utxos)?;
assert_eq!(our_input_idx, 0, "Our input must be first");

// Proposer's input should be at index 1
let proposer_input_idx = 1;
```

#### 7.2: SNICKER Tweak Verification

```rust
// Extract proposer's pubkey from TweakInfo
let proposer_pubkey = proposal.tweak_info.proposer_pubkey;

// Verify it matches the first non-ours input in PSBT
// (This checks proposer isn't lying about which key they used)
verify_proposer_pubkey_matches_psbt(&psbt, proposer_input_idx, proposer_pubkey)?;

// Calculate expected SNICKER shared secret
let our_seckey = derive_privkey(our_keychain, our_index)?;
let snicker_shared_secret = ECDH(our_seckey, proposer_pubkey);

// Apply tweak to our original output key
let original_output = &proposal.tweak_info.original_output;
let original_pubkey_xonly = extract_taproot_pubkey(original_output)?;
let expected_tweaked_pubkey = apply_taproot_tweak(
    original_pubkey_xonly,
    snicker_shared_secret
)?;

// Verify tweaked output matches expected
let tweaked_output = &proposal.tweak_info.tweaked_output;
let actual_tweaked_pubkey = extract_taproot_pubkey(tweaked_output)?;
assert_eq!(actual_tweaked_pubkey, expected_tweaked_pubkey);
```

#### 7.3: Equal Outputs Verification

```rust
// Outputs at index 0 and 1 should be equal value
let output0_value = psbt.unsigned_tx.output[0].value;
let output1_value = psbt.unsigned_tx.output[1].value;
assert_eq!(output0_value, output1_value, "Equal outputs required");

// Output 0 should use our tweaked key
assert_eq!(
    psbt.unsigned_tx.output[0].script_pubkey,
    tweaked_output.script_pubkey
);
```

#### 7.4: Delta Verification

```rust
// Calculate actual delta
let original_value = original_output.value.to_sat() as i64;
let equal_value = output0_value.to_sat() as i64;
let delta = original_value - equal_value;

// Verify delta is acceptable
let (min_delta, max_delta) = acceptable_delta_range;
assert!(delta >= min_delta && delta <= max_delta,
    "Delta {} outside acceptable range", delta);
```

#### 7.5: Proposer Signature Verification

```rust
// Verify proposer's input is actually signed
let proposer_input = &psbt.inputs[proposer_input_idx];
assert!(proposer_input.final_script_witness.is_some() ||
        proposer_input.partial_sigs.len() > 0,
    "Proposer must sign their input");
```

### Phase 8: Signing (Receiver)

**Alice signs the proposal** if validation passes:

```rust
let fully_signed_psbt = alice.accept_snicker_proposal(
    proposal,
    acceptable_delta_range
).await?;
```

**Process**:

```rust
// Derive our tweaked private key for signing
let our_original_seckey = wallet.derive_utxo_privkey(keychain, index)?;
let snicker_tweak_scalar = Scalar::from_bytes(snicker_shared_secret)?;
let our_tweaked_seckey = our_original_seckey.add_tweak(&snicker_tweak_scalar)?;

// Sign our input (index 0) with tweaked key
// Note: The wallet signing is actually more complex due to BIP86 taproot tweaking
wallet.sign(&mut psbt)?;

// PSBT now has:
// - Input 0 (Alice): signed ✓
// - Input 1 (Bob): signed ✓ (already had Bob's signature)
```

### Phase 9: Finalization and Broadcast (Receiver)

**Alice finalizes and broadcasts** the transaction:

```rust
// Finalize PSBT (convert signatures to final witness format)
let coinjoin_tx = alice.finalize_psbt(fully_signed_psbt).await?;

// Broadcast to Bitcoin network
let txid = alice.broadcast_transaction(coinjoin_tx).await?;
```

**Result**: A confirmed coinjoin transaction with:
- 2 inputs (Bob + Alice)
- 2 equal-sized outputs (privacy achieved!)
- 1 change output (Bob's)

### Phase 10: UTXO Tracking (Receiver)

**Alice tracks the SNICKER output** separately:

```rust
alice.store_accepted_snicker_utxo(
    &proposal,
    &coinjoin_tx,
    &our_utxos
).await?;
```

**Database storage** (`snicker_utxos` table):
```rust
struct SnickerUtxo {
    txid: Txid,
    vout: u32,
    amount: u64,
    script_pubkey: ScriptBuf,
    tweaked_privkey: SecretKey,        // For spending
    snicker_shared_secret: [u8; 32],   // For recovery verification
    block_height: Option<u32>,
}
```

**Why separate tracking?**
- BDK wallet doesn't recognize the tweaked output (different key derivation)
- Enables privileged status (prefer spending SNICKER UTXOs)
- Enables balance reporting: `wallet_balance + snicker_balance`
- Supports recovery scanning

---

## Transaction Structure

### Example Transaction

```
Inputs:
  [0] Alice's original UTXO (80k sats)
  [1] Bob's original UTXO (100k sats)

Outputs:
  [0] Alice's equal output (79k sats) - tweaked key
  [1] Bob's equal output (79k sats)
  [2] Bob's change output (21.6k sats - fees)

Fees: ~400 sats (2 P2TR inputs + 3 P2TR outputs ≈ 205 vbytes)
```

### Privacy Properties

**Indistinguishability**: The transaction looks like any 2-input, 3-output payment:
- Could be payment + change
- Could be payment + fee bump
- Could be coinjoin (but which inputs correspond to which outputs?)

**Output Unlinkability**: Observer cannot determine:
- Which input owns output[0]
- Which input owns output[1]
- Output[2] is identifiable as change (different amount)

**Best Case**: If both parties later spend their equal outputs in similar ways, the coinjoin provides long-term privacy.

---

## Recovery Mechanism

### The Recovery Problem

Traditional Bitcoin wallets recover from seed phrase by:
1. Deriving keys from seed using standard paths (BIP86)
2. Scanning blockchain for UTXOs controlled by those keys

**SNICKER challenge**: Tweaked outputs use non-standard keys:
- `tweaked_key = original_key + ECDH_shared_secret`
- If shared secret is random (ephemeral), it cannot be recomputed
- **Result**: SNICKER UTXOs would be permanently lost if database is lost

### The Solution: Deterministic Tweaks

**Key insight**: Use the **proposer's INPUT public key** (not ephemeral) for SNICKER tweak:

**Advantage**: Proposer's input key is:
- Visible on-chain (in transaction witness)
- Deterministic (can be extracted during recovery)
- Sufficient for ECDH (receiver knows their private key)

### Recovery Process

**Scenario**: Alice loses her database but has her seed phrase.

#### Step 1: Normal Wallet Recovery

```rust
// Scan blockchain for normal BIP86 UTXOs
for derivation_index in 0..gap_limit {
    let key = derive_key("m/86'/0'/0'/0/{derivation_index}");
    let address = bip86_address(key);

    // Find UTXOs controlled by this address
    let utxos = scan_blockchain(address);
    recovered_utxos.extend(utxos);
}
```

#### Step 2: SNICKER Output Recovery

For each recovered UTXO, check if it was spent:

```rust
for utxo in &recovered_utxos {
    // Check if this UTXO was spent
    let spending_tx = find_spending_transaction(utxo.outpoint)?;

    if let Some(tx) = spending_tx {
        // This UTXO was spent - check if it was in a SNICKER tx

        // Find which input spent our UTXO
        let our_input_idx = tx.input.iter()
            .position(|input| input.previous_output == utxo.outpoint)?;

        // Get the other input (proposer's input)
        let proposer_input_idx = if our_input_idx == 0 { 1 } else { 0 };
        let proposer_input = &tx.input[proposer_input_idx];

        // Extract proposer's public key from witness
        let proposer_pubkey = extract_pubkey_from_witness(
            &proposer_input.witness
        )?;

        // Derive our original private key
        let our_seckey = derive_key_for_utxo(utxo);

        // Calculate SNICKER shared secret
        let snicker_shared_secret = ECDH(our_seckey, proposer_pubkey);

        // Calculate expected tweaked output key
        let our_original_pubkey_xonly = extract_pubkey_from_utxo(utxo);
        let expected_tweaked_pubkey = apply_taproot_tweak(
            our_original_pubkey_xonly,
            snicker_shared_secret
        );

        // Check if any output matches our expected tweaked key
        for (vout, output) in tx.output.iter().enumerate() {
            let output_pubkey = extract_taproot_pubkey(output)?;

            if output_pubkey == expected_tweaked_pubkey {
                // Found our SNICKER output!
                let tweaked_privkey = derive_tweaked_seckey(
                    &our_seckey,
                    &snicker_shared_secret
                )?;

                recovered_snicker_utxos.push(SnickerUtxo {
                    outpoint: OutPoint { txid: tx.txid(), vout },
                    amount: output.value.to_sat(),
                    script_pubkey: output.script_pubkey.clone(),
                    tweaked_privkey,
                    snicker_shared_secret,
                    block_height: Some(tx.block_height),
                });
            }
        }
    }
}
```

#### Step 3: Full Recovery Achieved

```rust
let total_balance =
    recovered_utxos.sum() +
    recovered_snicker_utxos.sum();

println!("✅ Wallet fully recovered from seed!");
println!("   Normal UTXOs: {}", recovered_utxos.len());
println!("   SNICKER UTXOs: {}", recovered_snicker_utxos.len());
println!("   Total balance: {} sats", total_balance);
```

### Parity Handling

**Critical detail**: When tweaking keys, parity must be handled correctly:

```rust
fn apply_tweak_to_seckey_with_parity(
    seckey: &SecretKey,
    tweak: &Scalar,
) -> Result<SecretKey> {
    // Apply tweak
    let mut tweaked = seckey.add_tweak(tweak)?;

    // Check parity of resulting public key
    let pubkey = PublicKey::from_secret_key(&secp, &tweaked);
    let has_odd_y = pubkey.serialize()[0] == 0x03;

    // X-only keys (BIP340) always have even parity
    // If odd, negate the secret key
    if has_odd_y {
        tweaked = tweaked.negate();
    }

    Ok(tweaked)
}
```

**Why this matters**: X-only public keys in BIP340/Taproot always have even y-coordinate. When tweaking a secret key, the resulting public key might have odd y-coordinate. To match the x-only convention, we must negate the secret key.

---

## Security Properties

### Privacy

**Good**:
- Encrypted proposals hide receiver's identity
- Equal-sized outputs provide output unlinkability
- Non-interactive (no timing correlation)

**Limitations**:
- Change output reveals proposer's side
- Transaction graph analysis can still link addresses over time
- Best combined with other privacy techniques (Tor, address reuse avoidance)

### Robustness

**Proposer cannot cheat**:
- Receiver validates all amounts and tweaks
- Receiver never signs invalid transactions
- Proposer's signature is checked first

**Receiver cannot cheat**:
- Receiver can only ignore proposal (not modify it)
- Broadcasting reveals the coinjoin transaction
- Proposer gets the privacy benefit they expected

### Trust Model

**No trusted third party required**:
- No coordinator server
- No multisig setup
- Non-interactive proposal/acceptance

**Proposer trusts receiver to**:
- Not broadcast if proposal is inadequate
- Not broadcast before expected (timing)

**Receiver trusts proposer to**:
- Not be honeypot (deanonymization attack)
- Not be Sybil attacker (flooding proposals)

---

## Implementation Details

### Database Schema

**snicker_candidates**:
```sql
CREATE TABLE snicker_candidates (
    id INTEGER PRIMARY KEY,
    block_height INTEGER NOT NULL,
    txid TEXT NOT NULL,
    tx_hex TEXT NOT NULL,
    UNIQUE(txid)
);
```

**snicker_proposals**:
```sql
CREATE TABLE snicker_proposals (
    id INTEGER PRIMARY KEY,
    proposal_data BLOB NOT NULL
);
```

**snicker_utxos**:
```sql
CREATE TABLE snicker_utxos (
    txid TEXT NOT NULL,
    vout INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    script_pubkey BLOB NOT NULL,
    tweaked_privkey BLOB NOT NULL,
    snicker_shared_secret BLOB NOT NULL,
    block_height INTEGER,
    PRIMARY KEY (txid, vout)
);
```

### Key Functions

**Proposer side** (`manager.rs`):
- `scan_for_snicker_candidates()` - Find potential targets
- `find_snicker_opportunities()` - Match our UTXOs with candidates
- `create_snicker_proposal()` - Build, sign, encrypt proposal

**Receiver side** (`manager.rs`):
- `scan_for_our_proposals()` - Find and decrypt proposals for our UTXOs
- `accept_snicker_proposal()` - Validate and sign proposal
- `store_accepted_snicker_utxo()` - Track resulting UTXO

**Cryptographic operations** (`snicker/tweak.rs`):
- `calculate_dh_shared_secret()` - ECDH for two keys
- `apply_taproot_tweak()` - Add tweak to x-only pubkey
- `apply_tweak_to_seckey_with_parity()` - Add tweak to seckey with parity handling
- `derive_tweaked_seckey()` - Compute receiver's tweaked private key
- `encrypt_proposal()` / `decrypt_proposal()` - ChaCha20-Poly1305
- `compute_proposal_tag()` - Fast matching filter

### Integration with BDK

**Wallet operations** use [BDK (Bitcoin Dev Kit)](https://bitcoindevkit.org/):
- Key derivation (BIP86)
- PSBT creation and signing
- Transaction building
- UTXO management

**Blockchain sync** uses [Kyoto](https://github.com/rustaceanrob/kyoto):
- Compact block filters (BIP157)
- P2P network communication
- Block header validation
- Transaction scanning

---

## Conclusion

This implementation demonstrates a complete, production-ready SNICKER protocol with:
- ✅ Non-interactive coinjoin
- ✅ Encrypted proposals
- ✅ **Recoverable from seed phrase alone**
- ✅ Taproot (BIP86) integration
- ✅ Equal-output privacy structure
- ✅ Separate UTXO tracking

The key innovation is using the **proposer's input public key** for SNICKER tweaks, enabling wallet recovery while maintaining privacy properties.
