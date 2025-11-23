# SNICKER Wallet Recovery

## The Recovery Problem

Traditional Bitcoin wallets have a crucial property: **recoverability from seed phrase alone**.

### Traditional Wallet Recovery
1. User has BIP39 seed phrase (12/24 words)
2. Derive keys using standard paths (e.g., BIP86: `m/86'/0'/0'/0/*`)
3. Scan blockchain for UTXOs controlled by derived keys
4. Full wallet recovery - no database needed

### SNICKER Wallet Challenge

With naive SNICKER implementation using ephemeral keys for tweaks:

**What happens:**
- Alice receives SNICKER output with tweaked key: `alice_key + tweak`
- Tweak derived from ECDH with Bob's random ephemeral key
- Alice's database stores the tweaked private key

**If Alice loses database but has seed:**
1. ✓ Can recover normal BIP86 UTXOs by scanning
2. ✓ Can see transactions that spent her UTXOs
3. ✗ Cannot recover SNICKER outputs because:
   - Bob's ephemeral key was random (not on-chain)
   - Cannot recompute shared secret
   - Cannot derive tweaked private key
   - **SNICKER coins are permanently lost**

## The Solution: Deterministic Tweak Recovery

### Key Insight

Separate the two uses of keys in SNICKER:

1. **Encryption Key** (for proposal privacy)
   - Used to encrypt the proposal PSBT data
   - Ephemeral key is fine (only needed during proposal phase)
   - Receiver decrypts once, then discards

2. **SNICKER Tweak** (for output creation)
   - Used to create the tweaked output key
   - Must be recoverable from blockchain data alone
   - **Solution: Use proposer's INPUT public key**

### Implementation Strategy

**Current (non-recoverable):**
```
Bob generates random ephemeral keypair
shared_secret = ECDH(bob_ephemeral_seckey, alice_output_pubkey)
tweak = shared_secret
alice_tweaked_output = alice_output_key + tweak
```

**Proposed (recoverable):**
```
Encryption:
  ephemeral_key = random()  // for encrypting proposal
  encrypted_proposal = encrypt(proposal, ECDH(ephemeral, alice_key))

SNICKER Tweak:
  bob_input_pubkey = extract_from_bob_input_witness(tx)
  shared_secret = ECDH(bob_input_seckey, alice_output_pubkey)
  tweak = shared_secret
  alice_tweaked_output = alice_output_key + tweak
```

### Recovery Process

When Alice recovers wallet from seed:

1. **Scan for normal UTXOs** (standard BIP86 derivation)
   - Derive keys: `m/86'/0'/0'/0/0`, `m/86'/0'/0'/0/1`, ...
   - Find UTXOs controlled by these keys

2. **Scan for SNICKER outputs**
   - Find all transactions that spent Alice's UTXOs
   - For each such transaction:
     ```
     a. Extract proposer's input public key from witness
     b. Compute: shared_secret = ECDH(alice_seckey, proposer_pubkey)
     c. Compute: expected_tweaked_key = alice_output_key + shared_secret
     d. Check if any output uses expected_tweaked_key
     e. If match: derive tweaked_privkey to spend this output
     ```

3. **Full Recovery Achieved**
   - All normal BIP86 UTXOs recovered
   - All SNICKER-tweaked outputs recovered
   - No database required - only seed phrase + blockchain scan

## Benefits

1. **Maintains Bitcoin's core property**: Wallet recoverable from seed alone
2. **No special backup needed**: SNICKER outputs auto-recoverable
3. **Database is optimization**: Stores tweaked keys for performance, not necessity
4. **Standard recovery tools**: Can be implemented in any wallet that can scan blockchain

## Implementation Considerations

### Proposer Side
- When creating SNICKER transaction, use input key for tweak (not ephemeral)
- Still use ephemeral key for encrypting the proposal
- Must ensure input public key is extractable from witness

### Receiver Side
- Store tweaked keys in database for performance
- Implement recovery scanner that checks spent UTXOs
- Derive tweaked keys from proposer input keys during recovery

### Privacy Implications
- Using input key doesn't reduce privacy (it's already on-chain)
- The coinjoin still provides output unlinkability
- Ephemeral key for encryption maintains proposal privacy

## Future Work

- Implement recovery scanner in wallet
- Add tests for recovery scenarios
- Document recovery process for users
- Consider UI for "scan for SNICKER outputs"
