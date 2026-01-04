# Technical Details

Ambient is a Bitcoin wallet that implements [SNICKER](https://gist.github.com/AdamISZ/2c13fb5819bd469ca318156e2cf25d79) (Simple Non-Interactive Coinjoin with Keys for Encryption Reused) to provide privacy-enhancing coinjoins without user interaction.

## Trustless Validation

Under the hood, Ambient includes a **partial UTXO set** feature that enables trustless validation of incoming proposals:

- **Maintains a filtered UTXO set**: Tracks P2TR outputs ≥ 3000 sats from the wallet's creation block onwards
- **Validates proposer UTXOs**: Verifies that proposer's inputs actually exist and are unspent
- **Prevents spam attacks**: Rejects proposals with fake or spent UTXOs without external API calls
- **Privacy-preserving**: Downloads all blocks *from its creation* (not from genesis) but stores only filtered UTXOs
- **Automatic maintenance**: Updates in real-time as new blocks arrive, self-prunes old data

See [`AMBIENT_UTXO_MANAGEMENT.md`](AMBIENT_UTXO_MANAGEMENT.md) for the complete design.

## Key Features

- **Non-interactive**: No back-and-forth communication between parties
- **Encrypted proposals**: Proposals are encrypted to the receiver's public key
- **Trustless validation**: Maintains a partial UTXO set to validate proposer UTXOs without external services
- **Encrypted storage**: All wallet data encrypted at rest with [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) and [Argon2id](https://en.wikipedia.org/wiki/Argon2) key derivation
- **In-memory security**: Databases decrypted only in RAM, never written to disk as plaintext
- **Recoverable from seed**: Uses deterministic tweaks enabling full wallet recovery from seed phrase alone
- **Taproot-only**: [BIP86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki) keypath spending for efficiency and privacy
- **Light client**: Uses compact block filters ([BIP157](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki)) - no need to run a full node
- **GUI & CLI**: Desktop GUI (Linux) and command-line interface
