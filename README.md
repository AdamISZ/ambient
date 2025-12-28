# Ambient Wallet

A Taproot-only Bitcoin wallet that automatically creates coinjoins in the background.

---

## ⚠️ Work in Progress

**This project is experimental and not ready for production use.**

Do not use with real funds. The protocol, implementation, and APIs are subject to change.

(Also note that the development proces is making extensive use of LLM tech for rapid coding, which means it needs a lot more careful review; however a lot of testing infrastructure is being developed to avoid the potential for hallucinatory failure.)

---

## Overview

Ambient is a Bitcoin wallet that implements [SNICKER](https://gist.github.com/AdamISZ/2c13fb5819bd469ca318156e2cf25d79) (Simple Non-Interactive Coinjoin with Keys for Encryption Reused) to provide privacy-enhancing coinjoins without user interaction.

**The core idea:** Your wallet passively proposes, and receives proposals, for 2-party coinjoins in the background while you use it normally. No manual coinjoin rounds, no coordination servers, no waiting.

### How It Works

1. **Proposer** scans the blockchain for potential coinjoin partners
2. Creates an encrypted proposal and broadcasts it via Nostr relays
3. **Receiver** discovers proposals meant for them (via Nostr subscription), validates, and signs if acceptable
4. Completed coinjoin transaction is broadcast to Bitcoin network

**Automation modes:**
- **Basic**: Automatically accept incoming proposals within delta range
- **Advanced**: Auto-accept + auto-create proposals (fully autonomous coinjoining)

### Trustless Validation

Ambient includes a **partial UTXO set** feature that enables trustless validation of incoming proposals:

- **Maintains a filtered UTXO set**: Tracks P2TR outputs ≥ 5000 sats from the last ~1000 blocks
- **Validates proposer UTXOs**: Verifies that proposer's inputs actually exist and are unspent
- **Prevents spam attacks**: Rejects proposals with fake or spent UTXOs without external API calls
- **Privacy-preserving**: Downloads all blocks (like a full node) but stores only filtered UTXOs (~60 MB)
- **Automatic maintenance**: Updates in real-time as new blocks arrive, self-prunes old data

This "lobotomized full node" approach provides the security of full validation with the lightweight storage of an SPV client.

See [`docs/AMBIENT_UTXO_MANAGEMENT.md`](docs/AMBIENT_UTXO_MANAGEMENT.md) for the complete design.

### Key Features

- **Non-interactive**: No back-and-forth communication between parties
- **Encrypted proposals**: Proposals are encrypted to the receiver's public key for privacy (+)
- **Trustless validation**: Maintains a partial UTXO set to validate proposer UTXOs without external services
- **Encrypted storage**: All wallet data encrypted at rest with ChaCha20-Poly1305 and Argon2id key derivation
- **In-memory security**: Databases decrypted only in RAM, never written to disk as plaintext
- **Recoverable from seed**: Uses deterministic tweaks (proposer's input key) enabling full wallet recovery from seed phrase alone
- **Taproot-only**: [BIP86](#bip86-key-derivation) keypath spending for efficiency and privacy (++)
- **Light client**: Uses compact block filters (BIP157) via Kyoto - no need to run a full node
- **GUI & CLI**: Desktop GUI (Linux) and command-line interface

(+) - The encryption is done with ChaCha20-Poly1305 stream ciphering, much better than the original CBC proposal in the [SNICKER](#snicker-bip-draft) gist.

(++) - The original description of [SNICKER](#snicker-bip-draft) addressed the limitations of needing to know the public key of the recipient in various ways, but by restricting ourselves to the taproot coin set we completely avoid this issue - the public keys are all known.

---

## Technologies

- **[Rust](https://www.rust-lang.org/)** - Systems programming language
- **[BDK (Bitcoin Dev Kit)](https://bitcoindevkit.org/)** - Bitcoin wallet library
- **[Kyoto](https://github.com/rustaceanrob/kyoto)** - Compact block filter light client (BIP157/158)
- **[Iced](https://github.com/iced-rs/iced)** - Cross-platform GUI framework
- **[Nostr](https://github.com/rust-nostr/nostr)** - Decentralized proposal broadcast/discovery network
- **Taproot ([BIP341](#bip341-taproot))** - Modern Bitcoin scripting with keypath spending
- **[BIP86](#bip86-key-derivation)** - Deterministic key derivation for Taproot
- **[SNICKER](#snicker-bip-draft)** - Non-interactive coinjoin protocol
- **ChaCha20-Poly1305** - Authenticated encryption (AEAD) for wallet files
- **Argon2id** - Memory-hard key derivation function

---

## Project Status

**Current state:**
- ✅ Basic Taproot wallet functionality (send, receive, balance)
- ✅ [SNICKER](#snicker-bip-draft) protocol implementation (propose, receive, validate)
- ✅ Encrypted proposal system
- ✅ Encrypted wallet storage (ChaCha20-Poly1305 + Argon2id)
- ✅ In-memory database security (no plaintext on disk)
- ✅ Recoverable tweaked outputs
- ✅ Light client sync via Kyoto (BIP157/158)
- ✅ Partial UTXO set for trustless proposer validation
- ✅ Nostr network integration (proposal broadcast/discovery)
- ✅ Automation modes (Basic: auto-accept, Advanced: auto-accept + auto-create)
- ✅ SNICKER UTXO tracking and management
- ✅ GUI interface (Iced framework)
- ✅ Real-time wallet status updates
- ✅ End-to-end integration tests

**In Progress / TODO:**
- [ ] "Send All" function for emptying wallet
- [ ] Improved UTXO selection (prefer single SNICKER UTXO, warn on multiple)
- [ ] Enhanced status bar (permanent, network status, INFO logs)
- [ ] Standard OS file picker integration
- [ ] Fallback validation mode for UTXOs outside scan window
- [ ] Fee estimation improvements
- [ ] Password change functionality
- [ ] Private key memory zeroization
- [ ] Comprehensive testing on signet/mainnet

---

## Building

### Prerequisites

- Rust 1.70+ ([install via rustup](https://rustup.rs/))
- For tests: Bitcoin Core with compact block filters enabled

### Build

**CLI only:**
```bash
cargo build --release --bin ambient-cli
```

**GUI (requires Linux desktop environment):**
```bash
cargo build --release --features gui --bin ambient-gui
```

**Both:**
```bash
cargo build --release
```

### Run Tests

```bash
# Unit tests
cargo test --lib

# Integration tests (requires bitcoind and ENV setting)
cargo test --test regtest_snicker
```

See [`tests/README.md`](tests/README.md) for detailed testing instructions.

---

## Architecture

```
ambient/
├── src/
│   ├── manager.rs            # High-level wallet + SNICKER coordination
│   ├── wallet_node.rs        # Bitcoin wallet (BDK + Kyoto)
│   ├── partial_utxo_set.rs   # Partial UTXO set for trustless validation
│   ├── encryption.rs         # Encrypted in-memory database management
│   ├── snicker/
│   │   ├── mod.rs            # SNICKER protocol logic
│   │   ├── tweak.rs          # Cryptographic primitives (ECDH, tweaking)
│   │   └── automation.rs     # Automation task and rate limiting
│   ├── network/              # Proposal broadcast/discovery
│   │   ├── mod.rs            # Network trait and abstraction
│   │   ├── nostr.rs          # Nostr network implementation
│   │   ├── file_based.rs     # File-based proposal sharing
│   │   └── serialization.rs  # Proposal serialization (JSON)
│   ├── gui/                  # GUI interface (Iced framework)
│   │   ├── app.rs            # Application state and message handling
│   │   ├── state.rs          # Application state management
│   │   ├── views/            # UI views (wallet, settings, modals)
│   │   └── widgets/          # Custom UI components
│   ├── cli/                  # CLI interface
│   │   └── repl.rs           # Interactive REPL commands
│   ├── main.rs               # CLI entry point
│   └── gui_main.rs           # GUI entry point
├── tests/                    # Integration tests
└── docs/
    ├── PROTOCOL.md                  # Complete protocol description
    ├── ENCRYPTED_STORAGE.md         # Encrypted storage architecture and schemas
    ├── SNICKER_RECOVERY.md          # Wallet recovery design
    └── AMBIENT_UTXO_MANAGEMENT.md   # Partial UTXO set design
```

### Data Flow

```
┌─────────────────────────────────────────────────────────┐
│ Encrypted Files (Disk Storage)                          │
│  ← wallet.sqlite.enc, snicker.sqlite.enc, mnemonic.enc  │
└─────────────────────┬───────────────────────────────────┘
                      │ Decrypt with password (Argon2id + ChaCha20-Poly1305)
                      ↓
┌─────────────────────────────────────────────────────────┐
│  In-Memory DBs (RAM only)                               │
│  ← SQLite :memory: connections                          │
└─────────────────────┬───────────────────────────────────┘
                      │
       ┌──────────────┼──────────────┬──────────────┬──────────┐
       ↓              ↓              ↓              ↓          ↓
   ┌─────┐      ┌────────┐     ┌────────┐   ┌─────────┐  ┌───────┐
   │ BDK │      │ Kyoto  │     │SNICKER │   │ Partial │  │ Nostr │
   │     │      │(BIP157)│     │        │   │UTXO Set │  │Network│
   └─────┘      └────────┘     └────────┘   └─────────┘  └───────┘
       │              │              │              │          │
       │              └──────┬───────┴──────────────┴──────────┘
       │                     ↓
       │              ┌──────────────┐
       └──────────────> Manager      │ ← Automation Task
                      └──────┬───────┘
                             │
                        ┌────┴─────┐
                        ↓          ↓
                    ┌──────┐  ┌──────┐
                    │ CLI  │  │ GUI  │  ← Real-time updates
                    └──────┘  └──────┘
```

See [`docs/ENCRYPTED_STORAGE.md`](docs/ENCRYPTED_STORAGE.md) for detailed encryption architecture and database schemas.

---

## References

- **SNICKER BIP Draft**: [AdamISZ's Gist](https://gist.github.com/AdamISZ/2c13fb5819bd469ca318156e2cf25d79)
- **BIP341 (Taproot)**: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
- **BIP86 (Key Derivation)**: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
- **BIP157 (Compact Block Filters)**: https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki

---

## Contributing

This project is in early development. Contributions, feedback, and testing are welcome!

Please note that this is experimental software dealing with Bitcoin private keys. Exercise appropriate caution.

---

## License

Licensed under either of:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

---

## Disclaimer

This software is provided "as is" without warranty of any kind. Use at your own risk. The authors are not responsible for any loss of funds.
