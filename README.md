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
2. Creates an encrypted proposal and broadcasts it (via Nostr, bulletin boards, DHT, or any other mechanism - the broadcast is not yet implemented! - so proposals can only be shared manually for now)
3. **Receiver** discovers proposals meant for them, validates, and signs if acceptable
4. Completed coinjoin transaction is broadcast to Bitcoin network

### Key Features

- **Non-interactive**: No back-and-forth communication between parties
- **Encrypted proposals**: Proposals are encrypted to the receiver's public key for privacy (+)
- **Recoverable from seed**: Uses deterministic tweaks (proposer's input key) enabling full wallet recovery from seed phrase alone
- **Taproot-only**: [BIP86](#bip86-key-derivation) keypath spending for efficiency and privacy (++)
- **Light client**: Uses compact block filters (BIP157) via Kyoto - no need to run a full node

(+) - The encryption is done with ChaCha20-Poly1305 stream ciphering, much better than the original CBC proposal in the [SNICKER](#snicker-bip-draft) gist.

(++) - The original description of [SNICKER](#snicker-bip-draft) addressed the limitations of needing to know the public key of the recipient in various ways, but by restricting ourselves to the taproot coin set we completely avoid this issue - the public keys are all known.

---

## Technologies

- **[Rust](https://www.rust-lang.org/)** - Systems programming language
- **[BDK (Bitcoin Dev Kit)](https://bitcoindevkit.org/)** - Bitcoin wallet library
- **[Kyoto](https://github.com/rustaceanrob/kyoto)** - Compact block filter light client (BIP157/158)
- **Taproot ([BIP341](#bip341-taproot))** - Modern Bitcoin scripting with keypath spending
- **[BIP86](#bip86-key-derivation)** - Deterministic key derivation for Taproot
- **[SNICKER](#snicker-bip-draft)** - Non-interactive coinjoin protocol

---

## Project Status

**Current state:**
- ✅ Basic Taproot wallet functionality (send, receive, balance)
- ✅ [SNICKER](#snicker-bip-draft) protocol implementation (propose, receive, validate)
- ✅ Encrypted proposal system
- ✅ Recoverable tweaked outputs
- ✅ Light client sync via Kyoto
- ✅ End-to-end integration tests

**TODO:**
- [ ] Proposal broadcast/discovery mechanism (Nostr, DHT, etc.)
- [ ] Background automation (passive scanning and accepting)
- [ ] UTXO selection strategies
- [ ] Fee estimation improvements
- [ ] GUI interface - planned for Linux desktop binary distribution, only
- [ ] Comprehensive testing on signet/mainnet

---

## Building

### Prerequisites

- Rust 1.70+ ([install via rustup](https://rustup.rs/))
- For tests: Bitcoin Core with compact block filters enabled

### Build

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
│   ├── manager.rs        # High-level wallet + SNICKER coordination
│   ├── wallet_node.rs    # Bitcoin wallet (BDK + Kyoto)
│   ├── snicker/
│   │   ├── mod.rs        # SNICKER protocol logic
│   │   └── tweak.rs      # Cryptographic primitives (ECDH, tweaking)
│   └── main.rs           # CLI interface
├── tests/                # Integration tests
└── docs/
    ├── PROTOCOL.md       # Complete protocol description
    └── SNICKER_RECOVERY.md  # Wallet recovery design
```

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
