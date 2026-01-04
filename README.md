# Ambient Wallet

[![Build](https://github.com/AdamISZ/ambient/actions/workflows/ci.yml/badge.svg)](https://github.com/AdamISZ/ambient/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/github/actions/workflow/status/AdamISZ/ambient/ci.yml?label=tests)](https://github.com/AdamISZ/ambient/actions/workflows/ci.yml)

A light-client Bitcoin wallet that automatically creates coinjoins in the background.

---

## ⚠️ Work in Progress

**This project is experimental and not ready for production use.**

Do not use with real funds. The protocol, implementation, and APIs are subject to change.

(Also note that the development proces is making extensive use of LLM tech for rapid coding, which means it needs a lot more careful review; however a lot of testing infrastructure is being developed to avoid the potential for hallucinatory failure.)

---

## What the user needs to know

**The core idea:** Your wallet passively proposes, and receives proposals, for 2-party coinjoins in the background while you use it normally. No manual coinjoin rounds, no coordination servers, no waiting - but also, no promises! (i.e. you don't know if a coinjoin will happen, or not).

This is a light client wallet, using compact filters, so you can start it immediately without a full node. But it doesn't have the same security properties, as a full node, either.

Pay attention to the main tradeoff you have to accept for being able to passively coinjoin without any effort or attention: **you must keep the wallet folder, not only the seedphrase**. If you lose the wallet folder (which contains an encrypted dataset), you *can* still recover your funds with just the seedphrase, but it will require using a full node and could be a slow process. So don't!

There are other small quirks: it's taproot only (which isn't a negative), but it's also the case that since your wallet is proposing coinjoins in the background occasionally, you might get a payment conflicted with a coinjoin that happens to occur at the same time; you'll never lose money this way, but a time sensitive payment could be delayed. This will be exceptionally rare and the interface warns you to use a higher fee if it's actually important, but, something to know.

Finally, there are fees to pay for the coinjoins, albeit small ones. Your wallet can both receive and pay for the coinjoin itself, but the net effect over time will be very slightly negative; check the Settings for the restriction on how many sats you're willing to lose per day, week and per individual transaction.

### So what do I get out of these coinjoins?

Not *that* much: any individual coinjoin does very little to make your coins' history more private. SNICKER coinjoins are *not* steganographic (i.e. it's obvious that they are coinjoins), but since they have equal-outputs, they unambiguously *do* increase your "anonymity set" (the crowd you're mixing with). This wallet always *both* proposes *and* receives, which helps a lot: no one can trace your coins through 10 such transactions *just* by assuming your behaviour follows one of those two patterns: your "role" is random. The intention is that **over a long time, with no actual effort from the user except leaving the wallet online, the privacy effect is quite significant**. That's about the best you can achieve here; it's not a tool to anonymize 10 BTC next week.


## In more detail

From here, we'll start to discuss more technicalities. Ambient is a Bitcoin wallet that implements [SNICKER](https://gist.github.com/AdamISZ/2c13fb5819bd469ca318156e2cf25d79) (Simple Non-Interactive Coinjoin with Keys for Encryption Reused) to provide privacy-enhancing coinjoins without user interaction.


### How It Works

1. **Proposer** scans the blockchain for potential coinjoin partners
2. Creates an encrypted proposal and broadcasts it via Nostr relays (currently planned default, though other networks should be hot-swappable pretty easily)
3. **Receiver** discovers proposals meant for them (attempt-to-decrypt using a tag is very fast), validates, and signs if acceptable
4. Completed coinjoin transaction is broadcast by the receiver to Bitcoin network

### Trustless Validation

Under the hood, Ambient includes a **partial UTXO set** feature that enables trustless validation of incoming proposals:

- **Maintains a filtered UTXO set**: Tracks P2TR outputs ≥ 3000 sats from the wallet's creation block onwards
- **Validates proposer UTXOs**: Verifies that proposer's inputs actually exist and are unspent (so they can't be more than ~1000 blocks older than the receiver wallet's birthday)
- **Prevents spam attacks**: Rejects proposals with fake or spent UTXOs without external API calls
- **Privacy-preserving**: Downloads all blocks *from its creation* (not from genesis) but stores only filtered UTXOs (tens of MB)
- **Automatic maintenance**: Updates in real-time as new blocks arrive, self-prunes old data

This "lobotomized full node" approach provides a lot of the security of full validation with the lightweight storage of an SPV client. "A lot" : of course, this is more an SPV model of security inasmuch as you cannot validate locally using only a "slice" of the full utxo set.

You're forgiven for being a bit confused by this model. Are we doing BIP157 compact block filters or not? The answer is Ambient is a dual wallet: for the non-SNICKER utxos we just use a very vanilla BDK wallet that happens to be taproot, hooked up to the blockchain using the light client model of Kyoto. But that doesn't work for the customized SNICKER outputs from the coinjoins; for that we need our own infrastructure for tracking, and the partial UTXO set described above, serves that role.

See [`docs/AMBIENT_UTXO_MANAGEMENT.md`](docs/AMBIENT_UTXO_MANAGEMENT.md) for the complete design.

### Key Features

- **Non-interactive**: No back-and-forth communication between parties
- **Encrypted proposals**: Proposals are encrypted to the receiver's public key for privacy (+)
- **Trustless validation**: Maintains a partial UTXO set to validate proposer UTXOs without external services
- **Encrypted storage**: All wallet data encrypted at rest with ChaCha20-Poly1305 and Argon2id key derivation
- **In-memory security**: Databases decrypted only in RAM, never written to disk as plaintext (++)
- **Recoverable from seed**: Uses deterministic tweaks (proposer's input key) enabling full wallet recovery from seed phrase alone
- **Taproot-only**: [BIP86](#bip86-key-derivation) keypath spending for efficiency and privacy (+++)
- **Light client**: Uses compact block filters (BIP157) via Kyoto - no need to run a full node
- **GUI & CLI**: Desktop GUI (Linux) and command-line interface

(+) - The encryption is done with ChaCha20-Poly1305 stream ciphering, much better than the original CBC proposal in the [SNICKER](#snicker-bip-draft) gist.

(++) - In-RAM security is a work in progress: much harder than for a normal wallet, because there is hot-signing involved in making and accepting proposals for coinjoins passively without user interaction. This is a similar challenge to that of Lightning; in itself it fundamentally means that secret material must be sitting in memory. However, we can change this model via the Signer trait, to allow e.g. a policy-based hardware wallet signing process, in a future update.

(++) - The original description of [SNICKER](#snicker-bip-draft) addressed the limitations of needing to know the public key of the recipient in various ways, but by restricting ourselves to the taproot coin set we completely avoid this issue - the public keys are all known.

---

## Supporting technologies

- Rust
- **[BDK (Bitcoin Dev Kit)](https://bitcoindevkit.org/)** - Bitcoin wallet library
- **[Kyoto](https://github.com/rustaceanrob/kyoto)** - Compact block filter light client (BIP157/158)
- **[Iced](https://github.com/iced-rs/iced)** - Cross-platform GUI framework
- **[Nostr](https://github.com/rust-nostr/nostr)**
- **Taproot ([BIP341](#bip341-taproot))** - needed for non-interactive proposal against keys onchain
- **[BIP86](#bip86-key-derivation)** - Deterministic key derivation for Taproot
- **ChaCha20-Poly1305** - Authenticated encryption (AEAD) for wallet files
- **Argon2id** - Memory-hard key derivation function

---

## Project Status

**Current state:**
- ✅ Basic Taproot wallet functionality (send, send all, receive, balance)
- ✅ [SNICKER](#snicker-bip-draft) protocol implementation (propose, receive, validate)
- ✅ Encrypted proposal system
- ✅ Encrypted wallet storage (ChaCha20-Poly1305 + Argon2id)
- ✅ In-memory database security (no plaintext on disk)
- ✅ Recoverable tweaked outputs - (but recover method is *not* yet done!)
- ✅ Light client sync via Kyoto (BIP157/158)
- ✅ Partial UTXO set for trustless proposer validation
- ✅ Nostr network integration (proposal broadcast/discovery)
- ✅ SNICKER UTXO tracking and management
- ✅ GUI interface (Iced framework)
- ✅ Real-time wallet status updates
- ✅ End-to-end integration tests
- ✅ "Send All" function for emptying wallet
- ✅ Customized UTXO selection (prefer single SNICKER UTXO, warn on multiple)

**In Progress / TODO:**

- [ ] Password change functionality
- [ ] Recovery method including Snicker discovery, using a Core instance
- [ ] a ton of other stuff, will update this list later

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
│   ├── automation.rs         # Automation task and rate limiting
│   ├── snicker/
│   │   ├── mod.rs            # SNICKER protocol logic
│   │   └── tweak.rs          # Cryptographic primitives (ECDH, tweaking)
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
