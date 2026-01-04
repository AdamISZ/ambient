# Ambient Wallet

[![Build](https://github.com/AdamISZ/ambient/actions/workflows/ci.yml/badge.svg)](https://github.com/AdamISZ/ambient/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/github/actions/workflow/status/AdamISZ/ambient/ci.yml?label=tests)](https://github.com/AdamISZ/ambient/actions/workflows/ci.yml)

A light-client Bitcoin wallet that automatically creates coinjoins in the background.

---

## Warning: Work in Progress

**This project is experimental and not ready for production use.**

Do not use with real funds. The protocol, implementation, and APIs are subject to change.

(Also note that the development process is making extensive use of LLM tech for rapid coding, which means it needs a lot more careful review; however a lot of testing infrastructure is being developed to avoid the potential for hallucinatory failure.)

---

## Quickstart

**Download and Run (Linux):**

Pre-built AppImage executables will be available from the [Releases](https://github.com/AdamISZ/ambient/releases) page. These are signed by the developer(s) - verify the signature before running.

```bash
# Download the AppImage (when available)
wget https://github.com/AdamISZ/ambient/releases/download/vX.X.X/Ambient-x86_64.AppImage

# Verify signature (recommended)
wget https://github.com/AdamISZ/ambient/releases/download/vX.X.X/Ambient-x86_64.AppImage.sig
gpg --verify Ambient-x86_64.AppImage.sig Ambient-x86_64.AppImage

# Make executable and run
chmod +x Ambient-x86_64.AppImage
./Ambient-x86_64.AppImage
```

**Build from Source:** See [docs/BUILDING.md](docs/BUILDING.md)

---

## What the user needs to know

**The core idea:** Your wallet passively proposes, and receives proposals, for 2-party coinjoins in the background while you use it normally. No manual coinjoin rounds, no coordination servers, no waiting - but also, no promises! (i.e. you don't know if a coinjoin will happen, or not).

**How a coinjoin happens (under the hood):**

```
    PROPOSER (Alice)                              RECEIVER (Bob)
    ================                              ==============

    1. Scans blockchain for
       potential partners
              │
              ▼
    2. Creates coinjoin tx
       (partially signed)
              │
              ▼
    3. Encrypts proposal to
       Bob's public key
              │
              ▼
    4. Publishes to Nostr ─────────┐
              │                    │
              ▼                    │
        ┌───────────┐              │
        │   DONE    │              │    ⏳ Minutes, hours, or days later...
        │ (offline) │              │
        └───────────┘              │
                                   │
                                   └─────▶ 5. Discovers proposal
                                               (tries to decrypt)
                                                      │
                                                      ▼
                                          6. Validates proposal:
                                             - UTXO exists?
                                             - Delta acceptable?
                                                      │
                                                      ▼
                                          7. Signs & broadcasts
                                             completed coinjoin tx
                                                      │
                                                      ▼
                                               Bitcoin Network
```

Your wallet randomly alternates between these roles, making transaction analysis harder.

This is a light client wallet, using compact filters, so you can start it immediately without a full node. But it doesn't have the same security properties, as a full node, either.

Pay attention to the main tradeoff you have to accept for being able to passively coinjoin without any effort or attention: **you must keep the wallet folder, not only the seedphrase**. If you lose the wallet folder (which contains an encrypted dataset), you *can* still recover your funds with just the seedphrase, but it will require using a full node and could be a slow process. So don't!

There are other small quirks: it's taproot only (which isn't a negative), but it's also the case that since your wallet is proposing coinjoins in the background occasionally, you might get a payment conflicted with a coinjoin that happens to occur at the same time; you'll never lose money this way, but a time sensitive payment could be delayed. This will be exceptionally rare and the interface warns you to use a higher fee if it's actually important, but, something to know.

Finally, there are fees to pay for the coinjoins, albeit small ones. Your wallet can both receive and pay for the coinjoin itself, but the net effect over time will be very slightly negative; check the Settings for the restriction on how many sats you're willing to lose per day, week and per individual transaction.

### So what do I get out of these coinjoins?

Not *that* much: any individual coinjoin does very little to make your coins' history more private. SNICKER coinjoins are *not* steganographic (i.e. it's obvious that they are coinjoins), but since they have equal-outputs, they unambiguously *do* increase your "anonymity set" (the crowd you're mixing with). This wallet always *both* proposes *and* receives, which helps a lot: no one can trace your coins through 10 such transactions *just* by assuming your behaviour follows one of those two patterns: your "role" is random. The intention is that **over a long time, with no actual effort from the user except having the wallet open some of the time, the privacy effect is quite significant**. That's about the best you can achieve here; it's not a tool to anonymize 10 BTC next week.

---

## More

[Technical details](docs/TECHNICAL_DETAILS.md) | [Architecture](docs/ARCHITECTURE.md) | [Building](docs/BUILDING.md)

---

## Uses

- [BDK (Bitcoin Dev Kit)](https://bitcoindevkit.org/)
- [Kyoto](https://github.com/rustaceanrob/kyoto) (BIP157/158 light client)
- [Iced](https://github.com/iced-rs/iced) (GUI framework)
- [Nostr](https://github.com/rust-nostr/nostr) (proposal broadcast)
- [Taproot (BIP341)](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)

---

## License

Licensed under either of:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

---

## Disclaimer

This software is provided "as is" without warranty of any kind. Use at your own risk. The authors are not responsible for any loss of funds.

---

## Contributing

Contributions, feedback, and testing are welcome! This project is in early development.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
