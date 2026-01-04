# Ambient Wallet Architecture

## Directory Structure

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

## Data Flow

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

See [`ENCRYPTED_STORAGE.md`](ENCRYPTED_STORAGE.md) for detailed encryption architecture and database schemas.
