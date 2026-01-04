# Building Ambient Wallet

## Prerequisites

- Rust 1.70+ ([install via rustup](https://rustup.rs/))
- For tests: Bitcoin Core with compact block filters enabled

## Build

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

## Run Tests

```bash
# Unit tests
cargo test --lib

# Integration tests (requires bitcoind and ENV setting)
cargo test --test regtest_snicker
```

See [`tests/README.md`](../tests/README.md) for detailed testing instructions.
