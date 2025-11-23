# Integration Tests

Automated integration tests using a shared regtest bitcoind instance and Kyoto light client sync.

## Prerequisites

**Bitcoin Core**: You need `bitcoind` and `bitcoin-cli` binaries available via:
- In your PATH, OR
- Set `BITCOIN_BIN_DIR` environment variable to the directory containing the binaries

Example:
```bash
export BITCOIN_BIN_DIR=/path/to/bitcoin-28.0/bin
```

## Quick Start

Run all tests:
```bash
cargo test -- --test-threads=1
```

Run a specific test:
```bash
cargo test test_wallet_creation -- --test-threads=1 --nocapture
```

**Important**: Always use `--test-threads=1` to run tests sequentially. Tests share a single bitcoind instance and cannot run in parallel.

## How It Works

### Automated Test Infrastructure

1. **Shared Bitcoind Instance**: All tests share a single regtest bitcoind that starts automatically on first test and persists across tests within the same test run.

2. **Automatic Cleanup**: Each new test run automatically detects and terminates any stale bitcoind processes from previous runs before starting fresh.

3. **Per-Test Wallets**: Each test creates its own isolated wallet with:
   - Unique BIP39 mnemonic
   - Fresh temporary database
   - Independent Kyoto light client sync

4. **Dynamic Heights**: Tests adapt to the current blockchain state rather than assuming fixed heights, allowing tests to run in any order.

### Test Components

**TestBitcoind** - Shared regtest bitcoind instance:
- Starts on first access (via `once_cell::Lazy`)
- Listens on fixed ports: RPC 18443, P2P 18444
- Creates temporary datadir in `/tmp`
- Generates 101 initial blocks for coinbase maturity
- Provides RPC methods: `rpc_call()`, `mine_blocks()`, `get_block_count()`

**TestWallet** - Per-test wallet with Kyoto sync:
- `new_regtest(test_name)`: Creates wallet and starts Kyoto sync
- `wait_for_sync(height)`: Waits for wallet to sync to specified height
- `get_next_address()`: Returns new receiving address
- `get_balance()`: Returns total wallet balance
- `get_height()`: Returns wallet's current chain tip height

## Available Tests

### test_wallet_creation
Verifies basic wallet creation and address generation:
- Creates new wallet with BIP39 mnemonic
- Generates taproot (bc1p...) addresses
- Confirms wallet structure is valid

### test_connect_to_regtest
Tests Kyoto light client sync:
- Connects to regtest bitcoind via P2P (port 18444)
- Syncs using compact block filters (BIP157/158)
- Verifies wallet reaches current blockchain height

### test_receive_funds
Tests receiving and detecting transactions:
- Creates wallet and gets receiving address
- Sends 1.0 BTC from bitcoind's wallet to test wallet
- Mines block to confirm transaction
- Verifies wallet detects transaction and updates balance

### test_mine_blocks
Tests block mining functionality:
- Mines 6 blocks via RPC
- Verifies blockchain height increases correctly

## Troubleshooting

### "Port 18443 still in use"
The test infrastructure automatically kills stale processes, but if you see this error:
```bash
# Manually kill any bitcoind on that port
lsof -ti :18443 | xargs kill -9

# Clean up temp directories
rm -rf /tmp/.tmp* /tmp/ambient_*
```

### Tests timing out
If `wait_for_sync()` times out:
- Check bitcoind is actually running: `lsof -i :18444`
- Verify compact block filters are enabled (should be automatic)
- Try running with `--nocapture` to see sync progress

### Wallet database errors
Each test creates a unique database file. If you see conflicts:
```bash
# Clean up old test databases
rm -rf /tmp/ambient_*
```

## Manual Testing with regtest.sh

For manual testing or debugging, you can use the `regtest.sh` script:

```bash
# Start bitcoind manually
./regtest.sh start [/path/to/bitcoin/bin]

# Get a new address
./regtest.sh addr

# Send funds to an address
./regtest.sh fund bcrt1q... 0.5

# Mine blocks
./regtest.sh mine 6

# Check blockchain info
./regtest.sh info

# Run custom bitcoin-cli commands
./regtest.sh cli getblockcount

# Stop and clean up
./regtest.sh stop
./regtest.sh clean
```

## Adding New Tests

Example test that receives and spends funds:

```rust
#[tokio::test]
async fn test_my_feature() -> Result<()> {
    println!("\n=== Test: My Feature ===");

    // Create wallet and sync to current height
    let wallet = TestWallet::new_regtest("my_feature").await?;
    let current_height = BITCOIND.get_block_count()? as u32;
    wallet.wait_for_sync(current_height).await?;

    // Get address and fund it
    let addr = wallet.get_next_address().await?;
    BITCOIND.rpc_call("sendtoaddress", &[
        serde_json::json!(addr.to_string()),
        serde_json::json!(0.5),
    ], Some("testwallet"))?;

    // Mine and sync
    BITCOIND.mine_blocks(1)?;
    wallet.wait_for_sync(current_height + 1).await?;

    // Your test logic here
    let balance = wallet.get_balance().await?;
    assert_eq!(balance.to_sat(), 50_000_000);

    println!("✅ Test passed");
    Ok(())
}
```

**Key points**:
- Always get current height dynamically with `BITCOIND.get_block_count()`
- Use unique test names for wallet isolation
- Wait for sync after mining blocks
- Tests run sequentially, so blockchain state accumulates
