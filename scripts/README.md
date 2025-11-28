# Regtest Development Scripts

Scripts for running Ambient wallet with a local Bitcoin regtest node.

---

## Quick Start

### 1. Start Bitcoind in Regtest Mode

```bash
./scripts/start_regtest.sh
```

This will:
- Start bitcoind in regtest mode
- Create a "miner" wallet
- Mine 101 blocks (to get past coinbase maturity)
- Show you the miner's balance (~50 BTC from mining rewards)

**Data directory:** `~/.bitcoin/regtest_ambient/data`

---

### 2. Start Ambient Wallet(s)

**Terminal 1 - Alice's wallet:**
```bash
cargo run -- --network regtest --recovery-height 0
```

Then in the wallet prompt:
```
wallet> generate alice
wallet> address
```

Copy the address shown (starts with `bcrt1...`)

**Terminal 2 - Bob's wallet (optional):**
```bash
cargo run -- --network regtest --recovery-height 0
```

Then:
```
wallet> generate bob
wallet> address
```

---

### 3. Send Coins from Bitcoind to Ambient Wallets

**Using bitcoin-cli directly:**

```bash
# Set up variables for convenience
DATADIR="$HOME/.bitcoin/regtest_ambient/data"

# Send 1 BTC to Alice
bitcoin-cli -regtest -datadir=$DATADIR -rpcwallet=miner \
    sendtoaddress bcrt1q...alice_address... 1.0

# Mine a block to confirm
bitcoin-cli -regtest -datadir=$DATADIR -rpcwallet=miner \
    generatetoaddress 1 $(bitcoin-cli -regtest -datadir=$DATADIR -rpcwallet=miner getnewaddress)
```

**Or use the helper script (easier):**

```bash
# Load helper functions
source scripts/regtest_helpers.sh

# Send 1 BTC to Alice (automatically mines 1 block to confirm)
send bcrt1q...alice_address... 1.0

# Send 0.5 BTC to Bob
send bcrt1q...bob_address... 0.5

# Mine more blocks
mine 6

# Check miner balance
balance
```

---

### 4. Sync Ambient Wallets

In each Ambient wallet terminal:

```
wallet> sync
wallet> balance
```

You should now see the coins you sent!

---

## Complete Workflow Example

### Setup

```bash
# Terminal 1: Start bitcoind
./scripts/start_regtest.sh

# Terminal 2: Start Alice's wallet
cargo run -- --network regtest --recovery-height 0
```

### In Alice's Wallet

```
wallet> generate alice
🔑 New mnemonic (store this safely!):
word1 word2 word3 ... word12

wallet> address
Next address: bcrt1qxyz...abc123
```

### Terminal 3: Send Coins

```bash
source scripts/regtest_helpers.sh
send bcrt1qxyz...abc123 2.5
```

Output:
```
💸 Sending 2.5 BTC to bcrt1qxyz...abc123
✅ Transaction sent: abc123def...
⏳ Mining 1 block to confirm...
⛏️  Mining 1 block(s)...
✅ Mined 1 block(s)
📊 Current height: 102
```

### Back in Alice's Wallet

```
wallet> sync
Syncing (recent blocks)...
Done.

wallet> balance
Balance: 2.5 BTC

wallet> listunspent
OutPoint: abc123def...:0
  value: 250000000
  script: 0 abc123def...
```

---

## Helper Script Reference

### Load Helpers

```bash
source scripts/regtest_helpers.sh
```

### Available Commands

| Command | Description | Example |
|---------|-------------|---------|
| `mine [N]` | Mine N blocks (default: 1) | `mine 6` |
| `send <addr> <btc>` | Send BTC and auto-confirm | `send bcrt1q... 0.5` |
| `balance` | Show miner balance | `balance` |
| `info` | Show blockchain info | `info` |
| `btc <args>` | Raw bitcoin-cli command | `btc getblockchaininfo` |
| `btc_miner <args>` | Raw bitcoin-cli for miner wallet | `btc_miner getbalance` |

---

## Testing SNICKER Workflow

### 1. Set Up Two Wallets with Funds

**Alice (Terminal 1):**
```
wallet> generate alice
wallet> address
# Get address: bcrt1q...alice...
```

**Bob (Terminal 2):**
```
wallet> generate bob
wallet> address
# Get address: bcrt1q...bob...
```

**Fund them (Terminal 3):**
```bash
source scripts/regtest_helpers.sh
send bcrt1q...alice... 1.0
send bcrt1q...bob... 1.0
mine 6  # Create some history
```

### 2. Create SNICKER Candidates

**In Alice's wallet:**
```
wallet> sync
wallet> balance
Balance: 1 BTC

# Scan for candidates (Bob's UTXO should be visible)
wallet> scan_candidates 10 50000 5000000
🔍 Scanning 10 blocks for SNICKER candidates (50000-5000000 sats)...
✅ Found and stored 1 candidates

wallet> list_candidates
Stored candidates (1):
  Block 103: <Bob's txid>
```

### 3. Find and Create Proposal

**Still in Alice's wallet:**
```
wallet> find_opportunities 50000
🔍 Finding SNICKER opportunities...
✅ Found 1 opportunities:
  [0] Our UTXO: <Alice's txid>:0 (100000000 sats) → Target: 100000000 sats
```

At this point, you would create a proposal (functionality to be implemented in CLI).

### 4. Mine More Blocks

```bash
# In helper terminal
mine 10
```

Wallets will see new blocks when they sync.

---

## Troubleshooting

### Bitcoind won't start

**Check if already running:**
```bash
pgrep -f "bitcoind.*regtest"
```

**Stop existing bitcoind:**
```bash
bitcoin-cli -regtest -datadir=$HOME/.bitcoin/regtest_ambient/data stop
```

**Check logs:**
```bash
tail -f ~/.bitcoin/regtest_ambient/data/regtest/debug.log
```

### Ambient wallet won't sync

**Check bitcoind is running:**
```bash
bitcoin-cli -regtest -datadir=$HOME/.bitcoin/regtest_ambient/data getblockchaininfo
```

**Make sure compact block filters are enabled:**
The start script enables them with `-blockfilterindex=1` and `-peerblockfilters=1`.

**Check Ambient is connecting:**
Look at Ambient's logs in `~/.local/share/ambient/regtest/logs/ambient.log`

### Coins not appearing after sync

**Check transaction was mined:**
```bash
bitcoin-cli -regtest -datadir=$HOME/.bitcoin/regtest_ambient/data \
    getrawtransaction <txid> 1
```

**Mine more blocks:**
```bash
source scripts/regtest_helpers.sh
mine 6
```

Then sync Ambient again.

---

## Cleanup

### Stop bitcoind
```bash
bitcoin-cli -regtest -datadir=$HOME/.bitcoin/regtest_ambient/data stop
```

### Reset regtest chain (start fresh)
```bash
rm -rf ~/.bitcoin/regtest_ambient/data
./scripts/start_regtest.sh
```

### Remove Ambient wallet data
```bash
rm -rf ~/.local/share/ambient/regtest
```

---

## Tips

1. **Always mine at least 1 block after sending** - Transactions need confirmation
2. **Use the helper script** - It's much easier than typing bitcoin-cli commands
3. **Keep terminals organized** - One for bitcoind helpers, one per Ambient wallet
4. **Mine blocks between tests** - Creates blockchain history for SNICKER to scan
5. **Check logs when stuck** - Both bitcoind and Ambient write useful debug info

---

## Example: Full Two-Wallet SNICKER Test

```bash
# Terminal 1: Setup
./scripts/start_regtest.sh
source scripts/regtest_helpers.sh

# Terminal 2: Alice
cargo run -- --network regtest --recovery-height 0
# wallet> generate alice
# wallet> address  # Copy address

# Terminal 3: Bob
cargo run -- --network regtest --recovery-height 0
# wallet> generate bob
# wallet> address  # Copy address

# Back to Terminal 1: Fund wallets
send <alice_address> 1.0
send <bob_address> 1.0
mine 6  # Create history

# Terminal 2 (Alice): Scan and propose
# wallet> sync
# wallet> scan_candidates 10 50000 5000000
# wallet> find_opportunities 50000
# wallet> (create proposal - command TBD)

# Terminal 3 (Bob): Receive and accept
# wallet> sync
# wallet> (scan for proposals - command TBD)
# wallet> (accept proposal - command TBD)

# Terminal 1: Mine to confirm coinjoin
mine 1

# Both wallets: Check results
# wallet> sync
# wallet> summary
```
