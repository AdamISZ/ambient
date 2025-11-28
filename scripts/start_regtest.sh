#!/bin/bash
# Start bitcoind in regtest mode and mine initial blocks

set -e

BITCOIN_DIR="$HOME/.bitcoin/regtest_ambient"
DATADIR="$BITCOIN_DIR/data"
RPC_PORT=18443
P2P_PORT=18444

echo "🚀 Starting Bitcoin Core in regtest mode..."

# Find bitcoind binary (same logic as integration tests)
if [ -n "$BITCOIND_PATH" ]; then
    BITCOIND="$BITCOIND_PATH"
elif [ -n "$BITCOIN_BIN_DIR" ]; then
    BITCOIND="$BITCOIN_BIN_DIR/bitcoind"
elif command -v bitcoind &> /dev/null; then
    BITCOIND=$(command -v bitcoind)
else
    echo "❌ Cannot find bitcoind binary"
    echo "   Set BITCOIND_PATH or BITCOIN_BIN_DIR environment variable,"
    echo "   or ensure bitcoind is in PATH"
    exit 1
fi

# Find bitcoin-cli binary
if [ -n "$BITCOIN_CLI_PATH" ]; then
    BITCOIN_CLI="$BITCOIN_CLI_PATH"
elif [ -n "$BITCOIN_BIN_DIR" ]; then
    BITCOIN_CLI="$BITCOIN_BIN_DIR/bitcoin-cli"
elif command -v bitcoin-cli &> /dev/null; then
    BITCOIN_CLI=$(command -v bitcoin-cli)
else
    echo "❌ Cannot find bitcoin-cli binary"
    echo "   Set BITCOIN_CLI_PATH or BITCOIN_BIN_DIR environment variable,"
    echo "   or ensure bitcoin-cli is in PATH"
    exit 1
fi

echo "📍 Using bitcoind: $BITCOIND"
echo "📍 Using bitcoin-cli: $BITCOIN_CLI"

# Create directory if it doesn't exist
mkdir -p "$DATADIR"

# Clean up any stale bitcoind processes using lsof (same logic as integration tests)
echo "🔍 Checking for stale bitcoind processes on port $RPC_PORT..."

LSOF_OUTPUT=$(lsof -t -i:$RPC_PORT 2>/dev/null || true)

if [ -n "$LSOF_OUTPUT" ]; then
    echo "$LSOF_OUTPUT" | while read -r pid; do
        if [ -n "$pid" ]; then
            echo "   ⚠️  Found stale bitcoind process (PID: $pid), terminating..."
            kill "$pid" 2>/dev/null || true
            sleep 0.5

            # Check if still running with kill -0
            if kill -0 "$pid" 2>/dev/null; then
                echo "   ⚠️  Process still running, sending SIGKILL..."
                kill -9 "$pid" 2>/dev/null || true
                sleep 0.5
            fi
            echo "   ✅ Process terminated"
        fi
    done
else
    echo "   ✅ No stale processes found"
fi

# Start bitcoind
"$BITCOIND" \
    -regtest \
    -datadir="$DATADIR" \
    -server=1 \
    -rpcport=$RPC_PORT \
    -port=$P2P_PORT \
    -fallbackfee=0.00001 \
    -daemon \
    -txindex=1 \
    -blockfilterindex=1 \
    -peerblockfilters=1

echo "⏳ Waiting for bitcoind to start..."
sleep 3

# Create a wallet if it doesn't exist
"$BITCOIN_CLI" -regtest -datadir="$DATADIR" createwallet "miner" 2>/dev/null || true

# Get an address
MINER_ADDR=$("$BITCOIN_CLI" -regtest -datadir="$DATADIR" -rpcwallet=miner getnewaddress)

echo "✅ bitcoind started successfully"
echo ""
echo "📍 Data directory: $DATADIR"
echo "💰 Miner wallet address: $MINER_ADDR"
echo ""

# Mine initial blocks to get past coinbase maturity (need 101 blocks)
echo "⛏️  Mining 101 blocks to miner address..."
"$BITCOIN_CLI" -regtest -datadir="$DATADIR" -rpcwallet=miner generatetoaddress 101 "$MINER_ADDR" > /dev/null

BALANCE=$("$BITCOIN_CLI" -regtest -datadir="$DATADIR" -rpcwallet=miner getbalance)
echo "✅ Mined 101 blocks"
echo "💎 Miner balance: $BALANCE BTC"
echo ""

echo "📋 Useful commands:"
echo ""
echo "  # Get blockchain info"
echo "  bitcoin-cli -regtest -datadir=$DATADIR getblockchaininfo"
echo ""
echo "  # Get miner balance"
echo "  bitcoin-cli -regtest -datadir=$DATADIR -rpcwallet=miner getbalance"
echo ""
echo "  # Mine more blocks"
echo "  bitcoin-cli -regtest -datadir=$DATADIR -rpcwallet=miner generatetoaddress 1 $MINER_ADDR"
echo ""
echo "  # Send coins to an address (replace ADDRESS and AMOUNT)"
echo "  bitcoin-cli -regtest -datadir=$DATADIR -rpcwallet=miner sendtoaddress ADDRESS AMOUNT"
echo ""
echo "  # Stop bitcoind"
echo "  bitcoin-cli -regtest -datadir=$DATADIR stop"
echo ""
echo "🎉 Ready to use! Start your Ambient wallet with:"
echo "   cargo run -- --network regtest --recovery-height 0"
