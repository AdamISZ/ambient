#!/usr/bin/env bash
# Regtest bitcoind management script for rustsnicker testing

set -e

DATADIR="/tmp/rustsnicker-regtest"

# Check if second argument is a directory path (bitcoin bin directory)
if [ -n "$2" ] && [ -d "$2" ]; then
    BIN_DIR="$2"
    BITCOIN_CLI="$BIN_DIR/bitcoin-cli -regtest -datadir=$DATADIR"
    BITCOIND="$BIN_DIR/bitcoind -regtest -datadir=$DATADIR"
    # Shift to remove the bin directory from arguments for commands that use $2, $3
    COMMAND="$1"
    shift 2
    set -- "$COMMAND" "$@"
elif [ -n "$2" ] && [ ! -d "$2" ]; then
    echo "Error: '$2' is not a valid directory"
    exit 1
else
    # Use binaries from PATH
    BITCOIN_CLI="bitcoin-cli -regtest -datadir=$DATADIR"
    BITCOIND="bitcoind -regtest -datadir=$DATADIR"
fi

case "$1" in
    start)
        echo "Starting regtest bitcoind..."
        mkdir -p "$DATADIR"

        # Start bitcoind in background
        $BITCOIND -daemon \
            -fallbackfee=0.00001 \
            -server=1 \
            -txindex=1 \
            -rest=1 \
            -rpcuser=test \
            -rpcpassword=test \
            -rpcport=18443 \
            -port=18444

        # Wait for bitcoind to be ready
        echo "Waiting for bitcoind to start..."
        for i in {1..30}; do
            if $BITCOIN_CLI getblockchaininfo &>/dev/null; then
                echo "✅ bitcoind is ready"
                break
            fi
            sleep 1
        done

        # Create wallet if it doesn't exist
        if ! $BITCOIN_CLI listwallets | grep -q "testwallet"; then
            echo "Creating wallet..."
            $BITCOIN_CLI createwallet "testwallet" false false "" false false true
        fi

        # Generate initial blocks (need 101 for coinbase maturity)
        BLOCKCOUNT=$($BITCOIN_CLI getblockcount)
        if [ "$BLOCKCOUNT" -lt 101 ]; then
            echo "Generating 101 blocks..."
            ADDR=$($BITCOIN_CLI getnewaddress)
            $BITCOIN_CLI generatetoaddress 101 "$ADDR" > /dev/null
            echo "✅ Generated 101 blocks"
        fi

        echo ""
        echo "Regtest bitcoind running!"
        echo "  RPC: localhost:18443 (user: test, pass: test)"
        echo "  P2P: localhost:18444"
        echo "  Datadir: $DATADIR"
        echo ""
        echo "Commands:"
        echo "  ./regtest.sh stop     - Stop bitcoind"
        echo "  ./regtest.sh mine N   - Mine N blocks"
        echo "  ./regtest.sh info     - Show chain info"
        echo "  ./regtest.sh addr     - Get new address"
        echo "  ./regtest.sh fund ADDR AMOUNT - Send funds to address"
        ;;

    stop)
        echo "Stopping regtest bitcoind..."
        $BITCOIN_CLI stop || true
        sleep 2
        echo "✅ Stopped"
        ;;

    clean)
        echo "Cleaning regtest data..."
        $BITCOIN_CLI stop &>/dev/null || true
        sleep 2
        rm -rf "$DATADIR"
        echo "✅ Cleaned $DATADIR"
        ;;

    mine)
        BLOCKS=${2:-1}
        echo "Mining $BLOCKS blocks..."
        ADDR=$($BITCOIN_CLI getnewaddress)
        $BITCOIN_CLI generatetoaddress "$BLOCKS" "$ADDR" > /dev/null
        HEIGHT=$($BITCOIN_CLI getblockcount)
        echo "✅ Mined $BLOCKS blocks, height now: $HEIGHT"
        ;;

    info)
        echo "=== Blockchain Info ==="
        $BITCOIN_CLI getblockchaininfo | jq '{chain, blocks, headers, difficulty}'
        echo ""
        echo "=== Network Info ==="
        $BITCOIN_CLI getnetworkinfo | jq '{version, subversion, connections}'
        echo ""
        echo "=== Wallet Balance ==="
        $BITCOIN_CLI getbalance
        ;;

    addr)
        ADDR=$($BITCOIN_CLI getnewaddress)
        echo "New address: $ADDR"
        ;;

    fund)
        if [ -z "$2" ]; then
            echo "Usage: $0 fund <address> <amount_btc>"
            exit 1
        fi
        ADDR=$2
        AMOUNT=${3:-0.1}
        echo "Sending $AMOUNT BTC to $ADDR..."
        TXID=$($BITCOIN_CLI sendtoaddress "$ADDR" "$AMOUNT")
        echo "Transaction: $TXID"

        # Mine a block to confirm
        echo "Mining 1 block to confirm..."
        if [ -n "$BIN_DIR" ]; then
            "$0" mine "$BIN_DIR" 1
        else
            "$0" mine 1
        fi
        ;;

    cli)
        # Pass through to bitcoin-cli
        shift
        $BITCOIN_CLI "$@"
        ;;

    *)
        echo "Rustsnicker Regtest Manager"
        echo ""
        echo "Usage: $0 <command> [bin_dir] [args]"
        echo ""
        echo "Arguments:"
        echo "  bin_dir         Optional path to directory containing bitcoind and bitcoin-cli"
        echo "                  If not provided, binaries are assumed to be in PATH"
        echo ""
        echo "Commands:"
        echo "  start           Start regtest bitcoind and generate initial blocks"
        echo "  stop            Stop regtest bitcoind"
        echo "  clean           Stop and delete all regtest data"
        echo "  mine [N]        Mine N blocks (default: 1)"
        echo "  info            Show blockchain and network info"
        echo "  addr            Generate a new address"
        echo "  fund ADDR [AMT] Send funds to address (default: 0.1 BTC)"
        echo "  cli <args>      Run bitcoin-cli with custom arguments"
        echo ""
        echo "Example workflow (with bin_dir):"
        echo "  ./regtest.sh start /path/to/bitcoin/bin"
        echo "  ./regtest.sh fund /path/to/bitcoin/bin bcrt1q... 0.5"
        echo "  ./regtest.sh mine /path/to/bitcoin/bin 6"
        echo "  ./regtest.sh stop /path/to/bitcoin/bin"
        echo ""
        echo "Example workflow (binaries in PATH):"
        echo "  ./regtest.sh start"
        echo "  ./regtest.sh fund bcrt1q... 0.5"
        echo "  ./regtest.sh mine 6"
        echo "  ./regtest.sh stop"
        ;;
esac
