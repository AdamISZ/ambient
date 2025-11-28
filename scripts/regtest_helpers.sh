#!/bin/bash
# Helper functions for regtest operations

DATADIR="$HOME/.bitcoin/regtest_ambient/data"

# Find bitcoin-cli binary (same logic as start script)
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
    return 1
fi

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function btc() {
    "$BITCOIN_CLI" -regtest -datadir="$DATADIR" "$@"
}

function btc_miner() {
    "$BITCOIN_CLI" -regtest -datadir="$DATADIR" -rpcwallet=miner "$@"
}

# Mine blocks
function mine() {
    local blocks=${1:-1}
    local addr=$(btc_miner getnewaddress)
    echo -e "${BLUE}⛏️  Mining $blocks block(s)...${NC}"
    btc_miner generatetoaddress "$blocks" "$addr" > /dev/null
    echo -e "${GREEN}✅ Mined $blocks block(s)${NC}"
    local height=$(btc getblockchaininfo | jq -r '.blocks')
    echo -e "${BLUE}📊 Current height: $height${NC}"
}

# Send coins to address
function send() {
    local address=$1
    local amount=$2

    if [ -z "$address" ] || [ -z "$amount" ]; then
        echo "Usage: send <address> <amount_in_btc>"
        echo "Example: send bcrt1q... 1.5"
        return 1
    fi

    echo -e "${BLUE}💸 Sending $amount BTC to $address${NC}"
    local txid=$(btc_miner sendtoaddress "$address" "$amount")
    echo -e "${GREEN}✅ Transaction sent: $txid${NC}"
    echo -e "${YELLOW}⏳ Mining 1 block to confirm...${NC}"
    mine 1
}

# Get balance
function balance() {
    local bal=$(btc_miner getbalance)
    echo -e "${GREEN}💰 Miner balance: $bal BTC${NC}"
}

# Get blockchain info
function info() {
    btc getblockchaininfo | jq '{blocks, headers, chain, difficulty}'
}

# List commands
function help_regtest() {
    echo -e "${GREEN}Regtest Helper Commands:${NC}"
    echo ""
    echo "  mine [N]              - Mine N blocks (default: 1)"
    echo "  send <addr> <amount>  - Send BTC to address and mine 1 block"
    echo "  balance               - Show miner wallet balance"
    echo "  info                  - Show blockchain info"
    echo "  btc <args>            - Run bitcoin-cli with regtest args"
    echo "  btc_miner <args>      - Run bitcoin-cli for miner wallet"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo "  mine 6                                    # Mine 6 blocks"
    echo "  send bcrt1q...xyz 0.5                     # Send 0.5 BTC"
    echo "  btc getblockchaininfo                     # Get chain info"
    echo ""
}

# If sourced, show help
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    echo "This script should be sourced, not executed directly."
    echo "Run: source scripts/regtest_helpers.sh"
    exit 1
else
    echo -e "${GREEN}✅ Regtest helpers loaded${NC}"
    echo "Type 'help_regtest' for available commands"
fi
