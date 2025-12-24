#!/bin/bash
# Start a local Nostr relay for testing SNICKER proposals
#
# Usage:
#   ./scripts/start-test-relay.sh [port]
#
# Default port: 7777

set -e

PORT="${1:-7777}"
RELAY_DIR="${HOME}/.nostr-relay"
CONFIG_FILE="${RELAY_DIR}/config.toml"

echo "🚀 Starting local Nostr relay for SNICKER testing"
echo "   Port: ${PORT}"
echo "   Data directory: ${RELAY_DIR}"
echo ""

# Create relay directory
mkdir -p "${RELAY_DIR}"

# Create config file if it doesn't exist
if [ ! -f "${CONFIG_FILE}" ]; then
    echo "📝 Creating relay config at ${CONFIG_FILE}"
    cat > "${CONFIG_FILE}" << 'EOF'
[info]
relay_url = "ws://localhost:7777"
name = "SNICKER Test Relay"
description = "Local relay for SNICKER proposal testing"

[database]
# Use SQLite for persistence
data_directory = "."

[limits]
# Increase limits for testing
max_event_bytes = 102400  # 100KB
max_subscriptions = 20
max_filters = 10

[authorization]
# No authorization for local testing
pubkey_whitelist = []

[verified_users]
# No verification required
mode = "disabled"

[retention]
# Keep events for 7 days
max_seconds = 604800

[grpc]
# Disable gRPC for simplicity
enabled = false
EOF
fi

# Check if nostr-rs-relay is installed
if ! command -v nostr-rs-relay &> /dev/null; then
    echo "❌ nostr-rs-relay not found"
    echo ""
    echo "Install with:"
    echo "   cargo install nostr-rs-relay"
    echo ""
    echo "Or use Docker:"
    echo "   docker run -d -p ${PORT}:8080 -v ${RELAY_DIR}:/usr/src/app/db scsibug/nostr-rs-relay"
    exit 1
fi

echo "✅ Starting relay..."
echo "   Press Ctrl+C to stop"
echo "   Relay URL: ws://localhost:${PORT}"
echo ""

# Start relay
cd "${RELAY_DIR}"
nostr-rs-relay --port "${PORT}" --db .
