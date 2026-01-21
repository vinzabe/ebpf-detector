#!/bin/bash
# =============================================================================
# Abejar PQC VPN Router - Health Check
# =============================================================================
# Copyright 2024 Abejar. All rights reserved.
# =============================================================================

set -e

# Check WireGuard interface
if ! ip link show wg0 &>/dev/null; then
    echo "ERROR: WireGuard interface not found"
    exit 1
fi

# Check WireGuard handshake (within last 3 minutes)
LAST_HANDSHAKE=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}')
if [ -n "$LAST_HANDSHAKE" ] && [ "$LAST_HANDSHAKE" != "0" ]; then
    CURRENT_TIME=$(date +%s)
    HANDSHAKE_AGE=$((CURRENT_TIME - LAST_HANDSHAKE))
    if [ "$HANDSHAKE_AGE" -gt 180 ]; then
        echo "WARNING: Last handshake was ${HANDSHAKE_AGE}s ago"
    fi
fi

# Check PQC status if enabled
if [ "${PQC_ENABLED:-true}" = "true" ]; then
    if [ -f /opt/abejar/lib/libkyber.so.enc ]; then
        echo "PQC: Kyber library present"
    else
        echo "WARNING: PQC library not found"
    fi
fi

# Check internet connectivity through VPN
if curl -s --max-time 5 https://cloudflare.com/cdn-cgi/trace &>/dev/null; then
    echo "VPN: Connected"
else
    echo "WARNING: Internet connectivity issue"
fi

echo "Health check passed"
exit 0
