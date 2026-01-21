#!/bin/sh
# =============================================================================
# Abejar Cloudflared Entrypoint
# =============================================================================
# Copyright 2024 Abejar. All rights reserved.
# =============================================================================

set -e

echo "=============================================="
echo "  Abejar Cloudflare Tunnel with PQC"
echo "=============================================="
echo "  Post-Quantum: ${TUNNEL_POST_QUANTUM:-true}"
echo "  Log Level: ${TUNNEL_LOGLEVEL:-info}"
echo "=============================================="

# Enable post-quantum key agreement if requested
if [ "${TUNNEL_POST_QUANTUM}" = "true" ]; then
    export TUNNEL_POST_QUANTUM_KEY_AGREEMENT=true
    echo "PQC: Post-quantum key agreement ENABLED"
else
    echo "PQC: Post-quantum key agreement DISABLED"
fi

# Wait for VPN connection if running in VPN network mode
if [ -n "${WAIT_FOR_VPN}" ]; then
    echo "Waiting for VPN connection..."
    sleep "${WAIT_FOR_VPN}"
fi

# Start cloudflared
exec cloudflared "$@"
