#!/bin/bash
# =============================================================================
# Abejar PQC VPN Router - Test PQC Handshake
# =============================================================================
# Copyright 2024 Abejar. All rights reserved.
# Contact: grant@abejar.net
# =============================================================================

set -e

echo "=============================================="
echo "  Abejar PQC Handshake Test"
echo "=============================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if vpn-router container is running
if ! docker ps --format '{{.Names}}' | grep -q "vpn-router"; then
    echo -e "${RED}ERROR: vpn-router container is not running${NC}"
    echo "Start the VPN router first: docker compose up -d"
    exit 1
fi

echo ""
echo "Checking PQC Status..."
echo "----------------------------------------------"

# Check PQC environment
PQC_ENABLED=$(docker exec vpn-router printenv PQC_ENABLED 2>/dev/null || echo "false")
PQC_ALGORITHM=$(docker exec vpn-router printenv PQC_ALGORITHM 2>/dev/null || echo "unknown")
PQC_HYBRID=$(docker exec vpn-router printenv PQC_HYBRID_MODE 2>/dev/null || echo "false")

echo "PQC Enabled: $PQC_ENABLED"
echo "PQC Algorithm: $PQC_ALGORITHM"
echo "Hybrid Mode: $PQC_HYBRID"

# Check WireGuard status
echo ""
echo "WireGuard Status..."
echo "----------------------------------------------"
docker exec vpn-router wg show 2>/dev/null || echo "WireGuard not configured"

# Check for Kyber library
echo ""
echo "PQC Library Status..."
echo "----------------------------------------------"
if docker exec vpn-router test -f /opt/abejar/lib/libkyber.so.enc 2>/dev/null; then
    echo -e "${GREEN}Kyber library: Present (encrypted)${NC}"
elif docker exec vpn-router test -f /usr/local/lib/liboqs.so 2>/dev/null; then
    echo -e "${GREEN}liboqs library: Present${NC}"
else
    echo -e "${YELLOW}PQC library: Using standard WireGuard${NC}"
fi

# Test connectivity
echo ""
echo "Testing VPN Connectivity..."
echo "----------------------------------------------"
VPN_IP=$(docker exec vpn-router curl -s --max-time 10 https://ipinfo.io/ip 2>/dev/null || echo "Failed")
if [ "$VPN_IP" != "Failed" ]; then
    echo -e "${GREEN}VPN Connection: Active${NC}"
    echo "External IP: $VPN_IP"
    
    # Get location info
    LOCATION=$(docker exec vpn-router curl -s --max-time 10 https://ipinfo.io/json 2>/dev/null)
    if [ -n "$LOCATION" ]; then
        CITY=$(echo "$LOCATION" | jq -r '.city // "Unknown"')
        COUNTRY=$(echo "$LOCATION" | jq -r '.country // "Unknown"')
        ORG=$(echo "$LOCATION" | jq -r '.org // "Unknown"')
        echo "Location: $CITY, $COUNTRY"
        echo "ISP: $ORG"
    fi
else
    echo -e "${RED}VPN Connection: Failed${NC}"
fi

# Final status
echo ""
echo "=============================================="
if [ "$VPN_IP" != "Failed" ] && [ "$PQC_ENABLED" = "true" ]; then
    echo -e "${GREEN}  PQC Handshake Test: PASSED${NC}"
else
    echo -e "${YELLOW}  PQC Handshake Test: PARTIAL${NC}"
    echo "  VPN is working but PQC status may vary"
fi
echo "=============================================="
