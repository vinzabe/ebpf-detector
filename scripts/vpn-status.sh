#!/bin/bash
# =============================================================================
# Abejar PQC VPN Router - Status Check
# =============================================================================

echo "=============================================="
echo "  Abejar PQC VPN Router Status"
echo "=============================================="

# Check container status
echo ""
echo "Container Status:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(vpn-router|cloudflare)" || echo "No VPN containers running"

# Check VPN connection
echo ""
echo "VPN Connection:"
if docker exec vpn-router wg show wg0 2>/dev/null; then
    echo ""
    echo "External IP:"
    docker exec vpn-router curl -s https://ipinfo.io/json | jq -r '"  IP: \(.ip)\n  Location: \(.city), \(.country)\n  ISP: \(.org)"' 2>/dev/null || echo "  Could not fetch IP info"
else
    echo "  VPN not connected or container not running"
fi

# Check PQC status
echo ""
echo "PQC Status:"
if docker exec vpn-router test -f /opt/abejar/lib/libkyber.so.enc 2>/dev/null; then
    echo "  Kyber library: Present"
    echo "  Algorithm: Kyber-1024"
    echo "  Hybrid mode: X25519 + Kyber"
else
    echo "  Kyber library: Not found"
fi

echo ""
echo "=============================================="
