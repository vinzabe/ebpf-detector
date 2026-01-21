#!/bin/bash
# =============================================================================
# Abejar PQC VPN Router - Connection Test
# =============================================================================

echo "=============================================="
echo "  Abejar PQC VPN Router Connection Test"
echo "=============================================="

TESTS_PASSED=0
TESTS_FAILED=0

test_result() {
    if [ $1 -eq 0 ]; then
        echo "  PASS: $2"
        ((TESTS_PASSED++))
    else
        echo "  FAIL: $2"
        ((TESTS_FAILED++))
    fi
}

# Test 1: Container running
echo ""
echo "Test 1: VPN Container Status"
docker ps | grep -q vpn-router
test_result $? "Container is running"

# Test 2: WireGuard interface
echo ""
echo "Test 2: WireGuard Interface"
docker exec vpn-router ip link show wg0 &>/dev/null
test_result $? "WireGuard interface exists"

# Test 3: Internet connectivity
echo ""
echo "Test 3: Internet Connectivity"
docker exec vpn-router curl -s --max-time 10 https://cloudflare.com/cdn-cgi/trace &>/dev/null
test_result $? "Internet accessible through VPN"

# Test 4: External IP check
echo ""
echo "Test 4: External IP"
VPN_IP=$(docker exec vpn-router curl -s https://ipinfo.io/ip 2>/dev/null)
if [ -n "$VPN_IP" ]; then
    echo "  External IP: $VPN_IP"
    test_result 0 "External IP retrieved"
else
    test_result 1 "Could not retrieve external IP"
fi

# Test 5: DNS resolution
echo ""
echo "Test 5: DNS Resolution"
docker exec vpn-router nslookup google.com &>/dev/null
test_result $? "DNS resolution working"

# Test 6: Localhost ports
echo ""
echo "Test 6: Localhost Port Binding"
if netstat -tlnp 2>/dev/null | grep -q "127.0.0.1:10091" || ss -tlnp 2>/dev/null | grep -q "127.0.0.1:10091"; then
    test_result 0 "Localhost ports bound correctly"
else
    test_result 1 "Localhost ports not bound"
fi

# Summary
echo ""
echo "=============================================="
echo "  Test Results: $TESTS_PASSED passed, $TESTS_FAILED failed"
echo "=============================================="

exit $TESTS_FAILED
