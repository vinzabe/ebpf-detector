#!/bin/bash
# =============================================================================
# Abejar PQC VPN Router - Setup Script
# =============================================================================
# Copyright 2024 Abejar. All rights reserved.
# Contact: grant@abejar.net
# =============================================================================

set -e

echo "=============================================="
echo "  Abejar PQC VPN Router Setup"
echo "=============================================="

# Check prerequisites
check_prerequisites() {
    echo "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        echo "ERROR: Docker is not installed"
        exit 1
    fi
    
    if ! command -v docker compose &> /dev/null; then
        echo "ERROR: Docker Compose is not installed"
        exit 1
    fi
    
    echo "Prerequisites OK"
}

# Create configuration files
setup_config() {
    echo "Setting up configuration..."
    
    if [ ! -f ".env" ]; then
        cp .env.example .env
        echo "Created .env from template"
    fi
    
    if [ ! -f "vpn-router/config/wireguard/wg0.conf" ]; then
        cp vpn-router/config/wireguard/wg0.conf.example vpn-router/config/wireguard/wg0.conf
        echo "Created WireGuard config from template"
        echo "IMPORTANT: Edit vpn-router/config/wireguard/wg0.conf with your VPN credentials"
    fi
}

# Create Docker network
setup_network() {
    echo "Setting up Docker network..."
    
    if ! docker network inspect abejar_vpn_network &> /dev/null; then
        docker network create \
            --driver bridge \
            --subnet=172.25.0.0/16 \
            --gateway=172.25.0.1 \
            abejar_vpn_network
        echo "Created Docker network: abejar_vpn_network"
    else
        echo "Docker network already exists"
    fi
}

# Pull images
pull_images() {
    echo "Pulling Docker images..."
    docker compose pull
}

# Main
main() {
    check_prerequisites
    setup_config
    setup_network
    pull_images
    
    echo ""
    echo "=============================================="
    echo "  Setup Complete!"
    echo "=============================================="
    echo ""
    echo "Next steps:"
    echo "1. Edit .env with your settings"
    echo "2. Edit vpn-router/config/wireguard/wg0.conf with your VPN credentials"
    echo "3. (Optional) Configure Cloudflare Tunnel token"
    echo "4. Run: docker compose up -d"
    echo "5. Check status: ./scripts/vpn-status.sh"
    echo ""
}

main "$@"
