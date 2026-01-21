# Installation Guide

## Prerequisites

- Docker 24.0+
- Docker Compose 2.20+
- Linux host with kernel 5.6+ (for WireGuard)
- WireGuard VPN credentials

## Quick Installation

```bash
# Clone the repository
git clone https://github.com/vinzabe/abejar-pqc-vpn-kyber-native.git
cd abejar-pqc-vpn-kyber-native

# Run setup
./scripts/setup.sh

# Configure your VPN
nano vpn-router/config/wireguard/wg0.conf

# Start the stack
docker compose up -d
```

## Detailed Steps

### 1. System Requirements

Ensure your system has:
- Minimum 2GB RAM
- 10GB free disk space
- Internet connectivity

### 2. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

### 3. Configure Environment

Copy and edit the environment file:
```bash
cp .env.example .env
nano .env
```

Key settings:
- `CF_TUNNEL_TOKEN`: Your Cloudflare Tunnel token
- `PQC_ENABLED`: Enable post-quantum cryptography (default: true)
- `VPN_ROUTER_IP`: Static IP for VPN router container

### 4. Configure WireGuard

Copy and edit the WireGuard config:
```bash
cp vpn-router/config/wireguard/wg0.conf.example vpn-router/config/wireguard/wg0.conf
nano vpn-router/config/wireguard/wg0.conf
```

Add your VPN provider credentials:
- PrivateKey
- Address
- DNS
- Peer endpoint and public key

### 5. Start Services

```bash
docker compose up -d
```

### 6. Verify Installation

```bash
./scripts/vpn-status.sh
./scripts/test-pqc-handshake.sh
```

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues.

## Contact

For enterprise support: grant@abejar.net
