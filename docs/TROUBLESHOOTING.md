# Troubleshooting Guide

## Common Issues

### VPN Not Connecting

```mermaid
graph TD
    A[VPN Not Connecting] --> B{Container Running?}
    B -->|No| C[docker compose up -d]
    B -->|Yes| D{WireGuard Interface?}
    D -->|No| E[Check wg0.conf]
    D -->|Yes| F{Handshake Recent?}
    F -->|No| G[Check VPN Credentials]
    F -->|Yes| H[Connection OK]
    
    E --> I[Verify Private Key]
    E --> J[Verify Endpoint]
    E --> K[Verify AllowedIPs]
    
    G --> L[Regenerate Keys]
    G --> M[Check Provider Status]
```

### Application Can't Reach Database

```mermaid
graph TD
    A[DB Connection Failed] --> B{network_mode set?}
    B -->|No| C[Add network_mode: container:vpn-router]
    B -->|Yes| D{DB on vpn-network?}
    D -->|No| E[Add DB to abejar_vpn_network]
    D -->|Yes| F{Using Static IP?}
    F -->|No| G[Set ipv4_address in compose]
    F -->|Yes| H[Check IP matches DB_HOST]
```

## Diagnostic Commands

```bash
# Check VPN status
./scripts/vpn-status.sh

# Test connection
./scripts/test-connection.sh

# View logs
docker logs vpn-router --tail 100
docker logs cloudflare-tunnel --tail 100

# Check WireGuard
docker exec vpn-router wg show

# Check external IP
docker exec vpn-router curl https://ipinfo.io/ip

# Check network
docker network inspect abejar_vpn_network
```

---

For support, contact: grant@abejar.net

Copyright 2024 Abejar. All rights reserved.
