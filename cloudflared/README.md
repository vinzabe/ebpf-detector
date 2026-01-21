# Cloudflare Tunnel with Post-Quantum TLS

This directory contains the Cloudflare Tunnel configuration with post-quantum
cryptography enabled.

## Setup

1. Create a Cloudflare Tunnel in the Zero Trust dashboard
2. Copy your tunnel token
3. Set `CF_TUNNEL_TOKEN` in your `.env` file

## Post-Quantum Security

Cloudflared supports post-quantum key agreement using Kyber. This is enabled
by default in the Abejar configuration.

### Verify PQC is Active

```bash
docker logs cloudflare-tunnel 2>&1 | grep -i "post-quantum"
```

## Configuration

See `config.yml.example` for ingress configuration options.

## Encrypted Components

The `pqc-tunnel.sh.enc` script contains proprietary PQC initialization logic.
Contact grant@abejar.net for full source access.

---

Copyright 2024 Abejar. All rights reserved.
