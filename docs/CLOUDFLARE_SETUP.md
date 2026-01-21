# Cloudflare Tunnel Setup

## Overview

Cloudflare Tunnel provides secure ingress to your applications without exposing ports to the internet. Combined with PQC, it provides quantum-resistant security.

## Prerequisites

- Cloudflare account (free tier works)
- Domain added to Cloudflare

## Setup Steps

### 1. Create Tunnel

```bash
# Install cloudflared locally (for setup only)
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared
chmod +x cloudflared

# Login to Cloudflare
./cloudflared tunnel login

# Create tunnel
./cloudflared tunnel create abejar-vpn
```

### 2. Get Tunnel Token

```bash
./cloudflared tunnel token abejar-vpn
```

Copy this token to your `.env` file:
```
CF_TUNNEL_TOKEN=<your-token>
```

### 3. Configure DNS

In Cloudflare dashboard:
1. Go to your domain's DNS settings
2. Add CNAME record pointing to `<tunnel-id>.cfargotunnel.com`

### 4. Configure Tunnel Routes

Edit `cloudflared/config.yml.example`:
```yaml
ingress:
  - hostname: app.yourdomain.com
    service: http://localhost:10091
  - hostname: api.yourdomain.com
    service: http://localhost:10092
  - service: http_status:404
```

### 5. Enable PQC

Set in your `.env`:
```
CF_TUNNEL_PQC=true
```

This enables post-quantum key agreement for the tunnel connection.

## Verification

```bash
# Check tunnel status
docker logs cloudflare-tunnel

# Verify PQC is enabled
docker exec cloudflare-tunnel printenv TUNNEL_POST_QUANTUM
```

## Contact

For enterprise support: grant@abejar.net
