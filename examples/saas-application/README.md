# SaaS Application Example

Complete example demonstrating a full SaaS stack routed through the PQC VPN Router.

## Components

- **Frontend**: React application served via Nginx
- **Backend**: FastAPI with JWT authentication
- **Database**: PostgreSQL 16
- **Cache**: Redis 7

## Quick Start

```bash
# From the repository root, ensure VPN router is running
docker compose up -d

# Then start the SaaS example
cd examples/saas-application
cp .env.example .env
nano .env  # Configure your settings

docker compose up -d
```

## Endpoints

- Frontend: http://localhost:10091
- Backend API: http://localhost:10092
- API Docs: http://localhost:10092/api/docs

## Verify VPN Routing

```bash
# Check external IP (should show VPN IP)
curl http://localhost:10092/api/external-ip
```

## Architecture

All external traffic from the application goes through the VPN:

```
User -> Cloudflare -> Tunnel -> Frontend/Backend -> VPN Router -> Internet
                                    |
                           Database/Redis (internal network)
```

## Contact

For enterprise support: grant@abejar.net
