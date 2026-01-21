# =============================================================================
# Abejar Cloudflared with Post-Quantum TLS
# =============================================================================
# Copyright 2024 Abejar. All rights reserved.
# Contact: grant@abejar.net for full source code access.
# =============================================================================

FROM cloudflare/cloudflared:latest

LABEL maintainer="Abejar <grant@abejar.net>"
LABEL description="Cloudflare Tunnel with Post-Quantum TLS Support"
LABEL version="1.0.0"
LABEL com.abejar.pqc="true"

# Cloudflared supports post-quantum key agreement natively
# Post-quantum is enabled via CLI flag

ENV TUNNEL_LOGLEVEL=info

ENTRYPOINT ["cloudflared", "--post-quantum"]
CMD ["tunnel", "run"]
