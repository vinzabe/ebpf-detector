# =============================================================================
# Abejar Cloudflared with Post-Quantum TLS
# =============================================================================
# 
# Copyright 2024 Abejar. All rights reserved.
# Contact: grant@abejar.net for full source code access.
# =============================================================================

FROM cloudflare/cloudflared:latest

LABEL maintainer="Abejar <grant@abejar.net>"
LABEL description="Cloudflare Tunnel with Post-Quantum TLS Support"
LABEL version="1.0.0"
LABEL com.abejar.pqc="true"

# Cloudflared supports post-quantum key agreement natively
# This image ensures PQC is enabled and configured optimally

ENV TUNNEL_POST_QUANTUM=true
ENV TUNNEL_LOGLEVEL=info

# Copy PQC configuration helper
COPY pqc-tunnel.sh.enc /opt/abejar/
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tunnel", "run"]
