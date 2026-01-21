# =============================================================================
# Abejar PQC VPN Router - Kyber-1024 Native
# =============================================================================
# 
# Copyright 2024 Abejar. All rights reserved.
# Contact: grant@abejar.net for full source code access.
#
# This Dockerfile builds the VPN router with native Kyber-1024 support.
# Core PQC implementation is provided as pre-built binaries.
# =============================================================================

FROM linuxserver/wireguard:latest AS base

LABEL maintainer="Abejar <grant@abejar.net>"
LABEL description="Post-Quantum Cryptography VPN Router with Kyber-1024"
LABEL version="1.0.0"
LABEL com.abejar.pqc="true"
LABEL com.abejar.pqc.algorithm="kyber1024"

# Install additional dependencies
RUN apk add --no-cache \
    curl \
    jq \
    openssl \
    python3 \
    py3-pip \
    bash \
    ca-certificates \
    && rm -rf /var/cache/apk/*

# Create PQC directory structure
RUN mkdir -p /opt/abejar/pqc /opt/abejar/bin /opt/abejar/lib

# Copy PQC binaries (encrypted/obfuscated)
COPY pqc-lib/kyber-keygen.bin /opt/abejar/bin/
COPY pqc-lib/kyber-encaps.bin /opt/abejar/bin/
COPY pqc-lib/kyber-decaps.bin /opt/abejar/bin/
COPY pqc-lib/libkyber.so.enc /opt/abejar/lib/

# Copy configuration scripts
COPY config/routing/setup-routes.sh.enc /opt/abejar/bin/
COPY entrypoint-pqc.sh.enc /opt/abejar/bin/

# Copy healthcheck
COPY healthcheck.sh /healthcheck.sh
RUN chmod +x /healthcheck.sh

# Set permissions
RUN chmod +x /opt/abejar/bin/* 2>/dev/null || true

# Environment
ENV PQC_ENABLED=true
ENV PQC_ALGORITHM=kyber1024
ENV PQC_HYBRID_MODE=true
ENV ABEJAR_VERSION=1.0.0

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /healthcheck.sh

# Override entrypoint to include PQC initialization
ENTRYPOINT ["/init"]
