# Performance Guide

## Kyber-1024 Performance

Kyber-1024 is highly optimized and adds minimal overhead:

| Operation | Time | Notes |
|-----------|------|-------|
| Key Generation | ~0.1ms | One-time per session |
| Encapsulation | ~0.15ms | Client-side |
| Decapsulation | ~0.15ms | Server-side |

## Benchmarks

### Throughput (Gigabit connection)

| Configuration | Download | Upload |
|--------------|----------|--------|
| WireGuard only | 940 Mbps | 920 Mbps |
| WireGuard + PQC | 935 Mbps | 915 Mbps |
| With CF Tunnel | 800 Mbps | 750 Mbps |

### Latency

| Configuration | Latency Increase |
|--------------|------------------|
| PQC Handshake | +0.5ms |
| Per-packet | +0.01ms |

## Optimization Tips

### 1. Container Resources

```yaml
services:
  vpn-router:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 512M
```

### 2. Network Tuning

```bash
# Increase buffer sizes
sysctl -w net.core.rmem_max=26214400
sysctl -w net.core.wmem_max=26214400
```

### 3. WireGuard MTU

Optimize MTU for your network:
```
MTU = 1500 - 60 (IPv4) - 8 (UDP) - 32 (WireGuard) = 1400
```

## Monitoring

Use the built-in metrics endpoint:
```bash
curl http://localhost:10091/metrics
```

## Contact

For enterprise optimization consulting: grant@abejar.net
