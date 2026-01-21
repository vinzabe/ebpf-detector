# Advanced Configuration

## Multi-Application Routing

Route multiple applications through the VPN:

```yaml
services:
  app1:
    network_mode: "service:vpn-router"
    # Your app config...
    
  app2:
    network_mode: "service:vpn-router"
    # Your app config...
```

## Database on Shared Network

Keep databases accessible without VPN overhead:

```yaml
services:
  postgres:
    networks:
      vpn-network:
        ipv4_address: 172.25.0.10
```

## Custom PQC Key Rotation

Configure key rotation interval:
```
PQC_KEY_ROTATION_HOURS=12
```

## High Availability

For HA deployments, use multiple VPN endpoints:

```yaml
services:
  vpn-router-primary:
    # Primary VPN config
    
  vpn-router-backup:
    # Backup VPN config
```

## Logging

### JSON Logging
```
LOG_FORMAT=json
```

### Log Rotation
```yaml
services:
  vpn-router:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

## Security Hardening

### Read-only filesystem
```yaml
services:
  vpn-router:
    read_only: true
    tmpfs:
      - /tmp
```

### Drop capabilities
```yaml
services:
  vpn-router:
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
```

## Contact

For enterprise architecture consulting: grant@abejar.net
