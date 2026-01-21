# System Architecture

## Overview

The Abejar PQC VPN Router implements a multi-layered security architecture that combines post-quantum cryptography with modern container orchestration.

## High-Level Architecture

```mermaid
graph TB
    subgraph "Internet"
        Users[Users/Clients]
        ExtAPI[External APIs]
        VPN_Server[VPN Provider]
    end
    
    subgraph "Cloudflare Edge"
        CF_CDN[Cloudflare CDN]
        CF_WAF[Web Application Firewall]
        CF_Tunnel_Edge[Tunnel Endpoint]
    end
    
    subgraph "Docker Host"
        subgraph "VPN Router Stack"
            VPN[VPN Router Container]
            CF_Local[Cloudflared Container]
        end
        
        subgraph "Application Stack"
            App[Application]
            DB[(Database)]
            Cache[(Cache)]
        end
    end
    
    Users --> CF_CDN
    CF_CDN --> CF_WAF
    CF_WAF --> CF_Tunnel_Edge
    CF_Tunnel_Edge -.->|Tunnel Protocol| CF_Local
    CF_Local -->|localhost| App
    
    App -->|network_mode| VPN
    VPN -->|Kyber-1024| VPN_Server
    VPN_Server --> ExtAPI
    
    App --> DB
    App --> Cache
    
    style VPN fill:#e74c3c,color:#fff
    style CF_Local fill:#3498db,color:#fff
```

## Network Architecture

```mermaid
graph LR
    subgraph "External Network"
        Internet[Internet]
    end
    
    subgraph "Docker Networks"
        subgraph "abejar_vpn_network (172.25.0.0/16)"
            VPN_Router[VPN Router<br/>172.25.0.2]
            DB[Database<br/>172.25.0.10]
            Redis[Redis<br/>172.25.0.11]
        end
        
        subgraph "Container Network (shared with VPN)"
            App[Application]
            Tunnel[Cloudflared]
        end
    end
    
    App -->|network_mode: container| VPN_Router
    Tunnel -->|network_mode: container| VPN_Router
    VPN_Router -->|WireGuard + PQC| Internet
    
    App -.->|Internal| DB
    App -.->|Internal| Redis
    
    style VPN_Router fill:#e74c3c,color:#fff
```

## Security Layers

```mermaid
graph TB
    subgraph "Layer 1: Edge Security"
        L1A[Cloudflare WAF]
        L1B[DDoS Protection]
        L1C[Bot Management]
    end
    
    subgraph "Layer 2: Transport Security"
        L2A[TLS 1.3]
        L2B[Post-Quantum TLS]
        L2C[Certificate Pinning]
    end
    
    subgraph "Layer 3: Tunnel Security"
        L3A[Cloudflare Tunnel]
        L3B[Encrypted Channel]
        L3C[Zero Trust Access]
    end
    
    subgraph "Layer 4: Container Security"
        L4A[Network Isolation]
        L4B[Localhost Binding]
        L4C[Minimal Privileges]
    end
    
    subgraph "Layer 5: VPN Security"
        L5A[WireGuard Protocol]
        L5B[Kyber-1024 PQC]
        L5C[Hybrid Mode]
    end
    
    subgraph "Layer 6: Application Security"
        L6A[Authentication]
        L6B[Authorization]
        L6C[Input Validation]
    end
    
    L1A --> L2A
    L1B --> L2B
    L1C --> L2C
    L2A --> L3A
    L2B --> L3B
    L2C --> L3C
    L3A --> L4A
    L3B --> L4B
    L3C --> L4C
    L4A --> L5A
    L4B --> L5B
    L4C --> L5C
    L5A --> L6A
    L5B --> L6B
    L5C --> L6C
    
    style L5B fill:#9b59b6,color:#fff
```

## Data Flow

```mermaid
sequenceDiagram
    participant U as User
    participant CF as Cloudflare
    participant T as Cloudflared
    participant A as Application
    participant V as VPN Router
    participant VP as VPN Provider
    participant E as External API

    rect rgb(100, 100, 200)
        Note over U,CF: Incoming Request Flow
        U->>CF: HTTPS Request
        CF->>CF: WAF/DDoS Check
        CF->>T: Tunnel Protocol
        T->>A: localhost:port
    end
    
    rect rgb(200, 100, 100)
        Note over A,E: Outgoing Request Flow
        A->>V: HTTP Request (via network_mode)
        V->>V: PQC Key Exchange (Kyber-1024)
        V->>VP: WireGuard Encrypted
        VP->>E: Request (VPN IP)
        E-->>VP: Response
        VP-->>V: WireGuard Encrypted
        V-->>A: Decrypted Response
    end
    
    rect rgb(100, 200, 100)
        Note over A,U: Response Flow
        A-->>T: Response
        T-->>CF: Tunnel Protocol
        CF-->>U: HTTPS Response
    end
```

## Component Diagram

```mermaid
graph TB
    subgraph "VPN Router Container"
        WG[WireGuard]
        PQC[Kyber-1024 Library]
        RT[Routing Engine]
        HC[Health Check]
        
        WG --> PQC
        WG --> RT
        RT --> HC
    end
    
    subgraph "Cloudflared Container"
        TUN[Tunnel Client]
        PQC_TLS[PQC TLS Handler]
        
        TUN --> PQC_TLS
    end
    
    subgraph "Application Container"
        APP[Application Code]
        API[REST API]
        
        APP --> API
    end
    
    subgraph "Database Container"
        PG[PostgreSQL]
    end
    
    subgraph "Cache Container"
        RD[Redis]
    end
    
    API -->|network_mode| RT
    TUN -->|network_mode| RT
    API -.->|Internal Network| PG
    API -.->|Internal Network| RD
    
    style PQC fill:#9b59b6,color:#fff
    style PQC_TLS fill:#9b59b6,color:#fff
```

---

For more details, contact: grant@abejar.net

Copyright 2024 Abejar. All rights reserved.
