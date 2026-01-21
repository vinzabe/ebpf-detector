# Post-Quantum Cryptography Technical Details

## Kyber-1024 Algorithm

### Overview

Kyber is a key encapsulation mechanism (KEM) based on the Module Learning With Errors (MLWE) problem. It was selected by NIST as the standard for post-quantum key exchange.

### Key Exchange Flow

```mermaid
sequenceDiagram
    participant A as Alice (Client)
    participant B as Bob (Server)
    
    Note over A,B: Key Generation Phase
    B->>B: Generate keypair (pk, sk)
    B->>A: Send public key (pk)
    
    Note over A,B: Encapsulation Phase
    A->>A: Generate random seed
    A->>A: Encapsulate: (ct, K) = Encaps(pk)
    A->>B: Send ciphertext (ct)
    
    Note over A,B: Decapsulation Phase
    B->>B: Decapsulate: K = Decaps(sk, ct)
    
    Note over A,B: Shared Secret Established
    A->>A: Has shared secret K
    B->>B: Has shared secret K
```

### Hybrid Mode (X25519 + Kyber)

```mermaid
graph TB
    subgraph "Classical Component"
        X1[X25519 KeyGen]
        X2[X25519 Exchange]
        XS[X25519 Secret]
    end
    
    subgraph "Post-Quantum Component"
        K1[Kyber KeyGen]
        K2[Kyber Encaps/Decaps]
        KS[Kyber Secret]
    end
    
    subgraph "Key Derivation"
        HKDF[HKDF-SHA256]
        FS[Final Secret]
    end
    
    X1 --> X2
    X2 --> XS
    K1 --> K2
    K2 --> KS
    
    XS --> HKDF
    KS --> HKDF
    HKDF --> FS
    
    style K2 fill:#9b59b6,color:#fff
    style FS fill:#27ae60,color:#fff
```

### Security Parameters

| Parameter | Value | Security |
|-----------|-------|----------|
| n | 256 | Polynomial dimension |
| k | 4 | Module rank |
| q | 3329 | Modulus |
| eta1 | 2 | Noise parameter |
| eta2 | 2 | Noise parameter |
| du | 11 | Compression parameter |
| dv | 5 | Compression parameter |

### Performance Metrics

```mermaid
xychart-beta
    title "Kyber-1024 Performance (microseconds)"
    x-axis [KeyGen, Encaps, Decaps]
    y-axis "Time (μs)" 0 --> 100
    bar [45, 55, 50]
```

## Implementation Details

### Key Derivation Function

```
Final_Key = HKDF-SHA256(
    IKM = X25519_Secret || Kyber_Secret,
    Salt = Connection_ID || Timestamp,
    Info = "abejar-pqc-vpn-v1",
    Length = 32 bytes
)
```

### Cipher Suite

```
ABEJAR_PQC_KYBER1024_X25519_CHACHA20_POLY1305
```

Components:
- Key Exchange: Kyber-1024 + X25519 (hybrid)
- Symmetric Encryption: ChaCha20
- Authentication: Poly1305
- Hash: BLAKE2s (for WireGuard)

---

For full implementation details, contact: grant@abejar.net

Copyright 2024 Abejar. All rights reserved.
