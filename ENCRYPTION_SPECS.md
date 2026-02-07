# 암호화 명세서 (v4 - ECDH + Client Auth)

## 프로토콜 개요
**ECDH (P-256)** 키 교환에 **HMAC-SHA256 서명**을 추가하여 클라이언트 인증을 수행합니다.

### 1. 키 교환 핸드셰이크 (Key Exchange Handshake)
1.  **Client (클라이언트)**:
    *   ECDH 키 쌍 생성 (`Client Public Key`).
    *   현재 시간 `timestamp` (Unix Epoch Milliseconds) 생성.
    *   **서명 생성**: `Signature` = HMAC-SHA256(`Client Public Key` + `timestamp`, `CLIENT_SECRET`).
    *   전송: `{ publicKey, timestamp, signature }`

2.  **Server (서버)**:
    *   **타임스탬프 검증**: `Current Time` - `timestamp` < 5분 (Replay Attack 방지).
    *   **서명 검증**: 서버가 가진 `CLIENT_SECRET`으로 동일하게 HMAC을 계산하여 `signature`와 비교.
    *   검증 성공 시 ECDH 수행 (v3와 동일).
    *   응답: `{ publicKey, content }`

### 흐름도 (Sequence Diagram)
```mermaid
sequenceDiagram
    participant Client
    participant Server

    Note over Client: 1. ECDH Key Pair 생성 (P-256)
    Note over Client: 2. Timestamp 생성
    Note over Client: 3. Signature = HMAC(PublicKey + Timestamp, ClientSecret)
    
    Client->>Server: POST /api/novels/{id}<br/>{ publicKey, timestamp, signature }
    
    Note over Server: 4. Timestamp 검증 (5분 이내)
    Note over Server: 5. Signature 검증 (HMAC 일치 확인)
    
    alt Signature Invalid
        Server-->>Client: 401 Unauthorized
    else Signature Valid
        Note over Server: 6. ECDH Shared Secret 계산
        Note over Server: 7. AES Session Key 유도 (HKDF)
        Note over Server: 8. Content 암호화 (AES-GCM)
        Server-->>Client: 200 OK<br/>{ publicKey, content }
    end

    Note over Client: 9. ECDH Shared Secret 계산
    Note over Client: 10. AES Session Key 유도
    Note over Client: 11. Content 복호화
```

## 인증 정보 (Demo)
- **CLIENT_SECRET**: `auth-secret-1234`
- **Encryption Algorithm**: AES-256-GCM (Derived from ECDH)
