# 암호화 명세서 (v4 - ECDH + Client Auth)

## 프로토콜 개요
**ECDH (P-256)** 키 교환에 **HMAC-SHA256 서명**을 추가하여 클라이언트 인증을 수행합니다.

### POST를 사용하는 이유 (Why POST instead of GET?)
콘텐츠를 "조회"하는 API이지만, **GET이 아닌 POST**를 사용합니다. 이는 REST 의미론보다 **보안**을 우선한 설계입니다.

| 항목 | GET (Query Parameter) | POST (Request Body) |
| :--- | :--- | :--- |
| **민감 정보 노출** | ⚠️ URL에 공개키·서명이 포함되어 서버 로그, 브라우저 히스토리, CDN 로그, Referer 헤더에 기록됨 | ✅ Body는 로그에 기록되지 않음 |
| **URL 길이 제한** | ⚠️ ECDH 공개키(~180자) + 서명 + Salt로 URL이 수백 자 이상이 됨. 일부 프록시/CDN에서 잘릴 수 있음 | ✅ Body 크기 제한 없음 |
| **URL 인코딩** | ⚠️ Base64의 `+`, `/`, `=` 문자가 URL 인코딩 필요 (`%2B`, `%2F`, `%3D`). 인코딩/디코딩 오류 위험 | ✅ JSON으로 전송하므로 인코딩 이슈 없음 |
| **캐싱** | ⚠️ 브라우저/CDN이 자동 캐싱할 수 있음. 매번 새로운 ECDH 키 쌍이 필요한 구조와 충돌 | ✅ 캐싱되지 않음 |
| **북마크/공유** | ⚠️ 인증 정보가 포함된 URL이 북마크·공유될 위험 | ✅ 불가능 |

> **핵심**: 이 API는 단순 조회가 아니라 **ECDH 키 교환 + HMAC 인증 + 암호화**를 동시에 수행하는 **보안 프로토콜 엔드포인트**이므로, POST가 적합합니다.

### 1. 키 교환 핸드셰이크 (Key Exchange Handshake)
1.  **Client (클라이언트)**:
    *   ECDH 키 쌍 생성 (`Client Public Key`).
    *   **Random Salt 생성**: 32 bytes 난수 (Base64).
    *   현재 시간 `timestamp` (Unix Epoch Milliseconds) 생성.
    *   **서명 생성**: `Signature` = HMAC-SHA256(`Client Public Key` + `timestamp` + `Salt`, `CLIENT_SECRET`).
    *   전송: `{ publicKey, timestamp, signature, salt }`

2.  **Server (서버)**:
    *   **타임스탬프 검증**: `Current Time` - `timestamp` < 5분 (Replay Attack 방지).
    *   **서명 검증**: 클라이언트가 보낸 `salt`를 포함하여 HMAC 재계산 및 비교 (Salt Integrity).
    *   **Replay 방어**: Redis SETNX로 동일 (publicKey, timestamp, salt) 조합 재사용 차단.
    *   검증 성공 시 ECDH 수행.
    *   응답: `{ publicKey, content }`

### 흐름도 (Sequence Diagram)
```mermaid
sequenceDiagram
    participant Client
    participant Server

    Note over Client: 1. ECDH Key Pair 생성 (P-256)
    Note over Client: 2. Random Salt 생성 (32 bytes)
    Note over Client: 3. Timestamp 생성
    Note over Client: 4. Signature = HMAC(PublicKey + Timestamp + Salt, ClientSecret)
    
    Client->>Server: POST /api/novels/{entryId}<br/>{ publicKey, timestamp, signature, salt }
    
    Note over Server: 5. Timestamp 검증 (5분 이내)
    Note over Server: 6. Signature 검증 (HMAC 일치 확인)
    Note over Server: 7. Replay Guard (Redis SETNX)
    
    alt 인증 실패
        Server-->>Client: 401 Unauthorized
    else 인증 성공
        Note over Server: 8. ECDH Shared Secret 계산
        Note over Server: 9. AES Session Key 유도 (HKDF)<br/>Salt: Client Random Salt<br/>Info: "entry-id:{entryId}|ts:{timestamp}"
        Note over Server: 10. Content 암호화 (AES-GCM + AAD)
        Server-->>Client: 200 OK<br/>{ publicKey, content }
    end

    Note over Client: 11. ECDH Shared Secret 계산
    Note over Client: 12. AES Session Key 유도 (HKDF)<br/>(Android: Tink, iOS: CryptoKit, Web: WebCrypto)<br/>Salt & Info 동일 사용
    Note over Client: 13. Content 복호화 (AAD 검증 포함)
```

## 2. 상세 암호화/복호화 프로세스 (Detailed Cryptographic Process)

### Step 1: 키 생성 (Key Generation)
*   **알고리즘**: Elliptic Curve Diffie-Hellman (ECDH)
*   **Curve**: `secp256r1` (NIST P-256)
*   **Public Key Format**: X.509 `SubjectPublicKeyInfo` (SPKI)
*   **Private Key Format**: PKCS#8

### Step 2: 키 교환 (Key Exchange)
*   **입력**: `My Private Key`, `Peer Public Key`
*   **출력**: `Shared Secret` (32 bytes)
*   **설명**: 표준 ECDH 알고리즘을 사용하여 양쪽이 동일한 공유 비밀을 계산합니다.

### Step 3: 키 유도 (Key Derivation - HKDF)
공유 비밀을 그대로 암호화 키로 사용하지 않고, **HKDF (HMAC-based Key Derivation Function)** 를 통해 안전한 세션 키를 유도합니다.
*   **Algorithm**: `HKDF-SHA256`
*   **Salt**: Client가 생성한 Random 32 bytes (`salt` param)
*   **Info**: `"entry-id:{entryId}|ts:{timestamp}"` (Context Binding, UTF-8 bytes)
    *   `{entryId}`: 요청된 소설 챕터 ID
    *   `{timestamp}`: 클라이언트가 생성한 타임스탬프 (Unix Epoch Milliseconds)
*   **Output**: 32 bytes (256 bits) -> **AES Session Key**

### Step 4: 데이터 암호화 (Data Encryption - AES-GCM)
*   **Algorithm**: `AES/GCM/NoPadding`
*   **Key**: Step 3에서 유도된 `Session Key` (32 bytes)
*   **IV (Initialization Vector)**: 매 요청마다 생성되는 Random 12 bytes
*   **Tag Length**: 128 bits
*   **AAD (Additional Authenticated Data)**: `"entry-id:{entryId}|ts:{timestamp}"` (Context Binding)
    *   Info 문자열과 동일한 값을 AAD로 사용하여 암호문에 컨텍스트를 바인딩합니다.
*   **출력 포맷**: `Base64(IV + Ciphertext + Tag)`
    *   앞 12바이트: IV
    *   나머지: 암호문 + 인증 태그(Tag는 자동으로 붙음)

### Step 5: 클라이언트 인증 (Client Authentication & Integrity)
*   **Algorithm**: `HMAC-SHA256`
*   **Secret**: `CLIENT_SECRET` ("auth-secret-1234")
*   **Data to Sign**: `ClientPublicKey(Base64)` + `Timestamp(Long as String)` + `Salt(Base64)`
*   **Verification**: 키 교환 전에 서명을 검증하여 허가된 클라이언트인지 확인하며, Salt의 무결성을 보장함.
*   **Timing Attack 방지**: `MessageDigest.isEqual()` 사용 (Constant-time comparison)

## 3. 스트리밍 API (SSE - Server-Sent Events)

대용량 콘텐츠를 Chunk 단위로 암호화하여 실시간 스트리밍합니다.

*   **Endpoint**: `POST /api/novels/{id}/stream?chunkSize=100`
*   **인증**: REST API와 동일 (HMAC + Timestamp + Replay Guard)
*   **이벤트 흐름**:
    1.  `init` — `{ publicKey, totalChunks }` (서버 공개키 + 총 청크 수)
    2.  `chunk` — `{ index, content }` (암호화된 텍스트 조각, 각각 독립 IV)
    3.  `done` — `{ totalChunks }` (스트림 종료 신호)
*   **각 Chunk는 동일한 Session Key + 독립된 IV로 암호화됩니다.**

## 참고 정보 (Demo)
*   **CLIENT_SECRET**: `auth-secret-1234`
*   **REST API**: `POST http://localhost:8080/api/novels/1`
*   **Streaming API**: `POST http://localhost:8080/api/novels/1/stream?chunkSize=100`
