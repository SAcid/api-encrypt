# 암호화 명세서 (v3 - ECDH 보안)

## 프로토콜 개요 (ECDH + AES-GCM)
고정된 키(Static Key) 대신 **Curve P-256 (secp256r1)** 을 사용하는 **Ephemeral ECDH** 방식을 사용합니다.

### 1. 키 교환 핸드셰이크 (Key Exchange Handshake)
1.  **Client (클라이언트)**:
    *   ECDH 키 쌍(Client Private, Client Public)을 생성합니다.
    *   `Client Public Key` (Base64, X.509 SPKI 포맷)를 서버로 전송합니다.

2.  **Server (서버)**:
    *   `Client Public Key`를 수신합니다.
    *   ECDH 키 쌍(Server Private, Server Public)을 생성합니다.
    *   **공유 비밀 (Shared Secret)** 계산 = ECDH(Server Private, Client Public).
    *   **AES 세션 키 (Session Key)** 유도 = HKDF-SHA256(Shared Secret, salt="novel-api-salt", info="aes-gcm-key").
    *   내용을 **AES-GCM**으로 암호화 (세션 키 사용).
    *   반환 값:
        *   `publicKey`: Server Public Key (Base64, X.509 SPKI).
        *   `content`: 암호화된 내용 (Base64: IV + Ciphertext + Tag).

3.  **Client (클라이언트)**:
    *   `Server Public Key`와 `content`를 수신합니다.
    *   **공유 비밀 (Shared Secret)** 계산 = ECDH(Client Private, Server Public).
    *   **AES 세션 키 (Session Key)** 유도 = HKDF-SHA256(Shared Secret, salt="novel-api-salt", info="aes-gcm-key").
    *   세션 키를 사용하여 `content`를 복호화합니다.

## 알고리즘 상세
- **키 교환 (Key Exchange)**: ECDH (P-256)
- **키 유도 (Key Derivation)**: HKDF (HMAC-SHA256)
- **암호화 (Encryption)**: AES-256-GCM (v2와 동일)
