const API_URL = 'http://localhost:8080/api/novels/1';
const CLIENT_SECRET = "auth-secret-1234"; // 주의: 실제 서비스에서는 이 값을 난독화하거나 보호해야 합니다.

async function fetchAndDecrypt() {
    const statusDiv = document.getElementById('status');
    const contentDiv = document.getElementById('content');

    statusDiv.innerText = "키 생성 및 교환 중...";
    contentDiv.innerText = "";

    try {
        // 1. 클라이언트 ECDH 키 쌍 생성 (P-256)
        // - 'deriveKey': 나중에 AES 키를 유도하기 위해 필요
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-256"
            },
            true,
            ["deriveKey"]
        );

        // 2. 공개키 내보내기 (SPKI 포맷)
        // - 서버로 전송하기 위해 바이트 배열을 Base64 문자열로 변환
        const exportedPublicKey = await window.crypto.subtle.exportKey(
            "spki",
            keyPair.publicKey
        );
        const clientPublicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)));

        // --- NEW: HMAC 인증 서명 생성 ---
        // 타임스탬프와 공개키를 조합하고, Client Secret으로 서명하여 자신이 유효한 클라이언트임을 증명
        const timestamp = Date.now();
        const dataToSign = clientPublicKeyBase64 + timestamp;
        const infoEncoder = new TextEncoder();

        // HMAC 키 import
        const secretKey = await window.crypto.subtle.importKey(
            "raw",
            infoEncoder.encode(CLIENT_SECRET),
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"]
        );

        // 서명 생성
        const signatureBuffer = await window.crypto.subtle.sign(
            "HMAC",
            secretKey,
            infoEncoder.encode(dataToSign)
        );
        const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)));
        // ------------------------------------

        // 3. 서버로 키 교환 요청 (인증 정보 포함)
        statusDiv.innerText = "서버와 키 교환 중 (인증 포함)...";
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                publicKey: clientPublicKeyBase64,
                timestamp: timestamp,
                signature: signatureBase64
            })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`서버 요청 실패: ${response.status} ${errorText}`);
        }
        const responseData = await response.json();

        // 4. 서버의 공개키 import
        const serverPublicKeyBytes = Uint8Array.from(atob(responseData.publicKey), c => c.charCodeAt(0));
        const serverPublicKey = await window.crypto.subtle.importKey(
            "spki",
            serverPublicKeyBytes,
            { name: "ECDH", namedCurve: "P-256" },
            false,
            []
        );

        // 5. 공유 비밀 & 세션 키 유도 (HKDF)
        statusDiv.innerText = "세션 키 유도 중...";

        // 5a. 공유 비밀 계산 (ECDH)
        const sharedSecretBits = await window.crypto.subtle.deriveBits(
            { name: "ECDH", public: serverPublicKey },
            keyPair.privateKey,
            256
        );

        // 5b. HKDF를 사용하여 AES 키 유도
        const hkdfKey = await window.crypto.subtle.importKey(
            "raw",
            sharedSecretBits,
            { name: "HKDF" },
            false,
            ["deriveKey"]
        );

        const sessionKey = await window.crypto.subtle.deriveKey(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: new TextEncoder().encode("novel-api-salt"),
                info: new TextEncoder().encode("aes-gcm-key")
            },
            hkdfKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );

        // 6. 콘텐츠 복호화
        statusDiv.innerText = "복호화 중...";
        const encryptedBase64 = responseData.content;
        const encryptedBytes = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

        // IV(12바이트)와 암호문 분리
        const iv = encryptedBytes.slice(0, 12);
        const ciphertext = encryptedBytes.slice(12);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv, tagLength: 128 },
            sessionKey,
            ciphertext
        );

        const dec = new TextDecoder();
        contentDiv.innerText = dec.decode(decryptedBuffer);
        statusDiv.innerText = "완료! (ECDH + Client Auth 성공)";

    } catch (err) {
        console.error(err);
        statusDiv.innerHTML = `<span class="error">오류 발생: ${err.message}</span>`;
    }
}
