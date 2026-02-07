const API_URL = 'http://localhost:8080/api/novels/1';

async function fetchAndDecrypt() {
    const statusDiv = document.getElementById('status');
    const contentDiv = document.getElementById('content');

    statusDiv.innerText = "키 생성 및 교환 중...";
    contentDiv.innerText = "";

    try {
        // 1. Generate Client ECDH Key Pair (P-256)
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-256"
            },
            true,
            ["deriveKey"]
        );

        // 2. Export Public Key to SPKI (SubjectPublicKeyInfo) format for Server
        const exportedPublicKey = await window.crypto.subtle.exportKey(
            "spki",
            keyPair.publicKey
        );
        const clientPublicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)));

        // 3. Send Public Key to Server
        statusDiv.innerText = "서버와 키 교환 중...";
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ publicKey: clientPublicKeyBase64 })
        });

        if (!response.ok) throw new Error("Server Request Failed");
        const responseData = await response.json();

        // 4. Import Server's Public Key
        const serverPublicKeyBytes = Uint8Array.from(atob(responseData.publicKey), c => c.charCodeAt(0));
        const serverPublicKey = await window.crypto.subtle.importKey(
            "spki",
            serverPublicKeyBytes,
            {
                name: "ECDH",
                namedCurve: "P-256"
            },
            false,
            []
        );

        // 5. Derive Shared Secret & Session Key (HKDF)
        statusDiv.innerText = "세션 키 유도 중...";

        // 5a. Derive Bits (Shared Secret)
        const sharedSecretBits = await window.crypto.subtle.deriveBits(
            {
                name: "ECDH",
                public: serverPublicKey
            },
            keyPair.privateKey,
            256
        );

        // 5b. HKDF Implementation (Web Crypto doesn't have direct HKDF in some browsers, but let's try standard HKDF if available or implement manual HMAC)
        // Modern browsers support HKDF.
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
            {
                name: "AES-GCM",
                length: 256
            },
            false,
            ["decrypt"]
        );

        // 6. Decrypt Content
        statusDiv.innerText = "복호화 중...";
        const encryptedBase64 = responseData.content;
        const encryptedBytes = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

        // Extract IV (12 bytes) and Ciphertext
        const iv = encryptedBytes.slice(0, 12);
        const ciphertext = encryptedBytes.slice(12);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv,
                tagLength: 128
            },
            sessionKey,
            ciphertext
        );

        const dec = new TextDecoder();
        contentDiv.innerText = dec.decode(decryptedBuffer);
        statusDiv.innerText = "완료! (ECDH 보안 연결)";

    } catch (err) {
        console.error(err);
        statusDiv.innerHTML = `<span class="error">오류 발생: ${err.message}</span>`;
    }
}
