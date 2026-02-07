const API_URL = 'http://localhost:8080/api/novels/1';
const CLIENT_SECRET = "auth-secret-1234"; // In real app, this should be obfuscated/protected

async function fetchAndDecrypt() {
    const statusDiv = document.getElementById('status');
    const contentDiv = document.getElementById('content');

    statusDiv.innerText = "키 생성 및 교환 중...";
    contentDiv.innerText = "";

    try {
        // 1. Generate Client ECDH Key Pair
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-256"
            },
            true,
            ["deriveKey"]
        );

        // 2. Export Public Key
        const exportedPublicKey = await window.crypto.subtle.exportKey(
            "spki",
            keyPair.publicKey
        );
        const clientPublicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)));

        // --- NEW: Generate HMAC Signature ---
        const timestamp = Date.now();
        const dataToSign = clientPublicKeyBase64 + timestamp;
        const infoEncoder = new TextEncoder();

        const secretKey = await window.crypto.subtle.importKey(
            "raw",
            infoEncoder.encode(CLIENT_SECRET),
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"]
        );

        const signatureBuffer = await window.crypto.subtle.sign(
            "HMAC",
            secretKey,
            infoEncoder.encode(dataToSign)
        );
        const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)));
        // ------------------------------------

        // 3. Send to Server with Auth Info
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
            throw new Error(`Server Request Failed: ${response.status} ${errorText}`);
        }
        const responseData = await response.json();

        // ... (Rest is same: Import Server Key, Derive, Decrypt) ...
        const serverPublicKeyBytes = Uint8Array.from(atob(responseData.publicKey), c => c.charCodeAt(0));
        const serverPublicKey = await window.crypto.subtle.importKey(
            "spki",
            serverPublicKeyBytes,
            { name: "ECDH", namedCurve: "P-256" },
            false,
            []
        );

        const sharedSecretBits = await window.crypto.subtle.deriveBits(
            { name: "ECDH", public: serverPublicKey },
            keyPair.privateKey,
            256
        );

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

        statusDiv.innerText = "복호화 중...";
        const encryptedBase64 = responseData.content;
        const encryptedBytes = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

        const iv = encryptedBytes.slice(0, 12);
        const ciphertext = encryptedBytes.slice(12);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv, tagLength: 128 },
            sessionKey,
            ciphertext
        );

        const dec = new TextDecoder();
        contentDiv.innerText = dec.decode(decryptedBuffer);
        statusDiv.innerText = "완료! (ECDH + Client Auth)";

    } catch (err) {
        console.error(err);
        statusDiv.innerHTML = `<span class="error">오류 발생: ${err.message}</span>`;
    }
}
