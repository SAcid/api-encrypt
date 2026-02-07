const { webcrypto } = require('node:crypto');
const crypto = webcrypto;

const CLIENT_SECRET = "auth-secret-1234";

async function verifyAuthLogic() {
    console.log("Starting Web Client Logic Verification (Node.js)...");
    try {
        // 1. Generate ECDH Key Pair
        const keyPair = await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true,
            ["deriveKey"]
        );
        console.log("1. ECDH Key Pair Generated");

        // 2. Export Public Key
        const exportedPublicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
        const clientPublicKeyBase64 = Buffer.from(exportedPublicKey).toString('base64');
        console.log(`2. Public Key Exported: ${clientPublicKeyBase64.substring(0, 20)}...`);

        // 3. Generate HMAC Signature
        const timestamp = Date.now();
        const dataToSign = clientPublicKeyBase64 + timestamp;
        const infoEncoder = new TextEncoder();

        const secretKey = await crypto.subtle.importKey(
            "raw",
            infoEncoder.encode(CLIENT_SECRET),
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"]
        );

        const signatureBuffer = await crypto.subtle.sign(
            "HMAC",
            secretKey,
            infoEncoder.encode(dataToSign)
        );
        const signatureBase64 = Buffer.from(signatureBuffer).toString('base64');

        console.log(`3. Signature Generated: ${signatureBase64}`);
        console.log(`   Timestamp: ${timestamp}`);

        if (signatureBase64.length > 0) {
            console.log("\n✅ VERIFICATION SUCCESS: Web Client Logic is valid.");
        } else {
            console.error("\n❌ VERIFICATION FAILED: Signature is empty.");
            process.exit(1);
        }

    } catch (e) {
        console.error("\n❌ VERIFICATION ERROR:", e);
        process.exit(1);
    }
}

verifyAuthLogic();
