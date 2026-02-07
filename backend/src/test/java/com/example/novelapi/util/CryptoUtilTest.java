package com.example.novelapi.util;

import org.junit.jupiter.api.Test;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;
import static org.junit.jupiter.api.Assertions.*;

class CryptoUtilTest {

    @Test
    void testEcdhKeyExchangeAndEncryption() throws Exception {
        // ... (Same as before) ...
        KeyPair clientKeyPair = CryptoUtil.generateKeyPair();
        String clientPublicKeyBase64 = Base64.getEncoder().encodeToString(clientKeyPair.getPublic().getEncoded());

        KeyPair serverKeyPair = CryptoUtil.generateKeyPair();
        byte[] serverSharedSecret = CryptoUtil.computeSharedSecret(serverKeyPair.getPrivate(), clientPublicKeyBase64);
        SecretKey serverSessionKey = CryptoUtil.deriveKey(serverSharedSecret);

        String originalText = "ECDH Test Content";
        String encryptedText = CryptoUtil.encrypt(originalText, serverSessionKey);

        String serverPublicKeyBase64 = Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded());
        byte[] clientSharedSecret = CryptoUtil.computeSharedSecret(clientKeyPair.getPrivate(), serverPublicKeyBase64);
        SecretKey clientSessionKey = CryptoUtil.deriveKey(clientSharedSecret);

        assertArrayEquals(serverSessionKey.getEncoded(), clientSessionKey.getEncoded());
        String decryptedText = CryptoUtil.decrypt(encryptedText, clientSessionKey);
        assertEquals(originalText, decryptedText);
    }

    @Test
    void testHmacSignature() throws Exception {
        String clientSecret = "auth-secret-1234";
        String publicKey = "somePublicKeyBase64";
        long timestamp = 1678888888000L;

        String data = publicKey + timestamp;

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(clientSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] signatureBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.getEncoder().encodeToString(signatureBytes);

        assertNotNull(signature);
    }
}
