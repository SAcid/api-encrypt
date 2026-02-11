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

        byte[] salt = new byte[32]; // Dummy Salt
        byte[] info = "entry-id:test|user:test".getBytes(StandardCharsets.UTF_8); // Dummy Info

        KeyPair serverKeyPair = CryptoUtil.generateKeyPair();
        byte[] serverSharedSecret = CryptoUtil.computeSharedSecret(serverKeyPair.getPrivate(), clientPublicKeyBase64);
        SecretKey serverSessionKey = CryptoUtil.deriveKey(serverSharedSecret, salt, info);

        String originalText = "ECDH Test Content";
        // Context Info를 AAD로 사용
        String encryptedText = CryptoUtil.encrypt(originalText, serverSessionKey, info);

        String serverPublicKeyBase64 = Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded());
        byte[] clientSharedSecret = CryptoUtil.computeSharedSecret(clientKeyPair.getPrivate(), serverPublicKeyBase64);
        SecretKey clientSessionKey = CryptoUtil.deriveKey(clientSharedSecret, salt, info);

        assertArrayEquals(serverSessionKey.getEncoded(), clientSessionKey.getEncoded());
        String decryptedText = CryptoUtil.decrypt(encryptedText, clientSessionKey, info);
        assertEquals(originalText, decryptedText);
    }

    @Test
    void testAadMismatch() throws Exception {
        KeyPair keyPair = CryptoUtil.generateKeyPair();
        SecretKey key = CryptoUtil.deriveKey(new byte[32], new byte[32], "info".getBytes(StandardCharsets.UTF_8));

        byte[] aad1 = "context-1".getBytes(StandardCharsets.UTF_8);
        byte[] aad2 = "context-2".getBytes(StandardCharsets.UTF_8);

        String encrypted = CryptoUtil.encrypt("Secret", key, aad1);

        assertThrows(Exception.class, () -> {
            CryptoUtil.decrypt(encrypted, key, aad2);
        });
    }

    @Test
    void testHmacSignature() throws Exception {
        String clientSecret = "auth-secret-1234";
        String publicKey = "somePublicKeyBase64";
        long timestamp = 1678888888000L;
        String salt = "someSaltBase64";

        String data = publicKey + timestamp + salt;

        // Generate signature using Utility
        String signature = CryptoUtil.generateHmacSignature(data, clientSecret);

        assertNotNull(signature);

        // Verify manual generation matches
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(clientSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] expectedBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        String expected = Base64.getEncoder().encodeToString(expectedBytes);

        assertEquals(expected, signature);
    }

    @Test
    void testHmacSignatureMismatch() throws Exception {
        String clientSecret = "auth-secret-1234";
        String data = "data";
        String signature = CryptoUtil.generateHmacSignature(data, clientSecret);

        String wrongSecret = "wrong-secret";
        String wrongSignature = CryptoUtil.generateHmacSignature(data, wrongSecret);

        assertNotEquals(signature, wrongSignature);
    }
}
