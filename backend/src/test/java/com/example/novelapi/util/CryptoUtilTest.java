package com.example.novelapi.util;

import org.junit.jupiter.api.Test;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Base64;
import static org.junit.jupiter.api.Assertions.*;

class CryptoUtilTest {

    @Test
    void testEcdhKeyExchangeAndEncryption() throws Exception {
        // 1. Simulate Client Generating Keys
        KeyPair clientKeyPair = CryptoUtil.generateKeyPair();
        String clientPublicKeyBase64 = Base64.getEncoder().encodeToString(clientKeyPair.getPublic().getEncoded());

        // 2. Simulate Server Generating Keys & Processing
        KeyPair serverKeyPair = CryptoUtil.generateKeyPair();
        byte[] serverSharedSecret = CryptoUtil.computeSharedSecret(serverKeyPair.getPrivate(), clientPublicKeyBase64);
        SecretKey serverSessionKey = CryptoUtil.deriveKey(serverSharedSecret);

        String originalText = "ECDH Test Content";
        String encryptedText = CryptoUtil.encrypt(originalText, serverSessionKey);

        // 3. Simulate Client Decrypting
        String serverPublicKeyBase64 = Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded());
        byte[] clientSharedSecret = CryptoUtil.computeSharedSecret(clientKeyPair.getPrivate(), serverPublicKeyBase64);
        SecretKey clientSessionKey = CryptoUtil.deriveKey(clientSharedSecret);

        // Keys should be identical
        assertArrayEquals(serverSessionKey.getEncoded(), clientSessionKey.getEncoded());

        String decryptedText = CryptoUtil.decrypt(encryptedText, clientSessionKey);
        assertEquals(originalText, decryptedText);
    }
}
