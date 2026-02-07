package com.example.novelapi.util;

import org.junit.jupiter.api.Test;
import javax.crypto.AEADBadTagException;
import java.util.Base64;
import static org.junit.jupiter.api.Assertions.*;

class CryptoUtilTest {

    @Test
    void testEncryptionDecryption() throws Exception {
        String originalText = "This is a secret novel content with GCM security.";

        String encryptedText = CryptoUtil.encrypt(originalText);
        assertNotNull(encryptedText);
        assertNotEquals(originalText, encryptedText);

        String decryptedText = CryptoUtil.decrypt(encryptedText);
        assertEquals(originalText, decryptedText);
    }

    @Test
    void testKoreanContent() throws Exception {
        String originalText = "이것은 비밀 소설 내용입니다. GCM 모드로 보호됩니다.";

        String encryptedText = CryptoUtil.encrypt(originalText);
        String decryptedText = CryptoUtil.decrypt(encryptedText);

        assertEquals(originalText, decryptedText);
    }

    @Test
    void testTamperingDetection() throws Exception {
        String originalText = "Sensitive Data";
        String encryptedText = CryptoUtil.encrypt(originalText);

        // Decode Base64
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);

        // Tamper with the LAST byte (part of the Auth Tag or Ciphertext)
        encryptedBytes[encryptedBytes.length - 1] ^= 1;

        String tamperedText = Base64.getEncoder().encodeToString(encryptedBytes);

        // Expect decryption to fail
        assertThrows(AEADBadTagException.class, () -> {
            CryptoUtil.decrypt(tamperedText);
        });
    }
}
