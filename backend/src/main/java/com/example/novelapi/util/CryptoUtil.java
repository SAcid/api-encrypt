package com.example.novelapi.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoUtil {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_SIZE = 12; // GCM Standard IV size
    private static final int TAG_LENGTH_BIT = 128; // GCM Standard Tag size

    // In a real app, manage this key securely (e.g., Vault, Env Var).
    // Must be 32 bytes for AES-256.
    private static final String SECRET_KEY = "12345678901234567890123456789012";

    public static String encrypt(String plainText) throws Exception {
        byte[] clean = plainText.getBytes(StandardCharsets.UTF_8);

        // Generating IV.
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);

        // Hashing key.
        SecretKey secretKey = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "AES");

        // Encrypt.
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

        // GCM mode automatically appends the authentication tag to the end of the
        // ciphertext.
        byte[] encrypted = cipher.doFinal(clean);

        // Combine IV and Encrypted part (Ciphertext + Tag).
        byte[] encryptedIVAndText = new byte[IV_SIZE + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, IV_SIZE);
        System.arraycopy(encrypted, 0, encryptedIVAndText, IV_SIZE, encrypted.length);

        return Base64.getEncoder().encodeToString(encryptedIVAndText);
    }

    public static String decrypt(String encryptedIvText) throws Exception {
        byte[] encryptedIvTextBytes = Base64.getDecoder().decode(encryptedIvText);

        // Extract IV.
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(encryptedIvTextBytes, 0, iv, 0, IV_SIZE);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);

        // Extract Encrypted part.
        int encryptedSize = encryptedIvTextBytes.length - IV_SIZE;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(encryptedIvTextBytes, IV_SIZE, encryptedBytes, 0, encryptedSize);

        // Hash key.
        SecretKey secretKey = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "AES");

        // Decrypt.
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

        // This will throw AEADBadTagException if the tag is invalid (tampered data).
        byte[] decryptedByte = cipher.doFinal(encryptedBytes);

        return new String(decryptedByte, StandardCharsets.UTF_8);
    }
}
