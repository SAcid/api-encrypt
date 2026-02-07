package com.example.novelapi.util;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class CryptoUtil {

    private static final String AEAD_ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_SIZE = 12;
    private static final int TAG_LENGTH_BIT = 128;
    private static final String EC_ALGORITHM = "EC";

    // Salt and Info for HKDF (Should be consistent between Client and Server)
    private static final byte[] HKDF_SALT = "novel-api-salt".getBytes(StandardCharsets.UTF_8);
    private static final byte[] HKDF_INFO = "aes-gcm-key".getBytes(StandardCharsets.UTF_8);

    // --- ECDH Key Exchange ---

    /**
     * Generate an Ephemeral ECDH Key Pair (P-256).
     */
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EC_ALGORITHM);
        keyPairGenerator.initialize(256);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Compute Shared Secret using Local Private Key and Remote Public Key.
     */
    public static byte[] computeSharedSecret(PrivateKey privateKey, String remotePublicKeyBase64) throws Exception {
        byte[] publicBytes = Base64.getDecoder().decode(remotePublicKeyBase64);
        // Note: X509EncodedKeySpec expects SPKI format
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM);
        PublicKey remotePublicKey = keyFactory.generatePublic(keySpec);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(remotePublicKey, true);
        return keyAgreement.generateSecret();
    }

    /**
     * Derive AES Key from Shared Secret using HKDF-SHA256.
     */
    public static SecretKey deriveKey(byte[] sharedSecret) throws Exception {
        // HKDF Implementation (Extract and Expand)
        // 1. Extract (Simulated with simple HMAC since salt is fixed)
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(HKDF_SALT, "HmacSHA256"));
        byte[] prk = mac.doFinal(sharedSecret);

        // 2. Expand
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(HKDF_INFO);
        // Counter = 0x01
        mac.update((byte) 0x01);
        byte[] okm = mac.doFinal();

        // Use first 32 bytes for AES-256 Key
        byte[] aesKeyBytes = Arrays.copyOf(okm, 32);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    // --- AES-GCM Encryption (Using Derived Key) ---

    public static String encrypt(String plainText, SecretKey key) throws Exception {
        byte[] clean = plainText.getBytes(StandardCharsets.UTF_8);

        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);

        Cipher cipher = Cipher.getInstance(AEAD_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

        byte[] encrypted = cipher.doFinal(clean);

        byte[] encryptedIVAndText = new byte[IV_SIZE + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, IV_SIZE);
        System.arraycopy(encrypted, 0, encryptedIVAndText, IV_SIZE, encrypted.length);

        return Base64.getEncoder().encodeToString(encryptedIVAndText);
    }

    // Keep decrypt for testing or if server needs to decrypt client messages
    public static String decrypt(String encryptedIvText, SecretKey key) throws Exception {
        byte[] encryptedIvTextBytes = Base64.getDecoder().decode(encryptedIvText);

        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(encryptedIvTextBytes, 0, iv, 0, IV_SIZE);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);

        int encryptedSize = encryptedIvTextBytes.length - IV_SIZE;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(encryptedIvTextBytes, IV_SIZE, encryptedBytes, 0, encryptedSize);

        Cipher cipher = Cipher.getInstance(AEAD_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

        byte[] decryptedByte = cipher.doFinal(encryptedBytes);

        return new String(decryptedByte, StandardCharsets.UTF_8);
    }
}
