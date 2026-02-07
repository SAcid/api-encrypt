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

/**
 * 암호화 관련 유틸리티 클래스
 * ECDH 키 교환, AES-GCM 암호화, HKDF 키 유도 기능을 제공합니다.
 */
public class CryptoUtil {

    private static final String AEAD_ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_SIZE = 12; // GCM 권장 IV 크기 (12 bytes)
    private static final int TAG_LENGTH_BIT = 128; // 인증 태그 길이
    private static final String EC_ALGORITHM = "EC";

    // HKDF용 Salt와 Info (클라이언트와 서버가 동일해야 함)
    private static final byte[] HKDF_SALT = "novel-api-salt".getBytes(StandardCharsets.UTF_8);
    private static final byte[] HKDF_INFO = "aes-gcm-key".getBytes(StandardCharsets.UTF_8);

    // --- ECDH Key Exchange ---

    /**
     * 임시(Ephemeral) ECDH 키 쌍(P-256)을 생성합니다.
     */
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EC_ALGORITHM);
        keyPairGenerator.initialize(256); // secp256r1
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 내 개인키와 상대방의 공개키를 사용하여 공유 비밀(Shared Secret)을 계산합니다.
     */
    public static byte[] computeSharedSecret(PrivateKey privateKey, String remotePublicKeyBase64) throws Exception {
        // 상대방 공개키 디코딩 (X.509 SPKI 포맷)
        byte[] publicBytes = Base64.getDecoder().decode(remotePublicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM);
        PublicKey remotePublicKey = keyFactory.generatePublic(keySpec);

        // ECDH 수행
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(remotePublicKey, true);
        return keyAgreement.generateSecret();
    }

    /**
     * 공유 비밀(Shared Secret)로부터 AES 암호화 키를 유도합니다 (HKDF-SHA256 사용).
     */
    public static SecretKey deriveKey(byte[] sharedSecret) throws Exception {
        // HKDF 구현 (Extract & Expand 단계)

        // 1. Extract: 공유 비밀을 고정 길이의 PRK(Pseudorandom Key)로 추출
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(HKDF_SALT, "HmacSHA256"));
        byte[] prk = mac.doFinal(sharedSecret);

        // 2. Expand: PRK를 사용하여 AES 키 길이(32바이트)만큼 확장
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(HKDF_INFO);
        mac.update((byte) 0x01); // Counter
        byte[] okm = mac.doFinal();

        // 결과 중 앞 32바이트를 AES-256 키로 사용
        byte[] aesKeyBytes = Arrays.copyOf(okm, 32);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    // --- AES-GCM Encryption (Using Derived Key) ---

    /**
     * 파생된 세션 키를 사용하여 평문을 AES-GCM으로 암호화합니다.
     * 
     * @return Base64(IV + 암호문 + 인증태그)
     */
    public static String encrypt(String plainText, SecretKey key) throws Exception {
        byte[] clean = plainText.getBytes(StandardCharsets.UTF_8);

        // 고유 IV 생성
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);

        Cipher cipher = Cipher.getInstance(AEAD_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

        byte[] encrypted = cipher.doFinal(clean);

        // 결과 병합: IV + Encrypted Data (Tag는 doFinal 결과 뒤에 포함됨)
        byte[] encryptedIVAndText = new byte[IV_SIZE + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, IV_SIZE);
        System.arraycopy(encrypted, 0, encryptedIVAndText, IV_SIZE, encrypted.length);

        return Base64.getEncoder().encodeToString(encryptedIVAndText);
    }

    /**
     * 암호문 복호화 (테스트용)
     */
    public static String decrypt(String encryptedIvText, SecretKey key) throws Exception {
        byte[] encryptedIvTextBytes = Base64.getDecoder().decode(encryptedIvText);

        // IV 추출
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(encryptedIvTextBytes, 0, iv, 0, IV_SIZE);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);

        // 암호문 데이터 추출
        int encryptedSize = encryptedIvTextBytes.length - IV_SIZE;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(encryptedIvTextBytes, IV_SIZE, encryptedBytes, 0, encryptedSize);

        Cipher cipher = Cipher.getInstance(AEAD_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

        byte[] decryptedByte = cipher.doFinal(encryptedBytes);

        return new String(decryptedByte, StandardCharsets.UTF_8);
    }
}
