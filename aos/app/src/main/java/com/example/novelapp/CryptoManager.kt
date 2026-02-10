package com.example.novelapp

import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 암호화 관리 클래스 (Singleton)
 * ECDH 키 교환, HMAC 서명 생성, AES-GCM 복호화 기능을 제공합니다.
 */
object CryptoManager {

    private const val ALGORITHM_AES = "AES/GCM/NoPadding"
    private const val ALGORITHM_EC = "EC"
    private const val IV_SIZE = 12
    private const val TAG_LENGTH_BIT = 128
    
    // 클라이언트 인증 시크릿 (실제 앱에서는 안전하게 보호해야 함)
    private const val CLIENT_SECRET = "auth-secret-1234"
    
    // private val HKDF_SALT = ... (Dynamic Salt 사용)
    // private val HKDF_INFO = ... (Dynamic Info 사용)

    interface DecryptCallback {
        fun onSuccess(content: String)
        fun onError(e: Exception)
    }
    
    /**
     * 인증 서명 생성 (HMAC-SHA256)
     * @param publicKeyBase64 내 공개키
     * @param saltBase64 Random Salt
     * @return Pair(Timestamp, Signature)
     */
    fun generateAuth(publicKeyBase64: String, saltBase64: String): Pair<Long, String> {
        val timestamp = System.currentTimeMillis()
        val data = publicKeyBase64 + timestamp + saltBase64
        
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(CLIENT_SECRET.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        
        val signatureBytes = mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
        val signatureBase64 = Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
        
        return Pair(timestamp, signatureBase64)
    }

    /**
     * 클라이언트 ECDH 키 쌍 생성
     */
    fun generateClientKeys(): Pair<java.security.PrivateKey, String> {
        val kpg = KeyPairGenerator.getInstance(ALGORITHM_EC)
        kpg.initialize(256)
        val kp = kpg.generateKeyPair()
        val publicKeyBase64 = Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP)
        return Pair(kp.private, publicKeyBase64)
    }

    /**
     * Random Salt 생성 (32 bytes)
     */
    fun generateSalt(): String {
        val salt = ByteArray(32)
        java.security.SecureRandom().nextBytes(salt)
        return Base64.encodeToString(salt, Base64.NO_WRAP)
    }

    /**
     * 세션 키 유도 (ECDH + HKDF)
     */
    fun deriveSessionKey(clientPrivateKey: java.security.PrivateKey, serverPublicKeyBase64: String, saltBase64: String, novelId: String, timestamp: Long): javax.crypto.SecretKey {
        // 1. 서버 공개키 디코딩
        val serverBytes = Base64.decode(serverPublicKeyBase64, Base64.DEFAULT)
        val kf = KeyFactory.getInstance(ALGORITHM_EC)
        val serverPublicKey = kf.generatePublic(X509EncodedKeySpec(serverBytes))

        // 2. 공유 비밀 계산 (ECDH)
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(clientPrivateKey)
        ka.doPhase(serverPublicKey, true)
        val sharedSecret = ka.generateSecret()

        // 3. AES 키 유도 (HKDF)
        val salt = Base64.decode(saltBase64, Base64.DEFAULT)
        // Info: "novel-id:{id}|ts:{timestamp}"
        val infoString = "novel-id:$novelId|ts:$timestamp"
        val info = infoString.toByteArray(StandardCharsets.UTF_8)
        return hkdfSha256(sharedSecret, salt, info)
    }

    // HKDF-SHA256 구현
    private fun hkdfSha256(inputKeyingMaterial: ByteArray, salt: ByteArray, info: ByteArray): javax.crypto.SecretKey {
        // HKDF-Extract
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(inputKeyingMaterial)

        // HKDF-Expand
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(info)
        mac.update(0x01.toByte()) // Counter
        val okm = mac.doFinal()

        // 32바이트(256비트) 키 반환
        val keyBytes = okm.copyOf(32)
        return SecretKeySpec(keyBytes, "AES")
    }
    /**
     * 콘텐츠 복호화 (AES-GCM)
     */
    fun decrypt(encryptedContentBase64: String, sessionKey: javax.crypto.SecretKey, novelId: String, timestamp: Long): String {
        val encryptedBytes = Base64.decode(encryptedContentBase64, Base64.DEFAULT)

        // IV 추출
        val iv = ByteArray(IV_SIZE)
        System.arraycopy(encryptedBytes, 0, iv, 0, IV_SIZE)
        val gcmParameterSpec = GCMParameterSpec(TAG_LENGTH_BIT, iv)

        // 암호문 추출
        val ciphertext = ByteArray(encryptedBytes.size - IV_SIZE)
        System.arraycopy(encryptedBytes, IV_SIZE, ciphertext, 0, ciphertext.size)

        val cipher = Cipher.getInstance(ALGORITHM_AES)
        cipher.init(Cipher.DECRYPT_MODE, sessionKey, gcmParameterSpec)

        // AAD 설정 (Context Binding)
        val infoString = "novel-id:$novelId|ts:$timestamp"
        cipher.updateAAD(infoString.toByteArray(StandardCharsets.UTF_8))

        val decryptedBytes = cipher.doFinal(ciphertext)
        return String(decryptedBytes, StandardCharsets.UTF_8)
    }
