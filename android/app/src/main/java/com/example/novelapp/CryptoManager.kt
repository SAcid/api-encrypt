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

object CryptoManager {

    private const val ALGORITHM_AES = "AES/GCM/NoPadding"
    private const val ALGORITHM_EC = "EC"
    private const val IV_SIZE = 12
    private const val TAG_LENGTH_BIT = 128
    
    private const val CLIENT_SECRET = "auth-secret-1234"
    
    private val HKDF_SALT = "novel-api-salt".toByteArray(StandardCharsets.UTF_8)
    private val HKDF_INFO = "aes-gcm-key".toByteArray(StandardCharsets.UTF_8)

    interface DecryptCallback {
        fun onSuccess(content: String)
        fun onError(e: Exception)
    }
    
    // --- Helper for generating Auth Signature ---
    fun generateAuth(publicKeyBase64: String): Pair<Long, String> {
        val timestamp = System.currentTimeMillis()
        val data = publicKeyBase64 + timestamp
        
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(CLIENT_SECRET.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        
        val signatureBytes = mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
        val signatureBase64 = Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
        
        return Pair(timestamp, signatureBase64)
    }

    /**
     * ECDH Key Exchange Support
     */
    fun generateClientKeys(): Pair<java.security.PrivateKey, String> {
        val kpg = KeyPairGenerator.getInstance(ALGORITHM_EC)
        kpg.initialize(256)
        val kp = kpg.generateKeyPair()
        val publicKeyBase64 = Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP)
        return Pair(kp.private, publicKeyBase64)
    }

    fun deriveSessionKey(clientPrivateKey: java.security.PrivateKey, serverPublicKeyBase64: String): javax.crypto.SecretKey {
        val serverBytes = Base64.decode(serverPublicKeyBase64, Base64.DEFAULT)
        val kf = KeyFactory.getInstance(ALGORITHM_EC)
        val serverPublicKey = kf.generatePublic(X509EncodedKeySpec(serverBytes))

        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(clientPrivateKey)
        ka.doPhase(serverPublicKey, true)
        val sharedSecret = ka.generateSecret()

        return hkdfSha256(sharedSecret)
    }

    fun decryptContent(encryptedContentBase64: String, sessionKey: javax.crypto.SecretKey): String {
        val encryptedData = Base64.decode(encryptedContentBase64, Base64.DEFAULT)

        val iv = encryptedData.copyOfRange(0, IV_SIZE)
        val ciphertext = encryptedData.copyOfRange(IV_SIZE, encryptedData.size)

        val spec = GCMParameterSpec(TAG_LENGTH_BIT, iv)
        val cipher = Cipher.getInstance(ALGORITHM_AES)
        cipher.init(Cipher.DECRYPT_MODE, sessionKey, spec)

        val decryptedBytes = cipher.doFinal(ciphertext)
        return String(decryptedBytes, StandardCharsets.UTF_8)
    }

    private fun hkdfSha256(inputKeyingMaterial: ByteArray): javax.crypto.SecretKey {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(HKDF_SALT, "HmacSHA256"))
        val prk = mac.doFinal(inputKeyingMaterial)

        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(HKDF_INFO)
        mac.update(0x01.toByte())
        val okm = mac.doFinal()

        val keyBytes = okm.copyOf(32)
        return SecretKeySpec(keyBytes, "AES")
    }
}
