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
    
    private val HKDF_SALT = "novel-api-salt".toByteArray(StandardCharsets.UTF_8)
    private val HKDF_INFO = "aes-gcm-key".toByteArray(StandardCharsets.UTF_8)

    // Using a simple callback interface for demo purposes
    interface DecryptCallback {
        fun onSuccess(content: String)
        fun onError(e: Exception)
    }

    /**
     * ECDH Key Exchange and Decryption flow would typically involve a network call.
     * Since this class focuses on Crypto, we will simulate the steps or provide helper functions
     * that the Activity/ViewModel would call.
     * 
     * For this example, we provide the primitives:
     * 1. generateClientKeys() -> Pair<PrivateKey, PublicKeyBase64>
     * 2. deriveSessionKey(clientPrivateKey, serverPublicKeyBase64) -> SecretKey
     * 3. decryptContent(encryptedContentBase64, sessionKey) -> String
     */

    fun generateClientKeys(): Pair<java.security.PrivateKey, String> {
        val kpg = KeyPairGenerator.getInstance(ALGORITHM_EC)
        kpg.initialize(256)
        val kp = kpg.generateKeyPair()
        val publicKeyBase64 = Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP)
        return Pair(kp.private, publicKeyBase64)
    }

    fun deriveSessionKey(clientPrivateKey: java.security.PrivateKey, serverPublicKeyBase64: String): javax.crypto.SecretKey {
        // 1. Decode Server Public Key
        val serverBytes = Base64.decode(serverPublicKeyBase64, Base64.DEFAULT)
        val kf = KeyFactory.getInstance(ALGORITHM_EC)
        val serverPublicKey = kf.generatePublic(X509EncodedKeySpec(serverBytes))

        // 2. ECDH Shared Secret
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(clientPrivateKey)
        ka.doPhase(serverPublicKey, true)
        val sharedSecret = ka.generateSecret()

        // 3. HKDF-SHA256
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
        // HKDF-Extract (Simulated with simple HMAC)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(HKDF_SALT, "HmacSHA256"))
        val prk = mac.doFinal(inputKeyingMaterial)

        // HKDF-Expand
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(HKDF_INFO)
        mac.update(0x01.toByte()) // Counter
        val okm = mac.doFinal()

        // Take first 32 bytes
        val keyBytes = okm.copyOf(32)
        return SecretKeySpec(keyBytes, "AES")
    }
}
