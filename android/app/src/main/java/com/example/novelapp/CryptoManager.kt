package com.example.novelapp

import android.util.Base64
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object CryptoManager {

    private const val ALGORITHM = "AES/GCM/NoPadding"
    private const val IV_SIZE = 12
    private const val TAG_LENGTH_BIT = 128
    
    // Hardcoded Key for Demo (32 bytes)
    // In production, use Android Keystore system.
    private const val SECRET_KEY = "12345678901234567890123456789012"

    fun decrypt(encryptedBase64: String): String {
        val encryptedData = Base64.decode(encryptedBase64, Base64.DEFAULT)

        // Extract IV
        val iv = encryptedData.copyOfRange(0, IV_SIZE)
        
        // Extract Ciphertext (including Tag)
        val ciphertext = encryptedData.copyOfRange(IV_SIZE, encryptedData.size)

        // Prepare Key
        val secretKeySpec = SecretKeySpec(SECRET_KEY.toByteArray(StandardCharsets.UTF_8), "AES")
        
        // Prepare IV
        val spec = GCMParameterSpec(TAG_LENGTH_BIT, iv)

        // Decrypt
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, spec)

        val decryptedBytes = cipher.doFinal(ciphertext)
        return String(decryptedBytes, StandardCharsets.UTF_8)
    }
}
