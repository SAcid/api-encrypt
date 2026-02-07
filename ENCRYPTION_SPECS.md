# Encryption Specification (v2 - Secure)

## Algorithm Details
- **Algorithm**: AES (Advanced Encryption Standard)
- **Mode**: GCM (Galois/Counter Mode)
- **Padding**: NoPadding (GCM handles padding internally as a stream cipher)
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 96 bits (12 bytes) - *Standard for GCM efficiency*
- **Tag Length**: 128 bits (16 bytes) - *Appended automatically to ciphertext*

## Security Benefits (Why GCM?)
1.  **Integrity & Authenticity**: GCM includes an authentication tag. If the ciphertext is altered (e.g., Man-in-the-Middle attack), decryption will fail with an `AEADBadTagException`.
2.  **Confidentiality**: Like CBC, it keeps the data secret.
3.  **Performance**: GCM is parallelizable and often hardware-accelerated.

## Data Format
The encrypted data returned by the API is a Base64 encoded string containing the **IV** and the **Ciphertext (which includes the Auth Tag at the end)**.

`[IV (12 bytes)] + [Ciphertext + Auth Tag]` -> **Base64 Encode**

### Decryption Process
1.  **Base64 Decode**: Get byte array.
2.  **Extract IV**: First **12 bytes**.
3.  **Extract Ciphertext**: Remaining bytes.
4.  **Decrypt**: Use AES/GCM/NoPadding with the Key, IV, and Tag Length (128) to decrypt.
