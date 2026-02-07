import Foundation
import CryptoKit

class CryptoManager {
    static let shared = CryptoManager()
    
    // Hardcoded Key for Demo (32 bytes)
    // In production, use Keychain to store keys securely.
    private let keyData: Data
    
    private init() {
        let keyString = "12345678901234567890123456789012"
        self.keyData = keyString.data(using: .utf8)!
    }
    
    enum CryptoError: Error {
        case invalidBase64
        case decryptionFailed
    }
    
    /// Decrypts a Base64 string containing [IV (12 bytes) + Ciphertext + Tag]
    func decrypt(base64String: String) throws -> String {
        guard let data = Data(base64Encoded: base64String) else {
            throw CryptoError.invalidBase64
        }
        
        // Extract IV (First 12 bytes for GCM)
        let ivSize = 12
        guard data.count > ivSize else {
            throw CryptoError.decryptionFailed
        }
        
        let iv = data.prefix(ivSize)
        let ciphertext = data.dropFirst(ivSize)
        
        // Create SymmetricKey
        let symmetricKey = SymmetricKey(data: keyData)
        
        // Decrypt using AES.GCM
        // CryptoKit expects the tag to be appended to the ciphertext, which matches our backend format.
        // SealedBox structure: Nonce (IV) + Ciphertext + Tag
        do {
            let nonce = try AES.GCM.Nonce(data: iv)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: Data()) 
            // Note: CryptoKit's SealedBox(nonce:ciphertext:tag:) splits them.
            // But if we have combined data (ciphertext + tag), we can try to use `SealedBox(combined:)`
            // However, `SealedBox(combined:)` expects nonce + ciphertext + tag in a specific format.
            // Our format is: IV (12) + Ciphertext + Tag.
            // Let's us the `combined` initializer which acts on the standard representation.
            
            let sealedBoxCombined = try AES.GCM.SealedBox(combined: data)
            let decryptedData = try AES.GCM.open(sealedBoxCombined, using: symmetricKey)
            
            guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
                throw CryptoError.decryptionFailed
            }
            
            return decryptedString
            
        } catch {
            print("Decryption error: \(error)")
            throw CryptoError.decryptionFailed
        }
    }
}
