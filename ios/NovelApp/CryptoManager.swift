import Foundation
import CryptoKit

class CryptoManager {
    static let shared = CryptoManager()
    
    // Auth Secret (Ideally obfuscated)
    private let clientSecret = "auth-secret-1234".data(using: .utf8)!
    
    private let hkdfSalt = "novel-api-salt".data(using: .utf8)!
    private let hkdfInfo = "aes-gcm-key".data(using: .utf8)!
    
    private init() {}
    
    struct EncryptedResponse: Codable {
        let publicKey: String
        let content: String
    }
    
    enum CryptoError: Error {
        case invalidBase64
        case decryptionFailed
        case keyExchangeFailed
        case signatureFailed
    }
    
    func fetchAndDecrypt(novelId: String, completion: @escaping (Result<String, Error>) -> Void) {
        // 1. Generate Ephemeral Key Pair
        let clientPrivateKey = P256.KeyAgreement.PrivateKey()
        let clientPublicKey = clientPrivateKey.publicKey
        
        guard let clientPublicKeyDER = try? clientPublicKey.derRepresentation else {
            completion(.failure(CryptoError.keyExchangeFailed))
            return
        }
        let clientPublicKeyBase64 = clientPublicKeyDER.base64EncodedString()
        
        // --- NEW: Generate HMAC Signature ---
        let timestamp = Int64(Date().timeIntervalSince1970 * 1000)
        let dataToSign = "\(clientPublicKeyBase64)\(timestamp)".data(using: .utf8)!
        
        let symmetricKey = SymmetricKey(data: clientSecret)
        let signature = HMAC<SHA256>.authenticationCode(for: dataToSign, using: symmetricKey)
        let signatureBase64 = Data(signature).base64EncodedString()
        // ------------------------------------
        
        // 2. Send to Server
        guard let url = URL(string: "http://localhost:8080/api/novels/\(novelId)") else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let body: [String: Any] = [
            "publicKey": clientPublicKeyBase64,
            "timestamp": timestamp,
            "signature": signatureBase64
        ]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            if let httpResponse = response as? HTTPURLResponse, !(200...299).contains(httpResponse.statusCode) {
                 completion(.failure(CryptoError.keyExchangeFailed)) // Or specific auth error
                 return
            }
            
            guard let data = data,
                  let json = try? JSONDecoder().decode(EncryptedResponse.self, from: data) else {
                completion(.failure(CryptoError.decryptionFailed))
                return
            }
            
            do {
                // 3. Import Server's Public Key
                guard let serverPublicKeyData = Data(base64Encoded: json.publicKey) else {
                    throw CryptoError.invalidBase64
                }
                
                let serverPublicKey = try P256.KeyAgreement.PublicKey(derRepresentation: serverPublicKeyData)
                
                // 4. Compute Shared Secret
                let sharedSecret = try clientPrivateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)
                
                // 5. Derive AES Key using HKDF
                let sessionKey = sharedSecret.hkdfDerivedSymmetricKey(
                    using: SHA256.self,
                    salt: self.hkdfSalt,
                    sharedInfo: self.hkdfInfo,
                    outputByteCount: 32
                )
                
                // 6. Decrypt content
                let decryptedContent = try self.decrypt(base64String: json.content, key: sessionKey)
                completion(.success(decryptedContent))
                
            } catch {
                completion(.failure(error))
            }
        }.resume()
    }
    
    private func decrypt(base64String: String, key: SymmetricKey) throws -> String {
        guard let data = Data(base64Encoded: base64String) else {
            throw CryptoError.invalidBase64
        }
        
        let ivSize = 12
        guard data.count > ivSize else { throw CryptoError.decryptionFailed }
        
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        let decryptedData = try AES.GCM.open(sealedBox, using: key)
        
        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw CryptoError.decryptionFailed
        }
        
        return decryptedString
    }
}
