import Foundation
import CryptoKit

class CryptoManager {
    static let shared = CryptoManager()
    
    // Auth Secret (실제 앱에서는 난독화하거나 안전하게 보관해야 함)
    private let clientSecret = "auth-secret-1234".data(using: .utf8)!
    
    // HKDF용 Salt와 Info는 이제 동적으로 생성됩니다.
    // private let hkdfSalt = ...
    // private let hkdfInfo = ...
    
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
        case randomGenerationFailed
    }
    
    /// 서버에서 소설 내용을 가져와 복호화합니다.
    /// ECDH 키 교환과 HMAC 인증을 수행합니다.
    func fetchAndDecrypt(novelId: String, completion: @escaping (Result<String, Error>) -> Void) {
        // 1. 임시(Ephemeral) 키 쌍 생성 (P-256)
        let clientPrivateKey = P256.KeyAgreement.PrivateKey()
        let clientPublicKey = clientPrivateKey.publicKey
        
        guard let clientPublicKeyDER = try? clientPublicKey.derRepresentation else {
            completion(.failure(CryptoError.keyExchangeFailed))
            return
        }
        let clientPublicKeyBase64 = clientPublicKeyDER.base64EncodedString()
        
        // --- NEW: Random Salt 생성 ---
        var salt = Data(count: 32)
        let result = salt.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        
        guard result == errSecSuccess else {
            completion(.failure(CryptoError.randomGenerationFailed))
            return
        }
        
        let saltBase64 = salt.base64EncodedString()
        // -----------------------------

        // --- HMAC 서명 생성 ---
        // 현재 시간(Timestamp) + 공개키 + Salt를 조합하여 서명
        let timestamp = Int64(Date().timeIntervalSince1970 * 1000)
        let dataToSign = "\(clientPublicKeyBase64)\(timestamp)\(saltBase64)".data(using: .utf8)!
        
        let symmetricKey = SymmetricKey(data: clientSecret)
        let signature = HMAC<SHA256>.authenticationCode(for: dataToSign, using: symmetricKey)
        let signatureBase64 = Data(signature).base64EncodedString()
        // -----------------------

        // 2. 서버로 전송 (POST)
        guard let url = URL(string: "http://localhost:8080/api/novels/\(novelId)") else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let body: [String: Any] = [
            "publicKey": clientPublicKeyBase64,
            "timestamp": timestamp,
            "signature": signatureBase64,
            "salt": saltBase64 // Dynamic Salt 전송
        ]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            // 상태 코드 확인
            if let httpResponse = response as? HTTPURLResponse, !(200...299).contains(httpResponse.statusCode) {
                 completion(.failure(CryptoError.keyExchangeFailed))
                 return
            }
            
            guard let data = data,
                  let json = try? JSONDecoder().decode(EncryptedResponse.self, from: data) else {
                completion(.failure(CryptoError.decryptionFailed))
                return
            }
            
            do {
                // 3. 서버 공개키 Import
                guard let serverPublicKeyData = Data(base64Encoded: json.publicKey) else {
                    throw CryptoError.invalidBase64
                }
                
                let serverPublicKey = try P256.KeyAgreement.PublicKey(derRepresentation: serverPublicKeyData)
                
                // 4. 공유 비밀 계신 (ECDH)
                let sharedSecret = try clientPrivateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)
                
                // 5. AES 세션 키 유도 (HKDF)
                // Info: "novel-id:{id}|ts:{timestamp}"
                // 서버 응답의 timestamp를 사용하여 Info 구성
                let infoString = "novel-id:\(novelId)|ts:\(timestamp)"
                let infoData = infoString.data(using: .utf8)!
                
                let sessionKey = sharedSecret.hkdfDerivedSymmetricKey(
                    using: SHA256.self,
                    salt: salt, // Generated Salt
                    sharedInfo: infoData, // Context Binding Info
                    outputByteCount: 32
                )
                
                // 6. 콘텐츠 복호화 (AES-GCM)
                let decryptedContent = try self.decrypt(base64String: json.content, key: sessionKey, infoString: infoString)
                completion(.success(decryptedContent))
                
            } catch {
                completion(.failure(error))
            }
        }.resume()
    }
    
    private func decrypt(base64String: String, key: SymmetricKey, infoString: String) throws -> String {
        guard let data = Data(base64Encoded: base64String) else {
            throw CryptoError.invalidBase64
        }
        
        let ivSize = 12
        guard data.count > ivSize else { throw CryptoError.decryptionFailed }
        
        // 데이터 구조: IV(12) + Ciphertext + Tag
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        
        // AAD 설정 (Context Binding)
        let aad = infoString.data(using: .utf8)!
        
        let decryptedData = try AES.GCM.open(sealedBox, using: key, authenticating: aad)
        
        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw CryptoError.decryptionFailed
        }
        
        return decryptedString
    }
}
