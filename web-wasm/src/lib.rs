use wasm_bindgen::prelude::*;
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Key, Payload}};
use hkdf::Hkdf;
use sha2::Sha256;
use hmac::{Hmac, Mac};
// Import Digest KeyInit for HMAC - Removed to avoid ambiguity
// use sha2::digest::KeyInit as _; 
use p256::{PublicKey, ecdh::EphemeralSecret, NistP256};
// Import PKCS8 traits for key encoding/decoding
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use rand_core::{OsRng, RngCore};
use base64::{Engine as _, engine::general_purpose};

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

const CLIENT_SECRET: &[u8] = b"auth-secret-1234";
// HKDF Constants removed - using dynamic values
// const HKDF_SALT: &[u8] = b"novel-api-salt";
// const HKDF_INFO: &[u8] = b"aes-gcm-key";

#[wasm_bindgen]
pub struct CryptoManager {
    secret_key: Option<EphemeralSecret>,
    public_key_base64: String,
    salt: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl CryptoManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> CryptoManager {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public_key = PublicKey::from(&secret);
        
        // Export SPKI (SubjectPublicKeyInfo) format
        // Note: p256 crate's to_public_key_der output is SPKI
        let spki_der = public_key.to_public_key_der().unwrap();
        let base64 = general_purpose::STANDARD.encode(spki_der.as_bytes());

        CryptoManager {
            secret_key: Some(secret),
            public_key_base64: base64,
            salt: None,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> String {
        self.public_key_base64.clone()
    }

    pub fn generate_auth_signature(&mut self) -> Result<String, JsValue> {
        let timestamp = js_sys::Date::now().round() as u64;

        // Generate Random Salt first
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let salt_base64 = general_purpose::STANDARD.encode(salt);
        self.salt = Some(salt.to_vec());

        // Sign: PublicKey + Timestamp + Salt
        let data_to_sign = format!("{}{}{}", self.public_key_base64, timestamp, salt_base64);
        
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(CLIENT_SECRET)
            .map_err(|_| JsValue::from_str("HMAC Init Failed"))?;
        
        mac.update(data_to_sign.as_bytes());
        let result = mac.finalize();
        let signature_base64 = general_purpose::STANDARD.encode(result.into_bytes());

        // Return JSON: { timestamp, signature, salt }
        let json = format!(r#"{{"timestamp": {}, "signature": "{}", "salt": "{}"}}"#, timestamp, signature_base64, salt_base64);
        Ok(json)
    }

    pub fn decrypt_content(&mut self, server_pub_key_base64: &str, encrypted_content_base64: &str, novel_id: &str) -> Result<String, JsValue> {
        // 1. Decode Server Public Key
        let server_pub_bytes = general_purpose::STANDARD.decode(server_pub_key_base64)
            .map_err(|_| JsValue::from_str("Invalid Base64 Server Key"))?;
        
        let server_public = PublicKey::from_public_key_der(&server_pub_bytes)
            .map_err(|_| JsValue::from_str("Invalid Server Public Key Der"))?;

        // 2. ECDH: Compute Shared Secret
        let secret = self.secret_key.take().ok_or("Secret key already used or missing")?;
        let shared_secret = secret.diffie_hellman(&server_public);
        
        // --- Zeroization Applied ---
        // shared_secret_bytes ref is immutable, so we copy it to a zeroizable buffer
        let mut shared_secret_vec = shared_secret.raw_secret_bytes().to_vec();

        // 3. HKDF: Derive AES Key
        // Use stored Dynamic Salt
        let salt = self.salt.as_ref().ok_or("Salt not generated")?;
        let hkdf = Hkdf::<Sha256>::new(Some(salt), &shared_secret_vec);
        
        // Explicitly zeroize shared secret copy immediately after use
        use zeroize::Zeroize;
        shared_secret_vec.zeroize();

        // Construct Context-Specific Info: "novel-id:{id}|user:test"
        let info_string = format!("novel-id:{}|user:test", novel_id);
        let info_bytes = info_string.as_bytes();

        let mut okm = [0u8; 32];
        hkdf.expand(info_bytes, &mut okm)
            .map_err(|_| JsValue::from_str("HKDF Failed"))?;
        
        let session_key = Key::<Aes256Gcm>::from_slice(&okm);
        let cipher = Aes256Gcm::new(session_key);

        // Zeroize intermediate HKDF output (session key material)
        okm.zeroize();
        // ---------------------------

        // 4. Decrypt AES-GCM
        let encrypted_bytes = general_purpose::STANDARD.decode(encrypted_content_base64)
            .map_err(|_| JsValue::from_str("Invalid Base64 Content"))?;
        
        if encrypted_bytes.len() < 12 {
            return Err(JsValue::from_str("Content too short"));
        }

        let nonce = &encrypted_bytes[..12];
        let ciphertext = &encrypted_bytes[12..];
        
        let payload = Payload {
            msg: ciphertext,
            aad: info_bytes, // AAD (Context Binding)
        };

        let plaintext = cipher.decrypt(nonce.into(), payload)
            .map_err(|_| JsValue::from_str("Decryption Failed"))?;

        String::from_utf8(plaintext)
            .map_err(|_| JsValue::from_str("Invalid UTF-8 Plaintext"))
    }
}
