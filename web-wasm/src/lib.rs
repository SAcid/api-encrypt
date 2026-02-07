use wasm_bindgen::prelude::*;
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Key, Payload}};
use hkdf::Hkdf;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use p256::{PublicKey, ecdh::EphemeralSecret, NistP256};
use rand_core::OsRng;
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
const HKDF_SALT: &[u8] = b"novel-api-salt";
const HKDF_INFO: &[u8] = b"aes-gcm-key";

#[wasm_bindgen]
pub struct CryptoManager {
    secret_key: Option<EphemeralSecret>,
    public_key_base64: String,
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
        }
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> String {
        self.public_key_base64.clone()
    }

    pub fn generate_auth_signature(&self) -> Result<String, JsValue> {
        let timestamp = js_sys::Date::now().round() as u64;
        let data_to_sign = format!("{}{}", self.public_key_base64, timestamp);
        
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(CLIENT_SECRET)
            .map_err(|_| JsValue::from_str("HMAC Init Failed"))?;
        
        mac.update(data_to_sign.as_bytes());
        let result = mac.finalize();
        let signature_base64 = general_purpose::STANDARD.encode(result.into_bytes());

        // Return JSON: { timestamp, signature }
        let json = format!(r#"{{"timestamp": {}, "signature": "{}"}}"#, timestamp, signature_base64);
        Ok(json)
    }

    pub fn decrypt_content(&mut self, server_pub_key_base64: &str, encrypted_content_base64: &str) -> Result<String, JsValue> {
        // 1. Decode Server Public Key
        let server_pub_bytes = general_purpose::STANDARD.decode(server_pub_key_base64)
            .map_err(|_| JsValue::from_str("Invalid Base64 Server Key"))?;
        
        let server_public = PublicKey::from_public_key_der(&server_pub_bytes)
            .map_err(|_| JsValue::from_str("Invalid Server Public Key Der"))?;

        // 2. ECDH: Compute Shared Secret
        let secret = self.secret_key.take().ok_or("Secret key already used or missing")?;
        let shared_secret = secret.diffie_hellman(&server_public);
        let shared_secret_bytes = shared_secret.raw_secret_bytes();

        // 3. HKDF: Derive AES Key
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret_bytes.as_slice());
        let mut okm = [0u8; 32];
        hkdf.expand(HKDF_INFO, &mut okm)
            .map_err(|_| JsValue::from_str("HKDF Failed"))?;
        
        let session_key = Key::<Aes256Gcm>::from_slice(&okm);
        let cipher = Aes256Gcm::new(session_key);

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
            aad: &[],
        };

        let plaintext = cipher.decrypt(nonce.into(), payload)
            .map_err(|_| JsValue::from_str("Decryption Failed"))?;

        String::from_utf8(plaintext)
            .map_err(|_| JsValue::from_str("Invalid UTF-8 Plaintext"))
    }
}
