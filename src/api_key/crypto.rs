use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};

use crate::errors::AppError;

fn load_key() -> Result<[u8; 32], AppError> {
    let key_b64 = std::env::var("API_KEY_ENC_KEY_BASE64")
        .map_err(|_| AppError::Internal("missing API_KEY_ENC_KEY_BASE64".into()))?;

    let key_vec = general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|_| AppError::Internal("API_KEY_ENC_KEY_BASE64 is not valid base64".into()))?;

    if key_vec.len() != 32 {
        return Err(AppError::Internal(
            "API_KEY_ENC_KEY_BASE64 must decode to exactly 32 bytes".into(),
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_vec);
    Ok(key)
}

fn cipher() -> Result<Aes256Gcm, AppError> {
    let key = load_key()?;
    Aes256Gcm::new_from_slice(&key)
        .map_err(|_| AppError::Internal("failed to init Aes256Gcm".into()))
}

pub fn encrypt_api_key(plain: &str) -> Result<(Vec<u8>, [u8; 12]), AppError> {
    use rand::RngCore;

    let c = cipher()?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let ciphertext = c
        .encrypt(Nonce::from_slice(&nonce_bytes), plain.as_bytes())
        .map_err(|_| AppError::Internal("api key encrypt failed".into()))?;

    Ok((ciphertext, nonce_bytes))
}

pub fn decrypt_api_key(ciphertext: &[u8], nonce: &[u8]) -> Result<String, AppError> {
    if nonce.len() != 12 {
        return Err(AppError::Internal("api key nonce must be 12 bytes".into()));
    }

    let c = cipher()?;

    let plaintext = c
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| AppError::Unauthorized)?;

    String::from_utf8(plaintext)
        .map_err(|_| AppError::Internal("api key is not valid utf-8".into()))
}
