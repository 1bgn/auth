use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};

use crate::errors::AppError;

fn cipher() -> Result<Aes256Gcm, AppError> {
    let key_b64 = std::env::var("API_KEY_ENC_KEY_BASE64")
        .map_err(|_| AppError::Internal("missing API_KEY_ENC_KEY_BASE64".into()))?;
    let key = general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|_| AppError::Internal("API_KEY_ENC_KEY_BASE64 is not valid base64".into()))?;

    if key.len() != 32 {
        return Err(AppError::Internal(
            "API_KEY_ENC_KEY_BASE64 must decode to 32 bytes".into(),
        ));
    }

    Ok(Aes256Gcm::new_from_slice(&key)
        .map_err(|_| AppError::Internal("bad encryption key".into()))?)
}

pub fn encrypt_api_key(plain: &str) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    use rand::RngCore;

    let c = cipher()?;

    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let ct = c
        .encrypt(Nonce::from_slice(&nonce), plain.as_bytes())
        .map_err(|_| AppError::Internal("api key encrypt failed".into()))?;

    Ok((ct, nonce.to_vec()))
}

pub fn decrypt_api_key(ciphertext: &[u8], nonce: &[u8]) -> Result<String, AppError> {
    let c = cipher()?;

    if nonce.len() != 12 {
        return Err(AppError::Internal("bad api key nonce length".into()));
    }

    let pt = c
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| AppError::Unauthorized)?; // можно Internal, но лучше не палить детали

    String::from_utf8(pt)
        .map_err(|_| AppError::Internal("api key decrypt produced invalid utf8".into()))
}
