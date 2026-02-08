use crate::errors::AppError;
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::rngs::OsRng;

pub fn hash_password(plain: &str) -> Result<String, AppError> {
    if plain.len() < 8 {
        return Err(AppError::Validation(
            "password must be at least 8 chairs".into(),
        ));
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("argon2 hash: {e}")))?
        .to_string();
    Ok(hash)
}
pub fn verify_password(plain: &str, hash: &str) -> Result<bool, AppError> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| AppError::Internal(format!("bad password hash: {e}")))?;
    Ok(Argon2::default()
        .verify_password(plain.as_bytes(), &parsed)
        .is_ok())
}
