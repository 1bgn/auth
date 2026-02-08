use crate::{errors::AppError, models::jwt::Claims};
use axum::RequestPartsExt;
use axum::{extract::FromRequestParts, http::request::Parts};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use chrono::Duration;
use chrono::Utc;
use jsonwebtoken::{decode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;
use uuid::Uuid;
pub fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}
pub fn new_access_claims(user_id_hex: String, ttl_seconds: i64) -> Claims {
    let now = Utc::now();
    Claims {
        sub: user_id_hex,
        iat: now.timestamp() as usize,
        exp: (now + Duration::seconds(ttl_seconds)).timestamp() as usize,
        jti: None,
        typ: "access".into(),
    }
}
pub fn new_refresh_claims(user_id_hex: String, ttl_seconds: i64) -> (Claims, String) {
    let now = Utc::now();
    let jti = Uuid::new_v4().to_string();
    let claims = Claims {
        sub: user_id_hex,
        iat: now.timestamp() as usize,
        exp: (now + Duration::seconds(ttl_seconds)).timestamp() as usize,
        jti: Some(jti.clone()),
        typ: "access".into(),
    };
    return (claims, jti);
}
static JWT_SECRET: LazyLock<String> =
    LazyLock::new(|| std::env::var("JWT_SECRET").expect("JWT_SECRET must be set"));
#[derive(Clone)]
pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}
impl Keys {
    pub fn global() -> Self {
        let secret = JWT_SECRET.as_bytes();
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}
pub fn decode_token(token: &str) -> Result<TokenData<Claims>, AppError> {
    let keys = Keys::global();
    decode::<Claims>(token, &keys.decoding, &Validation::default()).map_err(|_| AppError::Jwt)
}
pub fn make_token(claims: &Claims) -> Result<String, AppError> {
    let keys = Keys::global();
    jsonwebtoken::encode(&Header::default(), claims, &keys.encoding).map_err(|_| AppError::Jwt)
}
#[derive(Debug, Clone)]
pub struct AuthClaims(pub Claims);
impl<S> FromRequestParts<S> for AuthClaims
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AppError::Unauthorized)?;

        let keys = Keys::global();
        let data = decode::<Claims>(bearer.token(), &keys.decoding, &Validation::default())
            .map_err(|_| AppError::Jwt)?;

        Ok(Self(data.claims))
    }
}
