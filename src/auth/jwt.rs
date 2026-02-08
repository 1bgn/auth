use axum::{extract::FromRequestParts, http::request::Parts, RequestPartsExt};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;
use uuid::Uuid;

use crate::errors::AppError;

static JWT_SECRET: LazyLock<String> =
    LazyLock::new(|| std::env::var("JWT_SECRET").expect("JWT_SECRET must be set"));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,

    pub typ: String,         // "access" | "refresh"
    pub jti: Option<String>, // refresh only
}

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
        typ: "access".into(),
        jti: None,
    }
}

pub fn new_refresh_claims(user_id_hex: String, ttl_seconds: i64) -> (Claims, String) {
    let now = Utc::now();
    let jti = Uuid::new_v4().to_string();

    (
        Claims {
            sub: user_id_hex,
            iat: now.timestamp() as usize,
            exp: (now + Duration::seconds(ttl_seconds)).timestamp() as usize,
            typ: "refresh".into(),
            jti: Some(jti.clone()),
        },
        jti,
    )
}

pub fn make_token(claims: &Claims) -> Result<String, AppError> {
    let keys = Keys::global();
    encode(&Header::default(), claims, &keys.encoding).map_err(|_| AppError::Jwt)
}

pub fn decode_token(token: &str) -> Result<TokenData<Claims>, AppError> {
    let keys = Keys::global();
    decode::<Claims>(token, &keys.decoding, &Validation::default()).map_err(|_| AppError::Jwt)
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

        let data = decode_token(bearer.token())?;
        Ok(Self(data.claims))
    }
}
