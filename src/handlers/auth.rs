use axum::{extract::State, Json};
use chrono::{Duration, Utc};
use mongodb::{
    bson::{doc, oid::ObjectId},
    options::{FindOneAndUpdateOptions, ReturnDocument},
};
use rand::RngCore;
use std::sync::Arc;

use crate::{
    auth::{make_token, new_access_claims, new_refresh_claims, sha256_hex, AuthClaims},
    dto::auth::{
        LoginRequest, LoginResponse, RefreshRequest, RefreshResponse, RegisterRequest,
        RegisterResponse, RotateApiKeyResponse,
    },
    errors::AppError,
    models::{
        refresh_token::RefreshTokenDoc,
        user::{UserDoc, UserPublic},
    },
    password::{hash_password, verify_password},
    state::AppState,
};

fn generate_api_key() -> String {
    let mut bytes = [0u8; 32]; // 256-bit
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes) // 64 hex chars
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    let email = req.email.trim().to_lowercase();
    let name = req.name.trim().to_string();

    if email.is_empty() || name.is_empty() {
        return Err(AppError::Validation("email/name required".into()));
    }

    let exists = state.users.find_one(doc! { "email": &email }).await?;
    if exists.is_some() {
        return Err(AppError::Conflict("user already exists".into()));
    }

    let password_hash = hash_password(&req.password)?;

    // apiKey
    let api_key_plain = generate_api_key();
    let api_key_hash = sha256_hex(&api_key_plain);
    let (api_key_ciphertext, api_key_nonce) =
        crate::api_key_crypto::encrypt_api_key(&api_key_plain)?;
    // create user
    let user = UserDoc {
        id: ObjectId::new(),
        email,
        name,
        password_hash,
        created_at: Utc::now(),
        api_key_hash,
        api_key_created_at: Utc::now(),
        api_key_ciphertext,
        api_key_nonce,
    };

    state.users.insert_one(&user).await?;

    // tokens
    let access_claims = new_access_claims(user.id.to_hex(), 15 * 60);
    let (refresh_claims, refresh_jti) = new_refresh_claims(user.id.to_hex(), 30 * 24 * 60 * 60);

    let access_token = make_token(&access_claims)?;
    let refresh_token = make_token(&refresh_claims)?;

    // store refresh token (hashed)
    let rt = RefreshTokenDoc {
        id: ObjectId::new(),
        user_id: user.id,
        jti: refresh_jti,
        token_hash: sha256_hex(&refresh_token),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::days(30),
        revoked_at: None,
        replaced_by: None,
    };
    state.refresh_tokens.insert_one(rt).await?;

    Ok(Json(RegisterResponse {
        user: UserPublic::from(user),
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
    }))
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let email = req.email.trim().to_lowercase();

    let user = state
        .users
        .find_one(doc! { "email": &email })
        .await?
        .ok_or(AppError::Unauthorized)?;

    let ok = verify_password(&req.password, &user.password_hash)?;
    if !ok {
        return Err(AppError::Unauthorized);
    }

    let now = Utc::now();
    let ttl = Duration::seconds(state.cfg.jwt_ttl_seconds);
    let access_claims = new_access_claims(user.id.to_hex(), 15 * 60);
    let (refresh_claims, refresh_jti) = new_refresh_claims(user.id.to_hex(), 30 * 24 * 60 * 60);

    let access_token = make_token(&access_claims)?;
    let refresh_token = make_token(&refresh_claims)?;
    let doc_rt = RefreshTokenDoc {
        id: ObjectId::new(),
        user_id: user.id,
        jti: refresh_jti,
        token_hash: sha256_hex(&refresh_token),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::days(30),
        revoked_at: None,
        replaced_by: None,
    };
    state.refresh_tokens.insert_one(doc_rt).await?;
    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
    }))
}

pub async fn me(
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
) -> Result<Json<UserPublic>, AppError> {
    let user_id = ObjectId::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
    let user = state
        .users
        .find_one(doc! { "_id": user_id })
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(user.into()))
}

pub async fn refresh(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, AppError> {
    // 1) verify refresh jwt (signature + exp)
    let data = crate::auth::decode_token(&req.refresh_token)?;
    let claims = data.claims;

    if claims.typ != "refresh" {
        return Err(AppError::Unauthorized);
    }

    // 2) check in DB by token_hash and status
    let token_hash = sha256_hex(&req.refresh_token);
    let current = state
        .refresh_tokens
        .find_one(doc! { "token_hash": &token_hash })
        .await?
        .ok_or(AppError::Unauthorized)?;

    if current.revoked_at.is_some() || current.expires_at < Utc::now() {
        return Err(AppError::Unauthorized);
    }

    // 3) rotate: revoke old, create new
    let user_id = current.user_id;

    let access_claims = new_access_claims(user_id.to_hex(), 15 * 60);
    let (new_refresh_claims, new_jti) = new_refresh_claims(user_id.to_hex(), 30 * 24 * 60 * 60);

    let new_access = make_token(&access_claims)?;
    let new_refresh = make_token(&new_refresh_claims)?;

    let new_doc = RefreshTokenDoc {
        id: ObjectId::new(),
        user_id,
        jti: new_jti,
        token_hash: sha256_hex(&new_refresh),
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::days(30),
        revoked_at: None,
        replaced_by: None,
    };
    state.refresh_tokens.insert_one(&new_doc).await?;

    // revoke old
    state
        .refresh_tokens
        .update_one(
            doc! { "_id": current.id },
            doc! { "$set": { "revoked_at": Utc::now(), "replaced_by": new_doc.id } },
        )
        .await?;

    Ok(Json(RefreshResponse {
        access_token: new_access,
        refresh_token: new_refresh,
        token_type: "Bearer".into(),
    }))
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let token_hash = sha256_hex(&req.refresh_token);
    state
        .refresh_tokens
        .update_one(
            doc! { "token_hash": &token_hash },
            doc! { "$set": { "revoked_at": Utc::now() } },
        )
        .await?;

    Ok(Json(serde_json::json!({"status":"ok"})))
}

pub async fn rotate_api_key(
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
) -> Result<Json<RotateApiKeyResponse>, AppError> {
    if claims.typ != "access" {
        return Err(AppError::Unauthorized);
    }

    let user_id = ObjectId::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;

    let user: UserDoc = state
        .users
        .find_one(doc! { "_id": user_id })
        .await?
        .ok_or(AppError::NotFound)?;

    let api_key =
        crate::api_key_crypto::decrypt_api_key(&user.api_key_ciphertext, &user.api_key_nonce)?;

    Ok(Json(RotateApiKeyResponse { api_key }))
}
