use chrono::Utc;
use mongodb::bson::{doc, oid::ObjectId, DateTime as BsonDateTime};

use crate::{
    api_key::{
        crypto::{decrypt_api_key, encrypt_api_key},
        generate::generate_api_key,
    },
    auth::{
        jwt::{decode_token, sha256_hex},
        tokens::{issue_tokens_and_store_refresh, IssuedTokens},
    },
    dto::auth::{LoginRequest, RefreshRequest, RegisterRequest},
    errors::AppError,
    models::{
        refresh_token::RefreshTokenDoc,
        user::{UserDoc, UserPublic},
    },
    password::{hash_password, verify_password},
    state::AppState,
};

pub struct RegisterOutput {
    pub user: UserPublic,
    pub api_key: String,
    pub tokens: IssuedTokens,
}

pub async fn register(state: &AppState, req: RegisterRequest) -> Result<RegisterOutput, AppError> {
    let email = req.email.trim().to_lowercase();
    let name = req.name.trim().to_string();

    if email.is_empty() || name.is_empty() {
        return Err(AppError::Validation("email/name required".into()));
    }

    if state
        .users
        .find_one(doc! { "email": &email })
        .await?
        .is_some()
    {
        return Err(AppError::Conflict("user already exists".into()));
    }

    let password_hash = hash_password(&req.password)?;

    let api_key_plain = generate_api_key();
    let api_key_hash = sha256_hex(&api_key_plain);

    let (ct, nonce) = encrypt_api_key(&api_key_plain)?;

    let user = UserDoc {
        id: ObjectId::new(),
        email,
        name,
        password_hash,
        created_at: BsonDateTime::now(),
        api_key_hash,
        api_key_ciphertext: ct,
        api_key_nonce: nonce.to_vec(),
        api_key_created_at: BsonDateTime::now(),
    };

    state.users.insert_one(&user).await?;

    let tokens = issue_tokens_and_store_refresh(state, user.id).await?;

    Ok(RegisterOutput {
        user: UserPublic::from(user),
        api_key: api_key_plain,
        tokens,
    })
}

pub async fn login(state: &AppState, req: LoginRequest) -> Result<IssuedTokens, AppError> {
    let email = req.email.trim().to_lowercase();

    let user = state
        .users
        .find_one(doc! { "email": &email })
        .await?
        .ok_or(AppError::Unauthorized)?;

    if !verify_password(&req.password, &user.password_hash)? {
        return Err(AppError::Unauthorized);
    }

    issue_tokens_and_store_refresh(state, user.id).await
}

pub async fn me(state: &AppState, user_id: ObjectId) -> Result<UserPublic, AppError> {
    let user = state
        .users
        .find_one(doc! { "_id": user_id })
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(user.into())
}

pub async fn refresh(state: &AppState, req: RefreshRequest) -> Result<IssuedTokens, AppError> {
    let data = decode_token(&req.refresh_token)?;
    let claims = data.claims;

    if claims.typ != "refresh" {
        return Err(AppError::Unauthorized);
    }

    let token_hash = sha256_hex(&req.refresh_token);

    let current = state
        .refresh_tokens
        .find_one(doc! { "token_hash": &token_hash })
        .await?
        .ok_or(AppError::Unauthorized)?;

    if current.revoked_at.is_some() || current.expires_at < BsonDateTime::now() {
        return Err(AppError::Unauthorized);
    }

    // issue new tokens + store new refresh doc
    let user_id = current.user_id;
    let new_tokens = issue_tokens_and_store_refresh(state, user_id).await?;

    // mark old refresh revoked
    let _ = state
        .refresh_tokens
        .update_one(
            doc! { "_id": current.id },
            doc! { "$set": { "revoked_at": BsonDateTime::now() } },
        )
        .await?;

    Ok(new_tokens)
}

pub async fn logout(state: &AppState, req: RefreshRequest) -> Result<(), AppError> {
    let token_hash = sha256_hex(&req.refresh_token);

    let _ = state
        .refresh_tokens
        .update_one(
            doc! { "token_hash": token_hash },
            doc! { "$set": { "revoked_at": BsonDateTime::now() } },
        )
        .await?;

    Ok(())
}

// Variant 2: "rotate" meaning reveal existing apiKey (stored encrypted)
pub async fn reveal_api_key(state: &AppState, user_id: ObjectId) -> Result<String, AppError> {
    let user = state
        .users
        .find_one(doc! { "_id": user_id })
        .await?
        .ok_or(AppError::NotFound)?;

    let api_key = decrypt_api_key(&user.api_key_ciphertext, &user.api_key_nonce)?;
    Ok(api_key)
}
