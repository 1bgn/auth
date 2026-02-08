use bson::{spec::BinarySubtype, Binary};
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
        api_key::ApiKeyDoc,
        user::{UserDoc, UserPublic},
    },
    password::{hash_password, verify_password},
    state::AppState,
};

pub struct RegisterOutput {
    pub user: UserPublic,
    pub api_key: String, // plain (показываем только один раз)
    pub tokens: IssuedTokens,
}

fn normalize_email(s: &str) -> String {
    s.trim().to_lowercase()
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), AppError> {
    if value.trim().is_empty() {
        return Err(AppError::Validation(format!("{field} is required")));
    }
    Ok(())
}

pub async fn register(state: &AppState, req: RegisterRequest) -> Result<RegisterOutput, AppError> {
    let email = normalize_email(&req.email);
    let name = req.name.trim().to_string();

    require_non_empty(&email, "email")?;
    require_non_empty(&name, "name")?;
    require_non_empty(&req.password, "password")?;

    if state
        .users
        .find_one(doc! { "email": &email })
        .await?
        .is_some()
    {
        return Err(AppError::Conflict("user already exists".into()));
    }

    let password_hash = hash_password(&req.password)?;

    let user = UserDoc {
        id: ObjectId::new(),
        email,
        name,
        password_hash,
        created_at: BsonDateTime::now(),
        default_api_key_id: None,
    };

    state.users.insert_one(&user).await?;

    // Create default API key (stored in api_keys collection)
    let api_key_plain = generate_api_key();

    // In case of extremely rare sha collision / unique index conflict, retry a few times.
    let mut inserted_key: Option<ApiKeyDoc> = None;
    for attempt in 0..5 {
        let key_hash = sha256_hex(&api_key_plain);
        let (ct, nonce) = encrypt_api_key(&api_key_plain)?;

        let key_doc = ApiKeyDoc {
            id: ObjectId::new(),
            user_id: user.id,
            name: "Default".into(),
            key_hash,
            key_ciphertext: ct,
            key_nonce: nonce,

            active: true,
            expires_at: None,

            // defaults; можно вынести в config
            requests_per_minute: 60,
            requests_per_day: 10_000,

            // counters initialized to 0
            minute_bucket: 0,
            requests_used_minute: 0,
            usage_day: 0,
            requests_used_today: 0,

            scopes: vec!["api".into()],

            created_at: BsonDateTime::now(),
            last_used_at: BsonDateTime::now(),
        };

        match state.api_keys.insert_one(&key_doc).await {
            Ok(_) => {
                inserted_key = Some(key_doc);
                break;
            }
            Err(e) => {
                if attempt == 4 {
                    return Err(e.into());
                }
            }
        }
    }

    let key_doc =
        inserted_key.ok_or_else(|| AppError::Internal("failed to create api key".into()))?;

    // Set user's default api key id
    state
        .users
        .update_one(
            doc! { "_id": user.id },
            doc! { "$set": { "default_api_key_id": key_doc.id } },
        )
        .await?;

    let tokens = issue_tokens_and_store_refresh(state, user.id).await?;

    Ok(RegisterOutput {
        user: UserPublic::from(user),
        api_key: api_key_plain,
        tokens,
    })
}

pub async fn login(state: &AppState, req: LoginRequest) -> Result<IssuedTokens, AppError> {
    let email = normalize_email(&req.email);
    require_non_empty(&email, "email")?;
    require_non_empty(&req.password, "password")?;

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
        .ok_or(AppError::Unauthorized)?;

    Ok(UserPublic::from(user))
}

/// Refresh rotation:
/// - If refresh token doc already revoked => treat as reuse, revoke all active refresh tokens for that user.
/// - Otherwise issue new tokens, revoke old, set replaced_by=new_refresh_doc_id.
pub async fn refresh(state: &AppState, req: RefreshRequest) -> Result<IssuedTokens, AppError> {
    require_non_empty(&req.refresh_token, "refresh_token")?;

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

    // Optional hard check that JWT sub matches DB user_id
    let sub_oid = ObjectId::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
    if sub_oid != current.user_id {
        return Err(AppError::Unauthorized);
    }

    if current.expires_at < BsonDateTime::now() {
        return Err(AppError::Unauthorized);
    }

    // reuse detection
    if current.revoked_at.is_some() {
        // revoke all non-revoked refresh tokens for this user
        let _ = state
            .refresh_tokens
            .update_many(
                doc! { "user_id": current.user_id, "revoked_at": mongodb::bson::Bson::Null },
                doc! { "$set": { "revoked_at": BsonDateTime::now() } },
            )
            .await?;
        return Err(AppError::Unauthorized);
    }

    // issue new tokens (and insert new refresh doc)
    let new_tokens = issue_tokens_and_store_refresh(state, current.user_id).await?;

    // revoke old + replaced_by
    state
        .refresh_tokens
        .update_one(
            doc! { "_id": current.id },
            doc! { "$set": { "revoked_at": BsonDateTime::now(), "replaced_by": new_tokens.refresh_doc_id } },
        )
        .await?;

    Ok(new_tokens)
}

/// Logout: revoke provided refresh token (idempotent).
pub async fn logout(state: &AppState, req: RefreshRequest) -> Result<(), AppError> {
    require_non_empty(&req.refresh_token, "refresh_token")?;
    let token_hash = sha256_hex(&req.refresh_token);

    // Don't leak whether token exists; treat missing as ok.
    let _ = state
        .refresh_tokens
        .update_one(
            doc! { "token_hash": &token_hash, "revoked_at": mongodb::bson::Bson::Null },
            doc! { "$set": { "revoked_at": BsonDateTime::now() } },
        )
        .await?;

    Ok(())
}

/// Returns plaintext of the user's default API key (decrypt from api_keys collection).
pub async fn reveal_api_key(state: &AppState, user_id: ObjectId) -> Result<String, AppError> {
    let user = state
        .users
        .find_one(doc! { "_id": user_id })
        .await?
        .ok_or(AppError::Unauthorized)?;

    let key_id = user.default_api_key_id.ok_or(AppError::NotFound)?;

    let key = state
        .api_keys
        .find_one(doc! { "_id": key_id, "user_id": user_id, "active": true })
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(decrypt_api_key(&key.key_ciphertext, &key.key_nonce)?)
}

/// Rotates the default API key for user and returns new plaintext key.
/// Old key becomes unusable because `key_hash` changes (unique index should exist).
pub async fn rotate_default_api_key(
    state: &AppState,
    user_id: ObjectId,
) -> Result<String, AppError> {
    let user = state
        .users
        .find_one(doc! { "_id": user_id })
        .await?
        .ok_or(AppError::Unauthorized)?;

    let key_id = user.default_api_key_id.ok_or(AppError::NotFound)?;

    // generate + update
    for _ in 0..5 {
        let api_key_plain = generate_api_key();
        let key_hash = sha256_hex(&api_key_plain);
        let (ct, nonce) = encrypt_api_key(&api_key_plain)?;

        let upd = doc! {
            "$set": {
                "key_hash": key_hash,
                "key_ciphertext": Binary { subtype: BinarySubtype::Generic, bytes: ct },
                "key_nonce": Binary { subtype: BinarySubtype::Generic, bytes: nonce.to_vec() },
                "last_used_at": BsonDateTime::now(),
                "active": true,
            }
        };

        let res = state
            .api_keys
            .update_one(doc! { "_id": key_id, "user_id": user_id }, upd)
            .await?;

        if res.matched_count == 1 {
            return Ok(api_key_plain);
        }
    }

    Err(AppError::Internal("failed to rotate api key".into()))
}
