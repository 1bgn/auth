use crate::{
    auth::jwt::{make_token, new_access_claims, new_refresh_claims, sha256_hex},
    errors::AppError,
    models::refresh_token::RefreshTokenDoc,
    state::AppState,
};
use chrono::{Duration, Utc};
use mongodb::bson::{oid::ObjectId, DateTime as BsonDateTime};

#[derive(Debug, Clone)]
pub struct IssuedTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub refresh_doc_id: ObjectId,
}

pub async fn issue_tokens_and_store_refresh(
    state: &AppState,
    user_id: ObjectId,
) -> Result<IssuedTokens, AppError> {
    let access_claims = new_access_claims(user_id.to_hex(), state.cfg.jwt_access_ttl_seconds);
    let (refresh_claims, refresh_jti) =
        new_refresh_claims(user_id.to_hex(), state.cfg.jwt_refresh_ttl_seconds);

    let access_token = make_token(&access_claims)?;
    let refresh_token = make_token(&refresh_claims)?;

    let expires_at_millis =
        (Utc::now() + Duration::seconds(state.cfg.jwt_refresh_ttl_seconds)).timestamp_millis();

    let refresh_doc_id = ObjectId::new();
    let rt = RefreshTokenDoc {
        id: refresh_doc_id,
        user_id,
        jti: refresh_jti,
        token_hash: sha256_hex(&refresh_token),
        created_at: BsonDateTime::now(),
        expires_at: BsonDateTime::from_millis(expires_at_millis),
        revoked_at: None,
        replaced_by: None,
    };

    state.refresh_tokens.insert_one(rt).await?;

    Ok(IssuedTokens {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        refresh_doc_id,
    })
}
