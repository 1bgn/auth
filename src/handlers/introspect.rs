use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use mongodb::bson::{doc, DateTime as BsonDateTime};

use crate::auth::jwt::{decode_token, sha256_hex};
use crate::dto::auth::{IntrospectRequest, IntrospectResponse};
use crate::errors::AppError;
use crate::state::AppState;

#[utoipa::path(
    post,
    path = "/introspect",
    request_body = IntrospectRequest,
    responses((status = 200, description = "Token introspection result", body = IntrospectResponse)),
    tag = "auth"
)]
pub async fn introspect(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, AppError> {
    let token = req.token.trim();

    if token.is_empty() {
        return Ok(Json(IntrospectResponse {
            active: false,
            sub: None,
            token_type: None,
            scopes: None,
        }));
    }

    // 1) JWT path (looks like header.payload.signature)
    if token.matches('.').count() == 2 {
        if let Ok(data) = decode_token(token) {
            let claims = data.claims;

            // refresh: must exist in DB and not be revoked/expired
            if claims.typ == "refresh" {
                let token_hash = sha256_hex(token);

                let db_rt = state
                    .refresh_tokens
                    .find_one(doc! { "token_hash": &token_hash })
                    .await?;

                let active = db_rt.as_ref().is_some_and(|rt| {
                    rt.revoked_at.is_none() && rt.expires_at > BsonDateTime::now()
                });

                if active {
                    return Ok(Json(IntrospectResponse {
                        active: true,
                        sub: Some(claims.sub),
                        token_type: Some("refresh".to_string()),
                        scopes: None,
                    }));
                }

                // RFC7662 style: for inactive token return active=false (лучше без лишних полей)
                return Ok(Json(IntrospectResponse {
                    active: false,
                    sub: None,
                    token_type: None,
                    scopes: None,
                }));
            }

            // access: signature+exp already verified by decode_token()
            if claims.typ == "access" {
                return Ok(Json(IntrospectResponse {
                    active: true,
                    sub: Some(claims.sub),
                    token_type: Some("access".to_string()),
                    scopes: None,
                }));
            }

            // unknown typ but valid JWT
            return Ok(Json(IntrospectResponse {
                active: true,
                sub: Some(claims.sub),
                token_type: Some(claims.typ),
                scopes: None,
            }));
        }
    }

    // 2) API key path (plaintext api key)
    let key_hash = sha256_hex(token);

    let key = state
        .api_keys
        .find_one(doc! {
            "key_hash": &key_hash,
            "active": true,
            "$or": [
                { "expires_at": mongodb::bson::Bson::Null },
                { "expires_at": { "$exists": false } },
                { "expires_at": { "$gt": BsonDateTime::now() } }
            ]
        })
        .await?;

    if let Some(key) = key {
        return Ok(Json(IntrospectResponse {
            active: true,
            sub: Some(key.user_id.to_hex()),
            token_type: Some("api_key".to_string()),
            scopes: Some(key.scopes),
        }));
    }

    Ok(Json(IntrospectResponse {
        active: false,
        sub: None,
        token_type: None,
        scopes: None,
    }))
}

