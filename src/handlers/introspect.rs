use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use mongodb::bson::doc;
// ...
use crate::auth::jwt::{decode_token, sha256_hex};

use crate::dto::auth::{IntrospectRequest, IntrospectResponse};
use crate::errors::AppError;
use crate::state::AppState;

#[utoipa::path(
    post,
    path = "/auth/introspect",
    request_body = IntrospectRequest,
    responses(
        (status = 200, description = "Token introspection result", body = IntrospectResponse)
    ),
    tag = "auth"
)]
pub async fn introspect(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, AppError> {
    let token = req.token.trim();

    // 1) Попробуем как JWT (3 части, разделённые точками)
    if token.split('.').count() == 3 {
        if let Ok(data) = decode_token(token) {
            let claims = data.claims;

            let token_type = match claims.typ.as_str() {
                "access" => "access",
                "refresh" => "refresh",
                other => other,
            };

            return Ok(Json(IntrospectResponse {
                active: true,
                sub: Some(claims.sub),
                token_type: Some(token_type.to_string()),
            }));
        }
    }

    // 2) Иначе считаем, что это api_key
    let api_key_hash = sha256_hex(token);
    let user = state
        .users
        .find_one(doc! { "api_key_hash": &api_key_hash })
        .await?;

    if let Some(user) = user {
        Ok(Json(IntrospectResponse {
            active: true,
            sub: Some(user.id.to_hex()),
            token_type: Some("api_key".to_string()),
        }))
    } else {
        Ok(Json(IntrospectResponse {
            active: false,
            sub: None,
            token_type: None,
        }))
    }
}
