use axum::Json;

use crate::api_key::extractor::ApiKeyUser;
#[utoipa::path(
    get,
    path = "/ping",
    responses((status = 200, description = "OK")),
    tag = "api",
      security(("apiKeyAuth" = [])),
)]
pub async fn ping(ApiKeyUser(user): ApiKeyUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "user_id": user.id.to_hex(),
        "email": user.email
    }))
}
