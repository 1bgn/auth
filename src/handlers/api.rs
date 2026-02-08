use axum::Json;

use crate::api_key::extractor::ApiKeyUser;

pub async fn ping(ApiKeyUser(user): ApiKeyUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "user_id": user.id.to_hex(),
        "email": user.email
    }))
}
