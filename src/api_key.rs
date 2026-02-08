use axum::{
    extract::{FromRequestParts, State},
    http::request::Parts,
};
use mongodb::bson::doc;
use std::sync::Arc;

use crate::{auth::sha256_hex, errors::AppError, models::user::UserDoc, state::AppState};

pub const API_KEY_HEADER: &str = "x-api-key";

#[derive(Clone, Debug)]
pub struct ApiKeyUser(pub UserDoc);

impl FromRequestParts<Arc<AppState>> for ApiKeyUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let v = parts
            .headers
            .get(API_KEY_HEADER)
            .ok_or(AppError::Unauthorized)?;
        let api_key = v.to_str().map_err(|_| AppError::Unauthorized)?;

        let api_key_hash = sha256_hex(api_key);
        let user = state
            .users
            .find_one(doc! { "api_key_hash": api_key_hash })
            .await?
            .ok_or(AppError::Unauthorized)?;

        Ok(Self(user))
    }
}
