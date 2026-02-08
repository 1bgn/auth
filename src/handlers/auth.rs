use axum::{extract::State, Json};
use mongodb::bson::oid::ObjectId;
use std::sync::Arc;

use crate::{
    auth::jwt::AuthClaims,
    dto::auth::{
        LoginRequest, LoginResponse, RefreshRequest, RefreshResponse, RegisterRequest,
        RegisterResponse, RotateApiKeyResponse,
    },
    errors::AppError,
    services::auth_service,
    state::AppState,
};

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    let out = auth_service::register(state.as_ref(), req).await?;

    Ok(Json(RegisterResponse {
        user: out.user,
        api_key: out.api_key,
        access_token: out.tokens.access_token,
        refresh_token: out.tokens.refresh_token,
        token_type: out.tokens.token_type,
    }))
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let tokens = auth_service::login(state.as_ref(), req).await?;

    Ok(Json(LoginResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: tokens.token_type,
    }))
}

pub async fn me(
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
) -> Result<Json<crate::models::user::UserPublic>, AppError> {
    if claims.typ != "access" {
        return Err(AppError::Unauthorized);
    }

    let user_id = ObjectId::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
    let me = auth_service::me(state.as_ref(), user_id).await?;
    Ok(Json(me))
}

pub async fn refresh(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, AppError> {
    let tokens = auth_service::refresh(state.as_ref(), req).await?;

    Ok(Json(RefreshResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: tokens.token_type,
    }))
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth_service::logout(state.as_ref(), req).await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

pub async fn rotate_api_key(
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
) -> Result<Json<RotateApiKeyResponse>, AppError> {
    if claims.typ != "access" {
        return Err(AppError::Unauthorized);
    }

    let user_id = ObjectId::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
    let api_key = auth_service::reveal_api_key(state.as_ref(), user_id).await?;

    Ok(Json(RotateApiKeyResponse { api_key }))
}
