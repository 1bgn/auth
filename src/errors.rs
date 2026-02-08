use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Not found")]
    NotFound,

    #[error("Database error: {0}")]
    Db(String),

    #[error("JWT error")]
    Jwt,

    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Too many requests")]
    TooManyRequests,
}

impl From<mongodb::error::Error> for AppError {
    fn from(e: mongodb::error::Error) -> Self {
        AppError::Db(e.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            AppError::Validation(s) => (StatusCode::BAD_REQUEST, s.as_str()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::Conflict(s) => (StatusCode::CONFLICT, s.as_str()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found"),
            AppError::Db(_) => (StatusCode::INTERNAL_SERVER_ERROR, "database error"),
            AppError::Jwt => (StatusCode::BAD_REQUEST, "invalid token"),
            AppError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "too many requests"),
            AppError::Internal(s) => (StatusCode::INTERNAL_SERVER_ERROR, s.as_str()),
        };

        (status, Json(json!({ "error": msg }))).into_response()
    }
}
