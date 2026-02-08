use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub name: String,
    pub password: String,
}
#[derive(Deserialize, Debug)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user: crate::models::user::UserPublic,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
}
#[derive(Debug, Deserialize)]
pub struct RotateApiKeyRequest {
    // можно добавить подтверждение паролем/refresh-token, но минимум — пустой body
}

#[derive(Debug, Serialize)]
pub struct RotateApiKeyResponse {
    pub api_key: String,
}
#[derive(Deserialize, Debug)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Serialize, Debug)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
}

#[derive(Serialize, Debug)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
}
