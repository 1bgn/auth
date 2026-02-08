#[derive(Clone, Debug)]
pub struct Config {
    pub mongodb_uri: String,
    pub db_name: String,

    pub jwt_secret: String,
    pub jwt_access_ttl_seconds: i64,
    pub jwt_refresh_ttl_seconds: i64,
}

impl Config {
    pub fn from_env() -> Self {
        let mongodb_uri = std::env::var("MONGODB_URI").expect("MONGODB_URI is required");
        let db_name = std::env::var("DB_NAME").unwrap_or_else(|_| "auth_db".to_string());

        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET is required");

        let jwt_access_ttl_seconds = std::env::var("JWT_ACCESS_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(15 * 60);

        let jwt_refresh_ttl_seconds = std::env::var("JWT_REFRESH_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30 * 24 * 60 * 60);

        Self {
            mongodb_uri,
            db_name,
            jwt_secret,
            jwt_access_ttl_seconds,
            jwt_refresh_ttl_seconds,
        }
    }
}
