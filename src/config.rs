#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: String,
    pub mongodb_uri: String,
    pub db_name: String,
    pub jwt_secret: String,
    pub jwt_ttl_seconds: i64,
}

impl Config {
    pub fn from_env() -> Self {
        let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
        let mongodb_uri = std::env::var("MONGODB_URI").expect("MONGODB_URI is required");
        let db_name = std::env::var("DB_NAME").unwrap_or_else(|_| "auth_db".to_string());
        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET is required");
        let jwt_ttl_seconds = std::env::var("JWT_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60 * 60 * 24);

        Self {
            bind_addr,
            mongodb_uri,
            db_name,
            jwt_secret,
            jwt_ttl_seconds,
        }
    }
}
