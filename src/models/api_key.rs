use mongodb::bson::{oid::ObjectId, DateTime as BsonDateTime};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyDoc {
    #[serde(rename = "_id")]
    pub id: ObjectId,

    pub user_id: ObjectId,

    pub name: String,

    // auth
    pub key_hash: String,        // sha256(api_key_plain)
    pub key_ciphertext: Vec<u8>, // encrypt(api_key_plain)
    pub key_nonce: [u8; 12],

    // state
    pub active: bool,
    pub expires_at: Option<BsonDateTime>,

    // throttling/quota
    pub requests_per_minute: i32,
    pub requests_per_day: i64,

    // usage counters (UTC)
    pub minute_bucket: i64,        // unix_minute
    pub requests_used_minute: i32, // within minute_bucket
    pub usage_day: i32,            // yyyymmdd (UTC)
    pub requests_used_today: i64,  // within usage_day

    pub scopes: Vec<String>,

    pub created_at: BsonDateTime,
    pub last_used_at: BsonDateTime,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiKeyPublic {
    pub id: String,
    pub name: String,
    pub active: bool,
    pub scopes: Vec<String>,
    pub expires_at: Option<String>,
    pub requests_per_minute: i32,
    pub requests_per_day: i64,
}
