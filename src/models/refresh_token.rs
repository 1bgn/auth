use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenDoc {
    #[serde(rename = "_id")]
    pub id: ObjectId,

    pub user_id: ObjectId,

    // jti из JWT refresh
    pub jti: String,

    // sha256(refresh_token_string)
    pub token_hash: String,

    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,

    // null => активен
    pub revoked_at: Option<DateTime<Utc>>,
    pub replaced_by: Option<ObjectId>,
}
