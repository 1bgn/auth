use ::serde::{Deserialize, Serialize};
use chrono::{serde, DateTime, Utc};
use mongodb::bson::oid::ObjectId;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDoc {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub name: String,
    pub email: String,

    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub api_key_hash: String,
    pub api_key_created_at: DateTime<Utc>,
    pub api_key_ciphertext: Vec<u8>,
    pub api_key_nonce: Vec<u8>,
}
#[derive(Debug, Clone, Serialize)]
pub struct UserPublic {
    pub id: String,
    pub email: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}
impl From<UserDoc> for UserPublic {
    fn from(value: UserDoc) -> Self {
        Self {
            id: value.id.to_hex(),
            email: value.email,
            name: value.name,
            created_at: value.created_at,
        }
    }
}
