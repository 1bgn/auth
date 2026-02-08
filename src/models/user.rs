use mongodb::bson::{oid::ObjectId, DateTime as BsonDateTime};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDoc {
    #[serde(rename = "_id")]
    pub id: ObjectId,

    pub email: String,
    pub name: String,

    pub password_hash: String,

    pub created_at: BsonDateTime,

    // API key (variant 2): hash for verification + ciphertext for reveal
    pub api_key_hash: String,
    pub api_key_ciphertext: Vec<u8>,
    pub api_key_nonce: Vec<u8>,
    pub api_key_created_at: BsonDateTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserPublic {
    pub id: String,
    pub email: String,
    pub name: String,
    pub created_at: BsonDateTime,
}

impl From<UserDoc> for UserPublic {
    fn from(u: UserDoc) -> Self {
        Self {
            id: u.id.to_hex(),
            email: u.email,
            name: u.name,
            created_at: u.created_at,
        }
    }
}
