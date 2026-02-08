use mongodb::bson::{oid::ObjectId, DateTime as BsonDateTime};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenDoc {
    #[serde(rename = "_id")]
    pub id: ObjectId,

    pub user_id: ObjectId,
    pub jti: String,

    pub token_hash: String,

    pub created_at: BsonDateTime,
    pub expires_at: BsonDateTime,

    pub revoked_at: Option<BsonDateTime>,
    pub replaced_by: Option<ObjectId>,
}
