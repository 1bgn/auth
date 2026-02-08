use mongodb::bson::{oid::ObjectId, DateTime as BsonDateTime};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDoc {
    #[serde(rename = "_id")]
    pub id: ObjectId,

    pub email: String,
    pub name: String,

    pub password_hash: String,
    pub created_at: BsonDateTime,

    pub default_api_key_id: Option<ObjectId>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserPublic {
    pub id: String,
    pub email: String,
    pub name: String,
    pub created_at: String,
}

impl From<UserDoc> for UserPublic {
    fn from(u: UserDoc) -> Self {
        Self {
            id: u.id.to_hex(),
            email: u.email,
            name: u.name,
            created_at: bson_to_rfc3339(u.created_at),
        }
    }
}
fn bson_to_rfc3339(dt: BsonDateTime) -> String {
    // bson::DateTime хранит миллисекунды от epoch; можно перевести в chrono
    let ms = dt.timestamp_millis();
    let secs = ms / 1000;
    let nsec = ((ms % 1000) * 1_000_000) as u32;
    let chrono_dt = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, nsec)
        .unwrap_or_else(|| chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap());
    chrono_dt.to_rfc3339()
}
