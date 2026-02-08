use axum::{extract::FromRequestParts, http::request::Parts};
use mongodb::{
    bson::{doc, oid::ObjectId, DateTime as BsonDateTime, Document},
    options::{FindOneAndUpdateOptions, ReturnDocument},
};
use std::sync::Arc;

use crate::{
    auth::jwt::sha256_hex,
    errors::AppError,
    models::{api_key::ApiKeyDoc, user::UserDoc},
    state::AppState,
};

pub const API_KEY_HEADER: &str = "x-api-key";

#[derive(Clone, Debug)]
pub struct ApiKeyUser(pub UserDoc);

fn utc_day_yyyymmdd() -> i32 {
    chrono::Utc::now()
        .format("%Y%m%d")
        .to_string()
        .parse()
        .unwrap()
}

fn utc_minute_bucket() -> i64 {
    chrono::Utc::now().timestamp() / 60
}

async fn consume_quota(state: &AppState, key_hash: &str) -> Result<ApiKeyDoc, AppError> {
    let now = BsonDateTime::now();
    let day = utc_day_yyyymmdd();
    let minute = utc_minute_bucket();

    // фильтр: ключ активен, не истёк, и есть квота по минуте/дню (либо новый бакет/день)
    let filter = doc! {
        "key_hash": key_hash,
        "active": true,
        "$and": [
            { "$or": [
                { "expires_at": mongodb::bson::Bson::Null },
                { "expires_at": { "$exists": false } },
                { "expires_at": { "$gt": now } },
            ]},
            { "$or": [
                { "minute_bucket": { "$ne": minute } },
                { "$expr": { "$lt": ["$requests_used_minute", "$requests_per_minute"] } },
            ]},
            { "$or": [
                { "usage_day": { "$ne": day } },
                { "$expr": { "$lt": ["$requests_used_today", "$requests_per_day"] } },
            ]},
        ],
    };

    // update pipeline: при смене окна/дня сбросить счетчики, затем +1
    let update: Vec<Document> = vec![
        doc! { "$set": {
            "last_used_at": now,

            "minute_bucket": { "$cond": [ { "$ne": ["$minute_bucket", minute] }, minute, "$minute_bucket" ] },
            "requests_used_minute": { "$cond": [ { "$ne": ["$minute_bucket", minute] }, 0i32, "$requests_used_minute" ] },

            "usage_day": { "$cond": [ { "$ne": ["$usage_day", day] }, day, "$usage_day" ] },
            "requests_used_today": { "$cond": [ { "$ne": ["$usage_day", day] }, 0i64, "$requests_used_today" ] },
        }},
        doc! { "$set": {
            "requests_used_minute": { "$add": ["$requests_used_minute", 1i32] },
            "requests_used_today": { "$add": ["$requests_used_today", 1i64] },
        }},
    ];

    let updated = state.api_keys.find_one_and_update(filter, update).await?;

    if let Some(k) = updated {
        return Ok(k);
    }

    // дифференцируем: ключ не найден/не активен (401) или квота выбита (429)
    let exists_active = state
        .api_keys
        .find_one(doc! {
            "key_hash": key_hash,
            "active": true,
            "$or": [
                { "expires_at": mongodb::bson::Bson::Null },
                { "expires_at": { "$exists": false } },
                { "expires_at": { "$gt": now } }
            ]
        })
        .await?;

    if exists_active.is_some() {
        Err(AppError::TooManyRequests)
    } else {
        Err(AppError::Unauthorized)
    }
}

impl FromRequestParts<Arc<AppState>> for ApiKeyUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let v = parts
            .headers
            .get(API_KEY_HEADER)
            .ok_or(AppError::Unauthorized)?;
        let api_key = v.to_str().map_err(|_| AppError::Unauthorized)?;
        let key_hash = sha256_hex(api_key);

        let key_doc = consume_quota(state.as_ref(), &key_hash).await?;

        let user = state
            .users
            .find_one(doc! { "_id": key_doc.user_id })
            .await?
            .ok_or(AppError::Unauthorized)?;

        Ok(Self(user))
    }
}
