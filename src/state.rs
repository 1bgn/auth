use crate::{
    config::Config,
    models::{refresh_token::RefreshTokenDoc, user::UserDoc},
};
use mongodb::{
    options::{ClientOptions, IndexOptions},
    Client, Collection, IndexModel,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub users: Collection<UserDoc>,
    pub refresh_tokens: Collection<RefreshTokenDoc>,
}

impl AppState {
    pub async fn new(cfg: Config) -> mongodb::error::Result<Self> {
        let mut opts = ClientOptions::parse(&cfg.mongodb_uri).await?;
        opts.app_name = Some("axum-mongo-auth".to_string());

        let client = Client::with_options(opts)?;
        let db = client.database(&cfg.db_name);

        let users: Collection<UserDoc> = db.collection("users");
        let refresh_tokens: Collection<RefreshTokenDoc> = db.collection("refresh_tokens");

        // unique email
        let email_index = IndexModel::builder()
            .keys(mongodb::bson::doc! { "email": 1 })
            .options(IndexOptions::builder().unique(true).build())
            .build();
        let _ = users.create_index(email_index).await?;

        // unique refresh token hash
        let token_hash_index = IndexModel::builder()
            .keys(mongodb::bson::doc! { "token_hash": 1 })
            .options(IndexOptions::builder().unique(true).build())
            .build();
        let _ = refresh_tokens.create_index(token_hash_index).await?;

        // unique jti
        let jti_index = IndexModel::builder()
            .keys(mongodb::bson::doc! { "jti": 1 })
            .options(IndexOptions::builder().unique(true).build())
            .build();
        let _ = refresh_tokens.create_index(jti_index).await?;

        Ok(Self {
            cfg: Arc::new(cfg),
            users,
            refresh_tokens,
        })
    }
}
