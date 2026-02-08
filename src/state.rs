use std::sync::Arc;

use mongodb::{
    options::{ClientOptions, IndexOptions},
    Client, Collection, IndexModel,
};

use crate::{
    config::Config,
    models::{refresh_token::RefreshTokenDoc, user::UserDoc},
};
#[derive(Clone)]
pub struct AppState {
    pub users: Collection<UserDoc>,
    pub cfg: Arc<Config>,
    pub refresh_tokens: Collection<RefreshTokenDoc>,
}
impl AppState {
    pub async fn new(cfg: &Config) -> mongodb::error::Result<Self> {
        let mut opts = ClientOptions::parse(&cfg.mongodb_uri).await?;
        opts.app_name = Some("b7am".to_string());
        let client = Client::with_options(opts)?;
        let db = client.database(&cfg.db_name);
        let users: Collection<UserDoc> = db.collection("users");
        let refresh_tokens: Collection<RefreshTokenDoc> = db.collection("refresh_tokens");
        let email_index = IndexModel::builder()
            .keys(mongodb::bson::doc! {"email":1})
            .options(IndexOptions::builder().unique(true).build())
            .build();
        let _ = users.create_index(email_index).await?;
        let hash_index = IndexModel::builder()
            .keys(mongodb::bson::doc! { "token_hash": 1 })
            .options(IndexOptions::builder().unique(true).build())
            .build();
        let _ = refresh_tokens.create_index(hash_index).await?;

        // jti unique
        let jti_index = IndexModel::builder()
            .keys(mongodb::bson::doc! { "jti": 1 })
            .options(IndexOptions::builder().unique(true).build())
            .build();
        let _ = refresh_tokens.create_index(jti_index).await?;
        Ok(Self {
            users,
            cfg: Arc::new(cfg.clone()),
            refresh_tokens,
        })
    }
}
