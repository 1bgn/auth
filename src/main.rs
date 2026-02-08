// src/main.rs
mod api_key;
mod auth;
mod config;
mod dto;
mod errors;
mod handlers;
mod models;
mod password;
mod rate_limit;
mod routes;
mod services;
mod state;

use crate::{config::Config, routes::app_router, state::AppState};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "axum_mongo_auth=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg = Config::from_env();
    let state = Arc::new(AppState::new(cfg).await.expect("init state"));

    let app = app_router(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let listener =
        TcpListener::bind(&std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into()))
            .await
            .unwrap();

    axum::serve(listener, app).await.unwrap();
}
