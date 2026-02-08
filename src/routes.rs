// src/routes.rs
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

use crate::{
    handlers::{api as api_handlers, auth as auth_handlers},
    rate_limit::ApiKeyExtractor,
    state::AppState,
};

pub fn app_router(state: Arc<AppState>) -> Router {
    let auth = Router::new()
        .route("/register", post(auth_handlers::register))
        .route("/login", post(auth_handlers::login))
        .route("/refresh", post(auth_handlers::refresh))
        .route("/logout", post(auth_handlers::logout))
        .route("/api-key/rotate", post(auth_handlers::rotate_api_key))
        .route("/me", get(auth_handlers::me));

    // Rate limit per API key (x-api-key) only for /api/*
    // Как в custom_key_bearer: Arc<GovernorConfigBuilder...> + GovernorLayer { config }. [web:188]
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(10)
            .key_extractor(ApiKeyExtractor)
            .use_headers() // добавит x-ratelimit-* headers [web:188][web:156]
            .finish()
            .unwrap(),
    );

    let api = Router::new()
        .route("/ping", get(api_handlers::ping))
        // Лучше route_layer: сработает только если маршрут совпал (не ломает fallback/404). [web:233]
        .route_layer(GovernorLayer::new(governor_conf));

    Router::new()
        .nest("/auth", auth)
        .nest("/api", api)
        .with_state(state) // при nest роутеры должны иметь одинаковый state type [web:233]
}

