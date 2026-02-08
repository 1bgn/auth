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
        .route("/me", get(auth_handlers::me))
        .route("/api-key/rotate", post(auth_handlers::rotate_api_key));

    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(10)
            .key_extractor(ApiKeyExtractor)
            .use_headers()
            .finish()
            .unwrap(),
    );

    let api = Router::new()
        .route("/ping", get(api_handlers::ping))
        .route_layer(GovernorLayer::new(governor_conf));

    Router::new()
        .nest("/auth", auth)
        .nest("/api", api)
        .with_state(state)
}
