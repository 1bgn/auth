use crate::{rate_limit::ApiKeyExtractor, state::AppState};
use axum::Router;
use std::sync::Arc;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::{Components, OpenApi};
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_swagger_ui::SwaggerUi;

pub fn app_router(state: Arc<AppState>) -> Router {
    // auth: каждый handler добавляем отдельно
    let auth = OpenApiRouter::new()
        .routes(routes!(crate::handlers::auth::register))
        .routes(routes!(crate::handlers::auth::login))
        .routes(routes!(crate::handlers::auth::refresh))
        .routes(routes!(crate::handlers::introspect::introspect))
        .routes(routes!(crate::handlers::auth::logout))
        .routes(routes!(crate::handlers::auth::me))
        .routes(routes!(crate::handlers::auth::rotate_api_key));

    // api
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(10)
            .key_extractor(ApiKeyExtractor)
            .use_headers()
            .finish()
            .unwrap(),
    );

    let api = OpenApiRouter::new()
        .routes(routes!(crate::handlers::api::ping))
        .route_layer(GovernorLayer::new(governor_conf));

    let root = OpenApiRouter::new()
        .nest("/auth", auth)
        .nest("/api", api)
        .with_state(state);

    let (router, mut openapi): (Router, OpenApi) = root.split_for_parts();
    let mut components = openapi.components.clone().unwrap_or_else(Components::new);

    // Bearer auth
    components.add_security_scheme(
        "bearerAuth",
        SecurityScheme::Http(
            HttpBuilder::new()
                .scheme(HttpAuthScheme::Bearer)
                .bearer_format("JWT")
                .build(),
        ),
    );

    // API key in header x-api-key
    components.add_security_scheme(
        "apiKeyAuth",
        SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("x-api-key"))),
    );

    openapi.components = Some(components);
    router.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", openapi))
}
