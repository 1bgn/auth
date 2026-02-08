use axum::http::{Request, StatusCode};
use tower_governor::{key_extractor::KeyExtractor, GovernorError};

pub const API_KEY_HEADER: &str = "x-api-key";

#[derive(Clone, Debug)]
pub struct ApiKeyExtractor;

impl KeyExtractor for ApiKeyExtractor {
    type Key = String;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        let v = req
            .headers()
            .get(API_KEY_HEADER)
            .ok_or(GovernorError::Other {
                code: StatusCode::UNAUTHORIZED,
                msg: Some("missing x-api-key".to_string()),
                headers: None,
            })?;

        let s = v.to_str().map_err(|_| GovernorError::UnableToExtractKey)?;
        Ok(s.to_owned())
    }
}
