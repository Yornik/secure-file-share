//! Error type shared by every handler. `IntoResponse` turns it into the JSON
//! error object the frontend (and curl) sees; the detail behind an
//! `Internal` is logged here and kept out of the response, because an
//! internal message can quote SQL or a file path.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("no such share")]
    NotFound,
    #[error("share expired or burned")]
    Gone,
    #[error("the share exceeds the configured limit of {limit} bytes")]
    TooLarge { limit: u64 },
    #[error("{0}")]
    BadRequest(String),
    #[error("import failed: {0}")]
    Import(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_owned()),
            Self::NotFound => (StatusCode::NOT_FOUND, "no such share".to_owned()),
            Self::Gone => (StatusCode::GONE, "share expired or burned".to_owned()),
            Self::TooLarge { .. } => (StatusCode::PAYLOAD_TOO_LARGE, self.to_string()),
            Self::BadRequest(detail) => (StatusCode::BAD_REQUEST, detail.clone()),
            Self::Import(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            Self::Internal(detail) => {
                // Logged where it is raised, not here: the raiser knows the
                // request it belongs to.
                let _ = detail;
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_owned(),
                )
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        log::error!("database error: {error}");
        Self::Internal("database".to_owned())
    }
}

impl From<crate::frame::FrameError> for AppError {
    fn from(error: crate::frame::FrameError) -> Self {
        match error {
            crate::frame::FrameError::TooLarge(limit) => Self::TooLarge { limit },
            crate::frame::FrameError::Malformed(detail) => {
                Self::BadRequest(format!("malformed upload: {detail}"))
            }
            crate::frame::FrameError::Io(detail) => {
                log::error!("upload stream failed: {detail}");
                Self::Internal("upload stream".to_owned())
            }
        }
    }
}
