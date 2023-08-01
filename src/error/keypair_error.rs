use crate::response::api_response::ErrorResponse;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeypairError {
    #[error("invalid keypair")]
    KeypairInvalid,
    #[error("keypair not found")]
    KeypairNotFound,
    #[error("keypair error: {0}")]
    KeypairYabai(String),
    #[error("failed to create keypair: {0}")]
    KeypairCreationError(String),
}

impl IntoResponse for KeypairError {
    fn into_response(self) -> Response {
        let status_code = match self {
            KeypairError::KeypairInvalid => StatusCode::UNPROCESSABLE_ENTITY,
            KeypairError::KeypairNotFound => StatusCode::NOT_FOUND,
            KeypairError::KeypairYabai(_) => StatusCode::INTERNAL_SERVER_ERROR,
            KeypairError::KeypairCreationError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        ErrorResponse::send(status_code.as_u16(), 0, Some(self.to_string()))
    }
}