use crate::response::api_response::ErrorResponse;
use axum::{
   http::StatusCode,
   response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
   #[error("invalid payload")]
   InvalidPayload,
   #[error("key not found")]
   KeyNotFound,
}

impl IntoResponse for SecurityError {
   fn into_response(self) -> Response {
      let status_code = match self {
        SecurityError::InvalidPayload => StatusCode::BAD_REQUEST,
        SecurityError::KeyNotFound => StatusCode::UNPROCESSABLE_ENTITY,
      };

      ErrorResponse::send(status_code.as_u16(), 0, Some(self.to_string()))
   }
}
