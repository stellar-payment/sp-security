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
   #[error("security error: {0}")]
   GenericError(String),
}

impl IntoResponse for SecurityError {
   fn into_response(self) -> Response {
      let status_code = match self {
         SecurityError::InvalidPayload => StatusCode::BAD_REQUEST,
         SecurityError::KeyNotFound => StatusCode::UNPROCESSABLE_ENTITY,
         SecurityError::GenericError(_) => StatusCode::INTERNAL_SERVER_ERROR,
      };

      match self {
         Self::GenericError(_) => ErrorResponse::send(
            status_code.as_u16(),
            0,
            Some("oops, something when wrong".to_string()),
         ),
         _ => ErrorResponse::send(status_code.as_u16(), 0, Some(self.to_string())),
      }
   }
}
