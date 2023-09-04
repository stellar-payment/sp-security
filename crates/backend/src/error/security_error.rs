use axum::response::{IntoResponse, Response};
use axum::http::StatusCode;
use corelib::security_error;
use crate::response::api_response::ErrorResponse;
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

impl From<security_error::SecurityError> for SecurityError {
    fn from(val: security_error::SecurityError) -> Self {
        match val {
            security_error::SecurityError::GenericError(v) => SecurityError::GenericError(v),
            security_error::SecurityError::InvalidPayload => SecurityError::InvalidPayload,
            security_error::SecurityError::KeyNotFound => SecurityError::KeyNotFound
        }
    }
}

impl IntoResponse for SecurityError {
    fn into_response(self) -> Response {
       let status_code = match self {
          SecurityError::InvalidPayload => StatusCode::BAD_REQUEST,
          SecurityError::KeyNotFound => StatusCode::UNPROCESSABLE_ENTITY,
          SecurityError::GenericError(_) => StatusCode::INTERNAL_SERVER_ERROR,
       };
 
       match self {
          Self::GenericError(v) => ErrorResponse::send(
             status_code.as_u16(),
             0,
            //  Some("oops, something when wrong".to_string()),
             Some(v),
          ),
          _ => ErrorResponse::send(status_code.as_u16(), 0, Some(self.to_string())),
       }
    }
 }
 