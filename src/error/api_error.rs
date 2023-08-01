use crate::error::{db_error::DBError, keypair_error::KeypairError, security_error::SecurityError};
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
   #[error(transparent)]
   DBError(#[from] DBError),
   #[error(transparent)]
   KeypairError(#[from] KeypairError),
   #[error(transparent)]
   SecurityError(#[from] SecurityError),
}

impl IntoResponse for ApiError {
   fn into_response(self) -> Response {
      match self {
         ApiError::DBError(error) => error.into_response(),
         ApiError::KeypairError(error) => error.into_response(),
         ApiError::SecurityError(error) => error.into_response(),
      }
   }
}
