use axum::Json;
use axum_extra::extract::WithRejection;

use crate::dto::payload_sec::{DecryptDataPayload, DecryptDataResponse};
use crate::dto::payload_sec::{EncryptDataPayload, EncryptDataResponse};
use crate::response::api_response::ApiResponse;
use crate::service::payload_sec_service::PayloadSecurityServiceTrait;
use crate::{error::api_error::ApiError, state::payload_sec_state::PayloadSecurityState};

use axum::extract::State;

pub async fn handle_encrypt_payload(
   State(state): State<PayloadSecurityState>,
   WithRejection(Json(payload), _): WithRejection<Json<EncryptDataPayload>, ApiError>,
) -> Result<Json<ApiResponse<EncryptDataResponse>>, ApiError> {
   let res = state.service.encrypt_payload(payload).await;

   match res {
      Ok(v) => Ok(Json(ApiResponse::send(v))),
      Err(e) => Err(e)?,
   }
}

pub async fn handle_decrypt_payload(
   State(state): State<PayloadSecurityState>,
   WithRejection(Json(payload), _): WithRejection<Json<DecryptDataPayload>, ApiError>,
) -> Result<Json<ApiResponse<DecryptDataResponse>>, ApiError> {
   let res = state.service.decrypt_payload(payload).await;

   match res {
      Ok(v) => Ok(Json(ApiResponse::send(v))),
      Err(e) => Err(e)?,
   }}
