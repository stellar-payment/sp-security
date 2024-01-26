use std::borrow::BorrowMut;

use crate::dto::partner_keypair::{PartnerPKPayload, PartnerPKResponse};
use crate::error::api_error::ApiError;
use crate::response::api_response::ApiResponse;
use crate::service::partner_pk::PartnerPKServiceTrait;
use crate::state::partner_pk_state::PartnerPKState;
use axum::extract::{Path, State};
use axum::Json;
use axum_extra::extract::WithRejection;

pub async fn handle_get_keypairs(
   State(mut state): State<PartnerPKState>,
   WithRejection(Path(partner_id), _): WithRejection<Path<String>, ApiError>,
) -> Result<Json<ApiResponse<PartnerPKResponse>>, ApiError> {
   let res = state.service.get_keypairs(partner_id).await;

   match res {
      Ok(v) => Ok(Json(ApiResponse::send(v))),
      Err(e) => Err(e)?,
   }
}

pub async fn handle_get_keypair_by_hash(
   State(mut state): State<PartnerPKState>,
   WithRejection(Path((partner_id, hash)), _): WithRejection<Path<(String, String)>, ApiError>,
) -> Result<Json<ApiResponse<PartnerPKResponse>>, ApiError> {
   let res = state.service.get_keypair_by_hash(partner_id, hash).await;

   match res {
      Ok(v) => Ok(Json(ApiResponse::send(v))),
      Err(e) => Err(e)?,
   }
}

pub async fn handle_generate_keypair(
   State(mut state): State<PartnerPKState>,
   WithRejection(Path(partner_id), _): WithRejection<Path<String>, ApiError>,
   WithRejection(Json(mut payload), _): WithRejection<Json<PartnerPKPayload>, ApiError>,
) -> Result<Json<ApiResponse<PartnerPKResponse>>, ApiError> {
   payload.partner_id = partner_id;
   let res = state.service.create_keypair(payload).await;

   match res {
      Ok(v) => Ok(Json(ApiResponse::send(v))),
      Err(e) => Err(e)?,
   }
}

pub async fn handle_delete_keypair(
   State(mut state): State<PartnerPKState>,
   WithRejection(Path((partner_id, hash)), _): WithRejection<Path<(String, String)>, ApiError>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
   let res = state.service.delete_keypair(partner_id, hash).await;

   match res {
      Err(e) => Err(e)?,
      _ => Ok(Json(ApiResponse::send(()))),
   }
}
