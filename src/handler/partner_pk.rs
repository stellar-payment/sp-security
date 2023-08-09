use crate::dto::partner_keypair::{ListPartnerPKResponse, PartnerPKPayload, PartnerPKResponse};
use crate::error::api_error::ApiError;
use crate::response::api_response::ApiResponse;
use crate::service::partner_pk_service::PartnerPKServiceTrait;
use crate::state::partner_pk_state::PartnerPKState;
use axum::extract::{Path, State};
use axum::Json;

pub async fn handle_get_keypairs(
   State(state): State<PartnerPKState>,
   Path(partner_id): Path<u64>
) -> Result<Json<ApiResponse<ListPartnerPKResponse>>, ApiError> {
   let res = state.service.get_keypairs(partner_id).await;

   return match res {
      Ok(v) => Ok(Json(ApiResponse::send(v))),
      Err(e) => Err(e)?,
   };
}

pub async fn handle_get_keypair_by_hash(
   State(state): State<PartnerPKState>,
   Path((partner_id, hash)): Path<(u64, String)>,
) -> Result<Json<ApiResponse<PartnerPKResponse>>, ApiError> {
   let res = state.service.get_keypair_by_hash(partner_id, hash).await;

   return match res {
      Ok(v) => Ok(Json(ApiResponse::send(v))),
      Err(e) => Err(e)?,
   };
}

pub async fn handle_generate_keypair(
   State(state): State<PartnerPKState>,
   Json(payload): Json<PartnerPKPayload>,
) -> Result<Json<ApiResponse<PartnerPKResponse>>, ApiError> {
   let res = state.service.create_keypair(payload).await;

   return match res {
      Ok(v) => Ok(Json(ApiResponse::send(v))),
      Err(e) => Err(e)?,
   };
}

pub async fn handle_delete_keypair(
   State(state): State<PartnerPKState>,
   Path(hash): Path<String>
) -> Result<Json<ApiResponse<()>>, ApiError> {
   let res = state.service.delete_keypair(hash).await;

   return match res {
      Err(e) => Err(e)?,
      _ => Ok(Json(ApiResponse::send(()))),
   };
}
