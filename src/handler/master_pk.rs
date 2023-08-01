use crate::dto::master_keypair::{ListMasterPKResponse, MasterPKPayload, MasterPKResponse};
use crate::error::api_error::ApiError;
use crate::response::api_response::ApiResponse;
use crate::service::master_pk_service::MasterPKServiceTrait;
use crate::state::master_pk_state::MasterPKState;
use axum::extract::{Path, State};
use axum::Json;

pub async fn handle_keypair_by_hash(
   State(state): State<MasterPKState>,
   Path(hash): Path<String>,
) -> Result<Json<ApiResponse<MasterPKResponse>>, ApiError> {
   let res = state.service.get_keypair_by_hash(hash).await;

   return match res {
      Ok(v) => Ok(Json(ApiResponse::send(v))),
      Err(e) => Err(e)?,
   };
}

pub async fn handle_generate_keypair(
   State(state): State<MasterPKState>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
   let res = state.service.create_keypair().await;

   return match res {
      Some(e) => Err(e)?,
      None => Ok(Json(ApiResponse::send(())))
   };
}
