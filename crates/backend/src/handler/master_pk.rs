use crate::dto::master_keypair::{ListMasterPKResponse, MasterPKResponse};
use crate::error::api_error::ApiError;
use crate::response::api_response::ApiResponse;
use crate::service::master_pk::MasterPKServiceTrait;
use crate::state::master_pk_state::MasterPKState;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use axum::Json;

pub async fn handle_get_keypairs(
   State(state): State<MasterPKState>,
) -> Result<Json<ApiResponse<ListMasterPKResponse>>, ApiError> {
   let res = state.service.get_keypairs().await;

   match res {
      Ok(v) => Ok(Json(ApiResponse::send(v))),
      Err(e) => Err(e)?,
   }
}

pub async fn handle_get_keypair_by_hash(
   State(state): State<MasterPKState>,
   WithRejection(Path(hash), _): WithRejection<Path<String>, ApiError>,
) -> Result<Json<ApiResponse<MasterPKResponse>>, ApiError> {
   let res = state.service.get_keypair_by_hash(hash).await;

   match res {
      Ok(v) => Ok(Json(ApiResponse::send(v))),
      Err(e) => Err(e)?,
   }
}

pub async fn handle_generate_keypair(
   State(state): State<MasterPKState>,
) -> Result<Json<ApiResponse<MasterPKResponse>>, ApiError> {
   let res = state.service.create_keypair().await;

   match res {
      Ok(v) => Ok(Json(ApiResponse::send(v))),
      Err(e) => Err(e)?,
   }
}
pub async fn handle_delete_keypair(
   State(state): State<MasterPKState>,
   WithRejection(Path(hash), _): WithRejection<Path<String>, ApiError>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
   let res = state.service.delete_keypair(hash).await;

   match res {
      Some(e) => Err(e)?,
      _ => Ok(Json(ApiResponse::send(()))),
   }
}
