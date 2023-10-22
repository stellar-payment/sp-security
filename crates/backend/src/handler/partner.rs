use crate::dto::partner::{ListPartnerResponse, PartnerResponse, PartnerPayload};
use crate::error::api_error::ApiError;
use crate::response::api_response::ApiResponse;
use crate::service::partner::PartnerServiceTrait;
use crate::state::partner_state::PartnerState;
use axum::extract::{Path, State};
use axum::Json;
use axum_extra::extract::WithRejection;

pub async fn handle_get_partners(
   State(state): State<PartnerState>,
) -> Result<Json<ApiResponse<ListPartnerResponse>>, ApiError> {
   let res = state.service.get_partners().await;

   match res {
      Ok(v) => Ok(Json(ApiResponse::send(v))),
      Err(e) => Err(e)?,
   }
}

pub async fn handle_get_partner_by_id(
   State(state): State<PartnerState>,
   WithRejection(Path(partner_id), _): WithRejection<Path<String>, ApiError>,
) -> Result<Json<ApiResponse<PartnerResponse>>, ApiError> {
   let res = state.service.get_partner_by_id(partner_id).await;

   match res {
      Ok(v) => Ok(Json(ApiResponse::send(v))),
      Err(e) => Err(e)?,
   }
}

pub async fn handle_create_partner(
   State(state): State<PartnerState>,
   WithRejection(Json(payload), _): WithRejection<Json<PartnerPayload>, ApiError>,
) -> Result<Json<ApiResponse<PartnerResponse>>, ApiError> {
   let res = state.service.create_partner(payload).await;

   match res {
      Ok(v) => Ok(Json(ApiResponse::send(v))),
      Err(e) => Err(e)?,
   }
}

pub async fn handle_update_partner(
   State(state): State<PartnerState>,
   WithRejection(Path(partner_id), _): WithRejection<Path<String>, ApiError>,
   WithRejection(Json(mut payload), _): WithRejection<Json<PartnerPayload>, ApiError>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
   payload.id = partner_id;
   let res = state.service.update_partner(payload).await;

   match res {
      Err(e) => Err(e)?,
      _ => Ok(Json(ApiResponse::send(()))),
   }
}

pub async fn handle_delete_partner(
   State(state): State<PartnerState>,
   WithRejection(Path(partner_id), _): WithRejection<Path<String>, ApiError>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
   let res = state.service.delete_partner(partner_id).await;

   match res {
      Err(e) => Err(e)?,
      _ => Ok(Json(ApiResponse::send(()))),
   }
}
