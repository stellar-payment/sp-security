use axum::Json;
use chrono::Utc;
use crate::dto::healthcheck_dto;
use crate::response::api_response::ApiResponse;


pub async fn handle_healthcheck() -> Json<ApiResponse<healthcheck_dto::HealthCheckDto>> {
    let time_now = Utc::now();
    
    Json(ApiResponse::send(healthcheck_dto::HealthCheckDto {
        message: "kyaaNakaWaZettaiDame!".to_string(),
        unix_timestamp: time_now.timestamp_millis(),
        timestamp: time_now.format("%d/%m/%Y %H:%M").to_string(),
    }))
}