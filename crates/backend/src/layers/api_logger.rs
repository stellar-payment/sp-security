use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use log::info;

pub async fn api_logger(
   req: Request<axum::body::Body>,
   next: Next,
) -> Result<impl IntoResponse, (StatusCode, String)> {
   let path = &req.uri().path().to_string();

   let (req_parts, req_body) = req.into_parts();
   let bytes = log_payload("request", path, req_body).await?;

   let res = next
      .run(Request::from_parts(req_parts, bytes))
      .await;

   let (res_parts, res_body) = res.into_parts();
   let bytes = log_payload("response", path, res_body).await?;

   let res = Response::from_parts(res_parts, Body::new(bytes));

   Ok(res)
}

async fn log_payload(direction: &str, path: &str, body: axum::body::Body) -> Result<axum::body::Body, (StatusCode, String)> {
   let bytes = match axum::body::to_bytes(body, usize::MAX).await {
      Ok(b) => b,
      Err(e) => {
         return Err((
            StatusCode::BAD_REQUEST,
            format!("failed to parse {} body: {}", direction, e),
         ));
      }
   };

   if let Ok(body) = std::str::from_utf8(&bytes) {
      if !body.is_empty() {
         if body.len() > 2000 {
            info!("{}: {} with body: {}...", direction, path, &body[0..2000]);
         } else {
            info!("{}: {} with body: {}", direction, path, body);
         }
      }
   }

   Ok(Body::from(bytes))
}
