use axum::{http::Request, middleware::Next, response::Response};
use hyper::http::HeaderValue;

use crate::{BUILD_TIME, BUILD_VER};

pub async fn build_version_header(req: Request<axum::body::Body>, next: Next) -> Response {
   let mut res = next.run(req).await;
   res.headers_mut()
      .insert("x-build-time", HeaderValue::from_static(BUILD_TIME));
   res.headers_mut()
      .insert("x-build-ver", HeaderValue::from_static(BUILD_VER));

   res
}
