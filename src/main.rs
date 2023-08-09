use crate::config::database::DatabaseTrait;
use crate::config::{database, parameter};
use std::sync::Arc;

mod config;
mod dto;
mod entity;
mod error;
mod handler;
mod layers;
mod repository;
mod response;
mod routes;
mod service;
mod state;

pub const BUILD_TIME: &str = env!("BUILD_TIMESTAMP");
pub const BUILD_VER: &str = env!("BUILD_TAG");

#[tokio::main]
async fn main() {
   parameter::init();
   let conn = database::Database::init()
      .await
      .unwrap_or_else(|e| panic!("database error: {}", e));

   let host = format!("0.0.0.0:{}", parameter::get("PORT"));
   tracing_subscriber::fmt::init();
   axum::Server::bind(&host.parse().unwrap())
      .serve(routes::root::routes(Arc::new(conn)))
      .await
      .unwrap_or_else(|e| panic!("server error: {}", e));
}
