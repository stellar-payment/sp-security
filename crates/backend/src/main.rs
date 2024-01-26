use crate::config::database::DatabaseTrait;
use crate::config::cache::CacheTrait;
use crate::config::{database, parameter, cache};
use std::panic;
use std::sync::Arc;
use log::{info, error};
use structured_logger::{async_json::new_writer, Builder};
use tokio::io;

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

macro_rules! env_or {
   ($name: expr, $default: expr) => {
      if let Some(val) = option_env!($name) {
         val
      } else {
         $default
      }
   };
}

pub const BUILD_TIME: &str = env_or!("BUILD_TIMESTAMP", "unknown");
pub const BUILD_VER: &str = env_or!("BUILD_TAG", "v1.0.0-alpha");

#[tokio::main]
async fn main() {
   Builder::new()
      .with_target_writer("*", new_writer(io::stdout()))
      .init();

   panic::set_hook(Box::new(move |panic_info| {
      let (file, line) = match panic_info.location() {
         Some(v) => (v.file(), v.line()),
         None => ("", 0),
      };

      if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
         log::error!(line=line, file=file; "{}", s);
      } else {
         log::error!(line=line, file=file; "{}", panic_info.to_string());
      }
   }));

   parameter::init();
   let db = database::Database::init()
      .await
      .unwrap_or_else(|e| panic!("database error: {}", e));
   
   let cache = cache::Cache::init()
      .await
      .unwrap_or_else(|e| panic!("cache error: {}", e));
   
   let host = format!("0.0.0.0:{}", parameter::get("PORT"));
   info!("listening on {}", host);

   // let listener = tokio::net::TcpListener::bind(host)
   //    .await
   //    .unwrap_or_else(|e| panic!("failed to initialize listener error: {}", e));

   // match axum::serve(listener, routes::root::routes(Arc::new(db), cache))
   //    .await {
   //       Ok(_) => (),
   //       Err(e) =>  error!("failed to connect error: {}", e)
   //    }

   match axum::Server::bind(&host.parse().unwrap())
   .serve(routes::root::routes(Arc::new(db), cache)).await {
      Ok(_) => (), 
      Err(e) => error!("failed to connect error: {}", e)
   }

}
