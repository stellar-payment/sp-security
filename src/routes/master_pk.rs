use axum::Router;

use crate::handler::master_pk::{handle_generate_keypair, handle_get_keypair_by_hash, handle_get_keypairs, handle_delete_keypair};
use crate::state::master_pk_state::MasterPKState;
use axum::routing::{get, post, delete};

pub fn routes() -> Router<MasterPKState> {
   let router = Router::new()
      .route("/keypairs/master", get(handle_get_keypairs))
      .route("/keypairs/master", post(handle_generate_keypair))
      .route(
         "/keypairs/master/hash/:hash",
         get(handle_get_keypair_by_hash),
      )
      .route(
         "/keypairs/master/hash/:hash",
         delete(handle_delete_keypair),
      );

   return router;
}
