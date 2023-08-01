use axum::Router;

use crate::handler::master_pk::{handle_keypair_by_hash, handle_generate_keypair};
use crate::state::master_pk_state::MasterPKState;
use axum::routing::{get, post};

pub fn routes() -> Router<MasterPKState> {
   let router = Router::new()
      .route("/keypairs/master/hash/:hash", get(handle_keypair_by_hash))
      .route("/keypairs/master", post(handle_generate_keypair));

   return router;
}
