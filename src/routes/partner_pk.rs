use axum::Router;

use axum::routing::{get, post, delete};

use crate::handler::partner_pk::{handle_get_keypairs, handle_get_keypair_by_hash, handle_generate_keypair, handle_delete_keypair};
use crate::state::partner_pk_state::PartnerPKState;

pub fn routes() -> Router<PartnerPKState> {
   let router = Router::new()
      .route("/keypairs/partners/:partner_id", get(handle_get_keypairs))
      .route("/keypairs/partners/:partner_id", post(handle_generate_keypair))
      .route(
         "/keypairs/partners/:partner_id/hash/:hash",
         get(handle_get_keypair_by_hash),
      )
      .route(
         "/keypairs/partners/:partner_id/hash/:hash",
         delete(handle_delete_keypair),
      );

   return router;
}
