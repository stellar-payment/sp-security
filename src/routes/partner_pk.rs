use axum::Router;

use axum::routing::{delete, get, post};

use crate::handler::partner_pk::{
   handle_delete_keypair, handle_generate_keypair, handle_get_keypair_by_hash, handle_get_keypairs,
};
use crate::state::partner_pk_state::PartnerPKState;

pub fn routes() -> Router<PartnerPKState> {
   Router::new()
      .route("/keypairs/partners/:partner_id", get(handle_get_keypairs))
      .route(
         "/keypairs/partners/:partner_id",
         post(handle_generate_keypair),
      )
      .route(
         "/keypairs/partners/:partner_id/hash/:hash",
         get(handle_get_keypair_by_hash),
      )
      .route(
         "/keypairs/partners/:partner_id/hash/:hash",
         delete(handle_delete_keypair),
      )
}
