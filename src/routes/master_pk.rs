use axum::Router;

use axum::routing::get;
use crate::handler::master_pk::{handle_keypair_by_hash};
use crate::state::master_pk_state::MasterPKState;

pub fn routes() -> Router<MasterPKState> {
    let router = Router::new()
    .route("/keypairs/master/hash/:hash", get(handle_keypair_by_hash));

    return router;
}