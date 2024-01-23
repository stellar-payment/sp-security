use axum::routing::{post, get};
use axum::Router;

use crate::handler::payload_sec::{
    handle_decrypt_payload, handle_encrypt_payload, 
    handle_generate_keypair, handle_get_keypair_by_hash,
};
use crate::state::payload_sec_state::PayloadSecurityState;

pub fn routes() -> Router<PayloadSecurityState> {
    Router::new()
        .route("/payload/encrypt", post(handle_encrypt_payload))
        .route("/payload/decrypt", post(handle_decrypt_payload))
        .route("/keypairs/master", post(handle_generate_keypair))
        .route(
            "/keypairs/master/hash/:hash",
            get(handle_get_keypair_by_hash),
        )
}
