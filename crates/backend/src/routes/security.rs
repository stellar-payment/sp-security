use axum::Router;
use axum::routing::post;

use crate::handler::payload_sec::{
    handle_decrypt_payload, handle_encrypt_payload
};
use crate::state::payload_sec_state::PayloadSecurityState;

pub fn routes() -> Router<PayloadSecurityState> {
    Router::new()
        .route("/payload/encrypt", post(handle_encrypt_payload))
        .route("/payload/decrypt", post(handle_decrypt_payload))
}