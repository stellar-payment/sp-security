use axum::Router;

use axum::routing::{get, post, put, delete};

use crate::handler::partner::{handle_get_partners, handle_get_partner_by_id, handle_create_partner, handle_update_partner, handle_delete_partner};
use crate::state::partner_state::PartnerState;

pub fn routes() -> Router<PartnerState> {
   Router::new()
      .route("/partners", get(handle_get_partners))
      .route("/partners/:partner_id", get(handle_get_partner_by_id))
      .route("/partners", post(handle_create_partner))
      .route("/partners/:partner_id", put(handle_update_partner))
      .route("/partners/:partner_id", delete(handle_delete_partner))
}
