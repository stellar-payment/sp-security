use axum::routing::{get, IntoMakeService};
use axum::Router;
use std::sync::Arc;

use crate::config::database::Database;
use crate::handler::root;
use crate::layers::api_logger::api_logger;
use crate::layers::build_versioner::build_version_header;
use crate::state::master_pk_state::MasterPKState;
use crate::state::partner_pk_state::PartnerPKState;
use crate::state::partner_state::PartnerState;
use crate::state::payload_sec_state::PayloadSecurityState;

use super::{master_pk, partner_pk, security, partner};

pub fn routes(db: Arc<Database>) -> IntoMakeService<Router> {
   let merged_router: Router = {
      let master_pk_state = MasterPKState::new(&db);
      let partner_pk_state = PartnerPKState::new(&db);
      let payload_enc_state = PayloadSecurityState::new(&db);
      let partner_state = PartnerState::new(&db);

      Router::new()
         .merge(master_pk::routes().with_state(master_pk_state))
         .merge(partner_pk::routes().with_state(partner_pk_state))
         .merge(security::routes().with_state(payload_enc_state))
         .merge(partner::routes().with_state(partner_state))
         .merge(Router::new().route("/ping", get(root::handle_healthcheck)))
         .fallback(root::handle_fallback)
   };

   let router = Router::new()
      .nest("/api/v1", merged_router)
      .layer(axum::middleware::from_fn(build_version_header))
      .layer(axum::middleware::from_fn(api_logger));
      // .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

   router.into_make_service()
}
