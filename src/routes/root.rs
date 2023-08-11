use axum::routing::{get, IntoMakeService};
use axum::Router;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

use crate::config::database::Database;
use crate::handler::healthcheck;
use crate::layers::build_versioner::build_version_header;
use crate::state::master_pk_state::MasterPKState;
use crate::state::partner_pk_state::PartnerPKState;

use super::{master_pk, partner_pk};

pub fn routes(db: Arc<Database>) -> IntoMakeService<Router> {
   let merged_router: Router = {
      let master_pk_state = MasterPKState::new(&db);
      let partner_pk_state = PartnerPKState::new(&db);

      Router::new()
         .merge(master_pk::routes().with_state(master_pk_state))
         .merge(partner_pk::routes().with_state(partner_pk_state))
         .merge(Router::new().route("/health", get(healthcheck::handle_healthcheck)))
   };

   let router = Router::new()
      .nest("/api/v1", merged_router)
      .layer(axum::middleware::from_fn(build_version_header))
      .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

   router.into_make_service()
}
