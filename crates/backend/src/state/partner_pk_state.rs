
use std::sync::Arc;

use crate::config::database::Database;
use crate::service::partner_pk_service::{PartnerPKService, PartnerPKServiceTrait};

#[derive(Clone)]
pub struct PartnerPKState {
   pub(crate) service: PartnerPKService,
   // pub(crate) repository: MasterPKRepository,
}

impl PartnerPKState {
   pub fn new(conn: &Arc<Database>) -> PartnerPKState {
      Self {
         service: PartnerPKService::new(conn),
         // repository: MasterPKRepository::new(conn),
      }
   }
}
