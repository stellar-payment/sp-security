
use std::sync::Arc;

use crate::config::database::Database;
use crate::service::partner::{PartnerService, PartnerServiceTrait};

#[derive(Clone)]
pub struct PartnerState {
   pub(crate) service: PartnerService,
   // pub(crate) repository: MasterPKRepository,
}

impl PartnerState {
   pub fn new(conn: &Arc<Database>) -> PartnerState {
      Self {
         service: PartnerService::new(conn),
         // repository: MasterPKRepository::new(conn),
      }
   }
}
