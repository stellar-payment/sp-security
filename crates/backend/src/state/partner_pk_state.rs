
use std::sync::Arc;

use crate::config::cache::Cache;
use crate::config::database::Database;
use crate::service::partner_pk::{PartnerPKService, PartnerPKServiceTrait};

#[derive(Clone)]
pub struct PartnerPKState {
   pub(crate) service: PartnerPKService,
   // pub(crate) repository: MasterPKRepository,
}

impl PartnerPKState {
   pub fn new(db: &Arc<Database>, cache: Cache) -> PartnerPKState {
      Self {
         service: PartnerPKService::new(db, cache),
         // repository: MasterPKRepository::new(conn),
      }
   }
}
