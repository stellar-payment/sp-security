use std::sync::Arc;

use crate::config::cache::Cache;
use crate::service::payload_sec::{PayloadSecurityService, PayloadSecurityServiceTrait};
use crate::config::database::Database;

#[derive(Clone)]
pub struct PayloadSecurityState {
    pub(crate) service: PayloadSecurityService
}

impl PayloadSecurityState {
    pub fn new(db: &Arc<Database>, cache: Cache) -> PayloadSecurityState {
        Self { 
            service: PayloadSecurityService::new(db, cache), 
        }
    }
}