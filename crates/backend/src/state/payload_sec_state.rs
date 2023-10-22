use std::sync::Arc;

use crate::service::payload_sec::{PayloadSecurityService, PayloadSecurityServiceTrait};
use crate::config::database::Database;

#[derive(Clone)]
pub struct PayloadSecurityState {
    pub(crate) service: PayloadSecurityService
}

impl PayloadSecurityState {
    pub fn new(conn: &Arc<Database>) -> PayloadSecurityState {
        Self { 
            service: PayloadSecurityService::new(conn), 
        }
    }
}