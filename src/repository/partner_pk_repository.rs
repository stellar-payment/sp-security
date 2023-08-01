use crate::config::database::Database;
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Clone)]
pub struct PartnerPKRepository {
   pub(crate) db: Arc<Database>,
}

#[async_trait]
pub trait PartnerPKRepositoryTrait {
   fn new(conn: &Arc<Database>) -> Self;

}
