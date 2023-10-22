use crate::{
   config::database::{Database, DatabaseTrait},
   entity::security::PartnerKeyPair,
   error::db_error::DBError,
};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct PartnerPKRepository {
   pub(crate) db: Arc<Database>,
}

#[async_trait]
pub trait PartnerPKRepositoryTrait {
   fn new(conn: &Arc<Database>) -> Self;

   async fn find_partner_keypairs(&self, partner_id: Uuid) -> Result<PartnerKeyPair, DBError>;
   async fn find_partner_keypair_by_id(&self, id: Uuid) -> Result<PartnerKeyPair, DBError>;
   async fn find_partner_keypair_by_hash(&self, hash: String) -> Result<PartnerKeyPair, DBError>;
   async fn insert_partner_keypair(&self, keypair: PartnerKeyPair) -> Result<Uuid, DBError>;
   async fn update_partner_keypair(&self, keypair: PartnerKeyPair) -> Option<DBError>;
   async fn delete_partner_keypair(&self, hash: String) -> Option<DBError>;
}

#[async_trait]
impl PartnerPKRepositoryTrait for PartnerPKRepository {
   fn new(conn: &Arc<Database>) -> Self {
      Self {
         db: Arc::clone(conn),
      }
   }

   async fn find_partner_keypairs(&self, partner_id: Uuid) -> Result<PartnerKeyPair, DBError> {
      let res = sqlx::query_as::<_, PartnerKeyPair>(
         r#"
         select id, partner_id, public_key, keypair_hash from partner_keypairs
         where partner_id = $1
      "#,
      )
      .bind(partner_id)
      .fetch_optional(self.db.get_pool())
      .await;

      match res {
         Ok(v) => match v {
            Some(v) => Ok(v),
            None => Err(DBError::NotFound),
         },
         Err(e) => Err(DBError::Yabaii(e.to_string())),
      }
   }

   async fn find_partner_keypair_by_id(&self, id: Uuid) -> Result<PartnerKeyPair, DBError> {
      let res = sqlx::query_as::<_, PartnerKeyPair>(
         r#"
      select id, partner_id, public_key, keypair_hash from partner_keypairs
      where id = $1
   "#,
      )
      .bind(id)
      .fetch_optional(self.db.get_pool())
      .await;

      match res {
         Ok(v) => match v {
            Some(v) => Ok(v),
            None => Err(DBError::NotFound),
         },
         Err(e) => Err(DBError::Yabaii(e.to_string())),
      }
   }

   async fn find_partner_keypair_by_hash(&self, hash: String) -> Result<PartnerKeyPair, DBError> {
      let res = sqlx::query_as::<_, PartnerKeyPair>(
         r#"
      select id, partner_id, public_key, keypair_hash from partner_keypairs
      where keypair_hash = $1
   "#,
      )
      .bind(hash)
      .fetch_optional(self.db.get_pool())
      .await;

      match res {
         Ok(v) => match v {
            Some(v) => Ok(v),
            None => Err(DBError::NotFound),
         },
         Err(e) => Err(DBError::Yabaii(e.to_string())),
      }
   }

   async fn insert_partner_keypair(&self, keypair: PartnerKeyPair) -> Result<Uuid, DBError> {
      let current_time = Utc::now();

      let res = sqlx::query("insert into partner_keypairs(id, partner_id, public_key, keypair_hash, created_at, updated_at) values ($1, $2, $3, $4, $5)")
      .bind(keypair.id)
      .bind(keypair.partner_id)
      .bind(keypair.public_key)
      .bind(keypair.keypair_hash)
      .bind(current_time)
      .bind(current_time)
      .fetch_one(self.db.get_pool())
      .await.map_err(|e| DBError::Yabaii(e.to_string()))?;

      Ok(res.get::<Uuid, _>(0))
   }

   async fn update_partner_keypair(&self, keypair: PartnerKeyPair) -> Option<DBError> {
      let current_time = Utc::now();

      let res = sqlx::query(
         r#"
         update partner_keypairs set
            public_key = $1,
            keypair_hash = $2,
            updated_at = $3
         where
            id = $4 and partner_id = $5
      "#,
      )
      .bind(keypair.public_key)
      .bind(keypair.keypair_hash)
      .bind(current_time)
      .bind(keypair.id)
      .bind(keypair.partner_id)
      .execute(self.db.get_pool())
      .await;

      match res {
         Err(e) => Some(DBError::Yabaii(e.to_string())),
         _ => None,
      }
   }

   async fn delete_partner_keypair(&self, hash: String) -> Option<DBError> {
      let res = sqlx::query(r#"delete from partner_keypairs where keypair_hash = $1"#)
         .bind(hash)
         .execute(self.db.get_pool())
         .await;

      match res {
         Err(e) => Some(DBError::Yabaii(e.to_string())),
         _ => None,
      }
   }
}
