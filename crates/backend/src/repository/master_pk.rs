use crate::config::database::{Database, DatabaseTrait};
use crate::entity::security::MasterKeyPair;

use crate::error::db_error::DBError;

use async_trait::async_trait;
use chrono::Utc;

use sqlx::Row;
use uuid::Uuid;
use std::sync::Arc;


#[derive(Clone)]
pub struct MasterPKRepository {
   pub(crate) db: Arc<Database>,
}

#[async_trait]
pub trait MasterPKRepositoryTrait {
   fn new(conn: &Arc<Database>) -> Self;

   async fn find_keypairs(&self) -> Result<Vec<MasterKeyPair>, DBError>;
   async fn find_keypair_by_id(&self, id: Uuid) -> Result<MasterKeyPair, DBError>;
   async fn find_keypair_by_hash(&self, hash: String) -> Result<MasterKeyPair, DBError>;
   async fn insert_keypair(&self, keypair: MasterKeyPair) -> Result<Uuid, DBError>;
   async fn update_keypair(&self, keypair: MasterKeyPair) -> Option<DBError>;
   async fn delete_keypair(&self, id: Uuid) -> Option<DBError>;
}

#[async_trait]
impl MasterPKRepositoryTrait for MasterPKRepository {
   fn new(conn: &Arc<Database>) -> Self {
      Self {
         db: Arc::clone(conn),
      }
   }

   async fn find_keypairs(&self) -> Result<Vec<MasterKeyPair>, DBError> {
      let res = sqlx::query_as::<_, MasterKeyPair>(r#"
         select id, public_key, private_key, keypair_hash, created_at, updated_at 
         from master_keypairs
         where deleted_at is null 
      "#).fetch_all(self.db.get_pool()).await;

      match res {
         Ok(v) => Ok(v),
         Err(e) => Err(DBError::Yabaii(e.to_string()))
      }
   }

   async fn find_keypair_by_id(&self, id: Uuid) -> Result<MasterKeyPair, DBError> {
      let res = sqlx::query_as::<_, MasterKeyPair>(r#"
         select id, public_key, private_key, keypair_hash, created_at, updated_at from master_keypairs 
         where
            id = $1 and
            deleted_at is null
      "#).bind(id)
      .fetch_optional(self.db.get_pool())
      .await;

      match res {
         Ok(v) => match v {
            Some(v) => Ok(v),
            None => Err(DBError::NotFound)
        },
        Err(e) => Err(DBError::Yabaii(e.to_string()))
     }
   }

   async fn find_keypair_by_hash(&self, hash: String) -> Result<MasterKeyPair, DBError> {
      let res = sqlx::query_as::<_, MasterKeyPair>(r"
         select id, public_key, private_key, keypair_hash, created_at, updated_at from master_keypairs 
         where
            keypair_hash = $1 and
            deleted_at is null").bind(hash)
      .fetch_optional(self.db.get_pool())
      .await;
      
      match res {
         Ok(v) => match v {
               Some(v) => Ok(v),
               None => Err(DBError::NotFound)
         },
         Err(e) => Err(DBError::Yabaii(e.to_string()))
      }
   }

   async fn insert_keypair(&self, keypair: MasterKeyPair) -> Result<Uuid, DBError> {
      let current_time = Utc::now();
      
      let res = sqlx::query(
         "insert into master_keypairs(id, public_key, private_key, keypair_hash, created_at, updated_at) values ($1, $2, $3, $4, $5) returning id")
         .bind(keypair.id)
         .bind(keypair.public_key)
         .bind(keypair.private_key) 
         .bind(keypair.keypair_hash) 
         .bind(current_time) 
         .bind(current_time)
      .fetch_one(self.db.get_pool())
      .await.map_err(|e| DBError::Yabaii(e.to_string()))?;
   
      Ok(res.get::<Uuid, _>(0))
   }

   async fn update_keypair(&self, keypair: MasterKeyPair) -> Option<DBError> {
      let current_time = Utc::now();

      let res = sqlx::query(
         "update master_keypairs set 
            public_key = $1, 
            private_key = $2, 
            keypair_hash = $3,  
            updated_at = $4
         where 
            id = $5 and
            deleted_at is null
         ")
      .bind(keypair.public_key)
         .bind(keypair.private_key) 
         .bind(keypair.keypair_hash) 
         .bind(current_time) 
         .bind(keypair.id)
      .execute(self.db.get_pool())
      .await;

      match res {
         Err(e) => Some(DBError::Yabaii(e.to_string())),
         _ => None
      }

   }
   
   async fn delete_keypair(&self, id: Uuid) -> Option<DBError> {
      let res = sqlx::query(
         "update master_keypairs set 
            updated_at = $1,
            deleted_at = $1
         where 
            id = $1 and
            deleted_at is null
         ")
      .bind(Utc::now())
      .bind(id)
      .execute(self.db.get_pool())
      .await;

      match res {
         Err(e) => Some(DBError::Yabaii(e.to_string())),
         _ => None
      }
   }
}
