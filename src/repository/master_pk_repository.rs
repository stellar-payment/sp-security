use crate::config::database::{Database, DatabaseTrait};
use crate::entity::security::MasterKeyPair;
use crate::error::db_error::DBError;

use async_trait::async_trait;
use chrono::Utc;
use sqlx::Error;
use std::sync::Arc;


#[derive(Clone)]
pub struct MasterPKRepository {
   pub(crate) db: Arc<Database>,
}

#[async_trait]
pub trait MasterPKRepositoryTrait {
   fn new(conn: &Arc<Database>) -> Self;

   async fn find_keypair_by_id(&self, id: i32) -> Result<MasterKeyPair, DBError>;
   async fn find_keypair_by_hash(&self, hash: String) -> Result<MasterKeyPair, DBError>;
   async fn insert_keypair(&self, keypair: MasterKeyPair) -> Result<MasterKeyPair, DBError>;
   async fn update_keypair(&self, keypair: MasterKeyPair) -> Option<DBError>;
   async fn delete_keypair(&self, id: i32) -> Option<DBError>;
}

#[async_trait]
impl MasterPKRepositoryTrait for MasterPKRepository {
   fn new(conn: &Arc<Database>) -> Self {
      Self {
         db: Arc::clone(conn),
      }
   }

   async fn find_keypair_by_id(&self, id: i32) -> Result<MasterKeyPair, DBError> {
      let res = sqlx::query_as::<_, MasterKeyPair>("
         select id, public_key, private_key, keypair_hash, created_at, updated_at from master_keypair 
         where
            id = ?
      ").bind(id)
      .fetch_one(self.db.get_pool())
      .await;

      match res {
         Ok(v) => Ok(v),
         Err(e) => Err(DBError::Yabaii(e.to_string()))
      }
   }

   async fn find_keypair_by_hash(&self, hash: String) -> Result<MasterKeyPair, DBError> {
      let res = sqlx::query_as::<_, MasterKeyPair>("
         select id, public_key, private_key, keypair_hash, created_at, updated_at from master_keypair 
         where
            keypair_hash = ?
      ").bind(hash)
      .fetch_one(self.db.get_pool())
      .await;
   
      match res {
         Ok(v) => Ok(v),
         Err(e) => Err(DBError::Yabaii(e.to_string()))
      }
   }

   async fn insert_keypair(&self, keypair: MasterKeyPair) -> Result<MasterKeyPair, DBError> {
      let current_time = Utc::now();

      let res = sqlx::query_as::<_, MasterKeyPair>(
         "insert into master_keypair columns(public_key, private_key, keypair_hash, created_at, updated_at) values (?, ?, ?, ?, ?) 
         returning id, public_key, private_key, keypair_hash, created_at, updated_at")
      .bind(keypair.public_key)
         .bind(keypair.private_key) 
         .bind(keypair.keypair_hash) 
         .bind(current_time) 
         .bind(current_time)
      .fetch_one(self.db.get_pool())
      .await;
   
      match res {
         Ok(v) => Ok(v),
         Err(e) => Err(DBError::Yabaii(e.to_string()))
      }
   }

   async fn update_keypair(&self, keypair: MasterKeyPair) -> Option<DBError> {
      let current_time = Utc::now();

      let res = sqlx::query(
         "update master_keypair set 
            public_key = ?, 
            private_key = ?, 
            keypair_hash = ?,  
            updated_at = ?
         where 
            id = ?
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
   
   async fn delete_keypair(&self, id: i32) -> Option<DBError> {
      let res = sqlx::query("delete from master_keypair where id = ?")
      .bind(id)
      .execute(self.db.get_pool())
      .await;

      match res {
         Err(e) => Some(DBError::Yabaii(e.to_string())),
         _ => None
      }
   }
}