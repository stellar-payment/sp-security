use async_trait::async_trait;
use p256::SecretKey;
use std::sync::Arc;

use crate::config::database::Database;
use crate::dto::master_keypair::{ListMasterPKResponse, MasterPKPayload, MasterPKResponse};
use crate::entity::security::MasterKeyPair;
use crate::error::keypair_error::KeypairError;
use crate::repository::master_pk_repository::{MasterPKRepository, MasterPKRepositoryTrait};
use sha256;
use base64::{engine::general_purpose, Engine as _};
use rand_core::OsRng;

#[derive(Clone)]
pub struct MasterPKService {
   repository: MasterPKRepository,
}

#[async_trait]
pub trait MasterPKServiceTrait {
   fn new(db: &Arc<Database>) -> Self;
   async fn get_keypair_by_hash(&self, hash: String) -> Result<MasterPKResponse, KeypairError>;
   async fn get_keypairs(&self) -> Result<ListMasterPKResponse, KeypairError>;
   async fn create_keypair(&self) -> Option<KeypairError>;
   async fn update_keypair(&self, payload: MasterPKPayload) -> Option<KeypairError>;
   async fn delete_keypair(&self, payload: MasterPKPayload) -> Option<KeypairError>;
}

#[async_trait]
impl MasterPKServiceTrait for MasterPKService {
   fn new(conn: &Arc<Database>) -> Self {
      Self {
         repository: MasterPKRepository::new(conn),
      }
   }

   async fn get_keypair_by_hash(&self, hash: String) -> Result<MasterPKResponse, KeypairError> {
      if hash.is_empty() {
         return Err(KeypairError::KeypairInvalid);
      };

      return match self.repository.find_keypair_by_hash(hash).await {
         Ok(v) => Ok(MasterPKResponse {
            id: v.id,
            public_key: v.public_key,
            private_key: v.private_key,
            keypair_hash: v.keypair_hash,
         }),
         Err(e) => Err(KeypairError::KeypairYabai(e.to_string())),
      };
   }

   async fn get_keypairs(&self) -> Result<ListMasterPKResponse, KeypairError> {
      todo!()
   }

   async fn create_keypair(&self) -> Option<KeypairError> {
      let secret = SecretKey::random(&mut OsRng);
      let pk = secret.public_key();

      let encoded_secret = general_purpose::STANDARD.encode(secret.to_bytes());
      let encoded_pk = general_purpose::STANDARD.encode(pk.to_sec1_bytes());
      let hashed = sha256::digest(encoded_secret.clone());

      let payload = MasterKeyPair {
         id: 0,
         public_key: encoded_pk,
         private_key: encoded_secret,
         keypair_hash: hashed,
      };

      return match self.repository.insert_keypair(payload).await {
         Ok(_) => None,
         Err(e) => Some(KeypairError::KeypairCreationError(e.to_string())),
      };
   }

   async fn update_keypair(&self, payload: MasterPKPayload) -> Option<KeypairError> {
      todo!()
   }
   async fn delete_keypair(&self, payload: MasterPKPayload) -> Option<KeypairError> {
      todo!()
   }
}
