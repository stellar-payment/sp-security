use std::sync::Arc;

use crate::config::database::Database;
use crate::entity::security::PartnerKeyPair;
use crate::repository::partner_pk_repository::{PartnerPKRepository, PartnerPKRepositoryTrait};
use crate::dto::partner_keypair::{PartnerPKResponse, ListPartnerPKResponse, PartnerPKPayload};
use crate::error::keypair_error::KeypairError;
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};


#[derive(Clone)]
pub struct PartnerPKService {
   repository: PartnerPKRepository,
}

#[async_trait]
pub trait PartnerPKServiceTrait {
   fn new(db: &Arc<Database>) -> Self;

   async fn get_keypairs(&self, partner_id: u64) -> Result<ListPartnerPKResponse, KeypairError>;
   async fn get_keypair_by_hash(&self, partner_id: u64, hash: String) -> Result<PartnerPKResponse, KeypairError>;
   async fn create_keypair(&self, payload: PartnerPKPayload) -> Result<PartnerPKResponse, KeypairError>;
   async fn update_keypair(&self, payload: PartnerPKPayload) -> Option<KeypairError>; 
   async fn delete_keypair(&self, hash: String) -> Option<KeypairError>; 
}


#[async_trait]
impl PartnerPKServiceTrait for PartnerPKService {
   fn new(db: &Arc<Database>) -> Self {
      Self { 
         repository: PartnerPKRepository::new(db) 
      }
   }   
   
   async fn get_keypairs(&self, partner_id: u64) -> Result<ListPartnerPKResponse, KeypairError> {
      return match self.repository.find_partner_keypairs(partner_id).await {
         Ok(v) => Ok(ListPartnerPKResponse {
            keys: v
               .into_iter()
               .map(|kp| PartnerPKResponse {
                  id: kp.id,
                  partner_id: kp.partner_id,
                  public_key: kp.public_key,
                  keypair_hash: kp.keypair_hash,
               })
               .collect(),
         }),
         Err(e) => Err(KeypairError::KeypairYabai(e.to_string())),
      };
   }

   async fn get_keypair_by_hash(&self, partner_id: u64, hash: String) -> Result<PartnerPKResponse, KeypairError> {
      if hash.is_empty() {
         return Err(KeypairError::KeypairInvalid);
      };

      return match self.repository.find_partner_keypair_by_hash(partner_id, hash).await {
         Ok(v) => Ok(PartnerPKResponse {
            id: v.id,
            partner_id: v.partner_id,
            public_key: v.public_key,
            keypair_hash: v.keypair_hash,
         }),
         Err(e) => Err(KeypairError::KeypairYabai(e.to_string())),
      };
   }



   async fn create_keypair(&self, payload: PartnerPKPayload) -> Result<PartnerPKResponse, KeypairError> {
      // !todo revamp keygen and actually encrypt those string
      let encoded_pk = general_purpose::STANDARD.encode(payload.public_key);
      let hashed = sha256::digest(encoded_pk.clone());

      let payload = PartnerKeyPair {
         id: 0,
         partner_id: payload.partner_id,
         public_key: encoded_pk,
         keypair_hash: hashed,
      };

      return match self.repository.insert_partner_keypair(payload.clone()).await {
         Ok(v) => Ok(PartnerPKResponse {
            id: v,
            partner_id: payload.partner_id,
            public_key: payload.public_key,
            keypair_hash: payload.keypair_hash,
         }),
         Err(e) => Err(KeypairError::KeypairCreationError(e.to_string())),
      };
   }

   async fn update_keypair(&self, payload: PartnerPKPayload) -> Option<KeypairError> {
      // !todo revamp keygen and actually encrypt those string
      let encoded_pk = general_purpose::STANDARD.encode(payload.public_key);
      let hashed = sha256::digest(encoded_pk.clone());

      let payload = PartnerKeyPair {
         id: payload.id,
         partner_id: payload.partner_id,
         public_key: encoded_pk,
         keypair_hash: hashed,
      };

      match self.repository.update_partner_keypair(payload.clone()).await {
         Some(e) => Some(KeypairError::KeypairYabai(e.to_string())),
         None => None,
      }
   }

   async fn delete_keypair(&self, hash: String) -> Option<KeypairError> {
      // !todo add existence check
      match self.repository.delete_partner_keypair(hash).await {
         Some(e) => return Some(KeypairError::KeypairYabai(e.to_string())),
         _ => None,
      }
   }

} 