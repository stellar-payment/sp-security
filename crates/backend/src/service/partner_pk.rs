use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use rand_core::{OsRng, RngCore};
use std::sync::Arc;
use uuid::Uuid;

use crate::config::database::Database;
use crate::config::parameter::get;
use crate::dto::partner_keypair::{PartnerPKPayload, PartnerPKResponse};
use crate::entity::security::PartnerKeyPair;
use crate::error::{db_error::DBError, keypair_error::KeypairError};
use crate::repository::partner_pk::{PartnerPKRepository, PartnerPKRepositoryTrait};
use async_trait::async_trait;
use corelib::security;
use data_encoding::{BASE64, BASE64URL};

#[derive(Clone)]
pub struct PartnerPKService {
   repository: PartnerPKRepository,
}

#[async_trait]
pub trait PartnerPKServiceTrait {
   fn new(db: &Arc<Database>) -> Self;

   async fn get_keypairs(&self, partner_id: String) -> Result<PartnerPKResponse, KeypairError>;
   async fn get_keypair_by_hash(
      &self,
      partner_id: String,
      hash: String,
   ) -> Result<PartnerPKResponse, KeypairError>;
   async fn create_keypair(
      &self,
      payload: PartnerPKPayload,
   ) -> Result<PartnerPKResponse, KeypairError>;
   async fn update_keypair(&self, payload: PartnerPKPayload) -> Result<(), KeypairError>;
   async fn delete_keypair(&self, partner_id: String, hash: String) -> Result<(), KeypairError>;
}

#[async_trait]
impl PartnerPKServiceTrait for PartnerPKService {
   fn new(db: &Arc<Database>) -> Self {
      Self {
         repository: PartnerPKRepository::new(db),
      }
   }

   async fn get_keypairs(&self, partner_id: String) -> Result<PartnerPKResponse, KeypairError> {
      let meta = match self.repository.find_partner_keypairs(Uuid::parse_str(&partner_id).unwrap_or_else(|e|  panic!("invalid uuidv7: {e}"))).await {
         Ok(v) => v,
         Err(e) => return Err(KeypairError::Yabai(e.to_string())),
      };

      let decoded_key = BASE64.decode(get("DB_KEY").as_bytes()).map_err(|e| KeypairError::Yabai(format!("failed to decode key: {e}")))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key); 

      corelib::security::hmac256_verify(get("HASH_KEY").as_bytes(), &meta.public_key, &meta.keypair_hash)
         .map_err(|e| KeypairError::IntegrityCheckFailed(e.to_string()))?;
      
      let pk = corelib::security::aes256_decrypt(key, &meta.public_key)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      Ok(PartnerPKResponse{
         id: meta.id.into(),
         partner_id: meta.partner_id.into(),
         public_key: BASE64.encode(&pk),
         keypair_hash: BASE64URL.encode(&meta.keypair_hash),
      })

   }

   async fn get_keypair_by_hash(
      &self,
      partner_id: String,
      hash: String,
   ) -> Result<PartnerPKResponse, KeypairError> {
      if hash.is_empty() {
         return Err(KeypairError::Invalid);
      };

      let meta = match self.repository.find_partner_keypair_by_hash(hash).await {
         Ok(v) => v,
         Err(_) => return Err(KeypairError::NotFound),
      };

      if meta.partner_id.to_string() != partner_id {
         return Err(KeypairError::NoAccess);
      }

      let decoded_key = BASE64.decode(get("DB_KEY").as_bytes())
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key);
   
      security::hmac256_verify(get("HASH_KEY").as_bytes(), &meta.public_key, &meta.keypair_hash)
         .map_err(|e| KeypairError::IntegrityCheckFailed(e.to_string()))?;

      let pk = security::aes256_decrypt(key, &meta.public_key)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;


      Ok(PartnerPKResponse {
         id: meta.id.into(),
         partner_id: meta.partner_id.into(),
         public_key: BASE64.encode(&pk),
         keypair_hash: BASE64URL.encode(&meta.keypair_hash),
      })
   }

   async fn create_keypair(
      &self,
      payload: PartnerPKPayload,
   ) -> Result<PartnerPKResponse, KeypairError> {
      match self.repository.find_partner_keypairs(Uuid::parse_str(&payload.partner_id).unwrap_or_else(|e|  panic!("invalid uuidv7: {e}"))).await {
         Ok(_) => return Err(KeypairError::CreationError("keypair already exists".to_string())),
         Err(v) => match v {
            DBError::Yabaii(e) => return Err(KeypairError::Yabai(e)),
            DBError::NotFound => (),
         },
      }

      let decoded_key = BASE64
         .decode(get("DB_KEY").as_bytes())
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key);

      let mut iv = [0u8; 16];
      OsRng.fill_bytes(&mut iv);

      let public_key = BASE64.decode(payload.public_key.as_bytes())
         .map_err(|e| KeypairError::CreationError(e.to_string()))?;

      let enc_pk = security::aes256_encrypt(key, &public_key);

      let hashed = security::hmac256_hash(get("HASH_KEY").as_bytes(), &enc_pk)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let payload = PartnerKeyPair {
         id: Uuid::now_v7(),
         partner_id: Uuid::parse_str(&payload.partner_id).unwrap_or_else(|e|  panic!("invalid uuidv7: {e}")),
         public_key: enc_pk,
         keypair_hash: hashed,
      };

      return match self
         .repository
         .insert_partner_keypair(payload.clone())
         .await
      {
         Ok(v) => Ok(PartnerPKResponse {
            id: v.to_string(),
            partner_id: payload.partner_id.to_string(),
            public_key: BASE64.encode(&payload.public_key),
            keypair_hash: BASE64URL.encode(&payload.keypair_hash),
         }),
         Err(e) => Err(KeypairError::CreationError(e.to_string())),
      };
   }

   async fn update_keypair(&self, payload: PartnerPKPayload) -> Result<(), KeypairError> {
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(get("DB_KEY").as_bytes());

      let public_key = BASE64.decode(payload.public_key.as_bytes())
      .map_err(|e| KeypairError::CreationError(e.to_string()))?;

      let enc_pk = security::aes256_encrypt(key, &public_key);

      let hashed = security::hmac256_hash(get("HASH_KEY").as_bytes(), &enc_pk)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let payload = PartnerKeyPair {
         id: Uuid::parse_str(&payload.id).unwrap_or_else(|e|  panic!("invalid uuidv7: {e}")),
         partner_id: Uuid::parse_str(&payload.partner_id).unwrap_or_else(|e|  panic!("invalid uuidv7: {e}")),
         public_key: enc_pk,
         keypair_hash: hashed,
      };

      match self.repository.update_partner_keypair(payload.clone()).await {
         Some(e) => Err(KeypairError::Yabai(e.to_string())),
         None => Ok(()),
      }
   }

   async fn delete_keypair(&self, partner_id: String, hash: String) -> Result<(), KeypairError> {
      let meta = match self.repository.find_partner_keypair_by_hash(hash.clone()).await {
         Ok(v) => v,
         Err(e) => match e {
            DBError::Yabaii(m) => return Err(KeypairError::Yabai(m)),
            DBError::NotFound => return Err(KeypairError::NotFound),
         },
      };

      if meta.partner_id.to_string() != partner_id {
         return Err(KeypairError::NoAccess);
      }

      match self.repository.delete_partner_keypair(hash).await {
         Some(e) => return Err(KeypairError::Yabai(e.to_string())),
         _ => Ok(()),
      }
   }
}
