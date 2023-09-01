use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use rand_core::{OsRng, RngCore};
use std::sync::Arc;

use crate::config::database::Database;
use crate::config::parameter::get;
use crate::dto::partner_keypair::{ListPartnerPKResponse, PartnerPKPayload, PartnerPKResponse};
use crate::entity::security::PartnerKeyPair;
use crate::error::{db_error::DBError, keypair_error::KeypairError};
use corelib;
use crate::repository::partner_pk_repository::{PartnerPKRepository, PartnerPKRepositoryTrait};
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
   async fn get_keypair_by_hash(
      &self,
      partner_id: u64,
      hash: String,
   ) -> Result<PartnerPKResponse, KeypairError>;
   async fn create_keypair(
      &self,
      payload: PartnerPKPayload,
   ) -> Result<PartnerPKResponse, KeypairError>;
   async fn update_keypair(&self, payload: PartnerPKPayload) -> Result<(), KeypairError>;
   async fn delete_keypair(&self, partner_id: u64, hash: String) -> Result<(), KeypairError>;
}

#[async_trait]
impl PartnerPKServiceTrait for PartnerPKService {
   fn new(db: &Arc<Database>) -> Self {
      Self {
         repository: PartnerPKRepository::new(db),
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
         Err(e) => Err(KeypairError::Yabai(e.to_string())),
      };
   }

   async fn get_keypair_by_hash(
      &self,
      partner_id: u64,
      hash: String,
   ) -> Result<PartnerPKResponse, KeypairError> {
      if hash.is_empty() {
         return Err(KeypairError::Invalid);
      };

      let meta = match self.repository.find_partner_keypair_by_hash(hash).await {
         Ok(v) => PartnerPKResponse {
            id: v.id,
            partner_id: v.partner_id,
            public_key: v.public_key,
            keypair_hash: v.keypair_hash,
         },
         Err(_) => return Err(KeypairError::NotFound),
      };

      if meta.partner_id != partner_id {
         return Err(KeypairError::NoAccess)
      }

      let decoded_key = general_purpose::STANDARD.decode(get("DB_KEY")).map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key);
      let (encoded_pk, encoded_pk_iv) = meta.public_key.split_once('.').unwrap_or_else(|| panic!("invalid structure"));

      let pk_iv = general_purpose::STANDARD.decode(encoded_pk_iv).map(|v| {
         let mut buf = [0u8; 16];
         buf[..16].copy_from_slice(&v);
         buf
      }).map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let pk_ct = general_purpose::STANDARD.decode(encoded_pk).map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let mut msg = pk_ct.clone();
      msg.extend_from_slice(&pk_iv);

      let pk_hash = general_purpose::STANDARD.decode(meta.keypair_hash.clone()).map_err(|e| KeypairError::Yabai(e.to_string()))?;
      corelib::security::hmac256_verify(get("HASH_KEY").as_bytes(), &msg, &pk_hash)
         .map_err(|e| KeypairError::IntegrityCheckFailed(e.to_string()))?;


      let pk = corelib::security::aes256_decrypt(key, pk_iv, &pk_ct)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      Ok(PartnerPKResponse{
         id: meta.id,
         partner_id: meta.partner_id,
         public_key: String::from_utf8(pk).unwrap_or("".to_string()),
         keypair_hash: meta.keypair_hash,
      })
   }

   async fn create_keypair(
      &self,
      payload: PartnerPKPayload,
   ) -> Result<PartnerPKResponse, KeypairError> {
      let decoded_key = general_purpose::STANDARD.decode(get("DB_KEY")).map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key);

      let mut iv = [0u8; 16];
      OsRng.fill_bytes(&mut iv);

      let enc_pk = corelib::security::aes256_encrypt(key, iv, payload.public_key.as_bytes());
      let encoded_pk = general_purpose::STANDARD.encode(enc_pk.clone());
      let encoded_iv = general_purpose::STANDARD.encode(iv);
      
      let mut msg = enc_pk.clone();
      msg.extend_from_slice(&iv);
      let hashed = corelib::security::hmac256_hash(get("HASH_KEY").as_bytes(), &msg)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let payload = PartnerKeyPair {
         id: 0,
         partner_id: payload.partner_id,
         public_key: format!("{}.{}", encoded_pk, encoded_iv),
         keypair_hash: general_purpose::STANDARD.encode(hashed),
      };

      return match self
         .repository
         .insert_partner_keypair(payload.clone())
         .await
      {
         Ok(v) => Ok(PartnerPKResponse {
            id: v,
            partner_id: payload.partner_id,
            public_key: payload.public_key,
            keypair_hash: payload.keypair_hash,
         }),
         Err(e) => Err(KeypairError::CreationError(e.to_string())),
      };
   }

   async fn update_keypair(&self, payload: PartnerPKPayload) -> Result<(), KeypairError> {
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(get("DB_KEY").as_bytes());

      let mut iv = [0u8; 16];
      OsRng.fill_bytes(&mut iv);

      let enc_pk = corelib::security::aes256_encrypt(key, iv, payload.public_key.as_bytes());

      let encoded_pk = general_purpose::STANDARD.encode(enc_pk.clone());
      let encoded_iv = general_purpose::STANDARD.encode(iv);

      let mut msg = enc_pk.clone();
      msg.extend_from_slice(&iv);
      let hashed = corelib::security::hmac256_hash(get("HASH_KEY").as_bytes(), &msg)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let payload = PartnerKeyPair {
         id: payload.id,
         partner_id: payload.partner_id,
         public_key: format!("{}.{}", encoded_pk, encoded_iv),
         keypair_hash: general_purpose::STANDARD.encode(hashed),
      };

      match self
         .repository
         .update_partner_keypair(payload.clone())
         .await
      {
         Some(e) => Err(KeypairError::Yabai(e.to_string())),
         None => Ok(()),
      }
   }

   async fn delete_keypair(&self, partner_id: u64,  hash: String) -> Result<(), KeypairError> {
      let meta = match self.repository.find_partner_keypair_by_hash(hash.clone()).await {
         Ok(v) => v,
         Err(e) => {
            match e {
              DBError::Yabaii(m) => return Err(KeypairError::Yabai(m)),
              DBError::NotFound => return Err(KeypairError::NotFound),
           }
         }
      };

      if meta.partner_id != partner_id {
         return Err(KeypairError::NoAccess)
      }

      match self.repository.delete_partner_keypair(hash).await {
         Some(e) => return Err(KeypairError::Yabai(e.to_string())),
         _ => Ok(()),
      }
   }
}
