use aes::cipher::block_padding::Pkcs7;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use aes::cipher::{BlockEncryptMut, KeyIvInit};
use base64::engine::GeneralPurpose;
use p256::ecdsa::signature::Keypair;
use rand_core::{OsRng, RngCore};
use std::sync::Arc;

use crate::config::database::Database;
use crate::config::parameter::get;
use crate::dto::partner_keypair::{ListPartnerPKResponse, PartnerPKPayload, PartnerPKResponse};
use crate::entity::security::PartnerKeyPair;
use crate::error::keypair_error::KeypairError;
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
   async fn delete_keypair(&self, hash: String) -> Result<(), KeypairError>;
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
         Err(e) => Err(KeypairError::KeypairYabai(e.to_string())),
      };
   }

   async fn get_keypair_by_hash(
      &self,
      partner_id: u64,
      hash: String,
   ) -> Result<PartnerPKResponse, KeypairError> {
      if hash.is_empty() {
         return Err(KeypairError::KeypairInvalid);
      };

      return match self
         .repository
         .find_partner_keypair_by_hash(partner_id, hash)
         .await
      {
         Ok(v) => Ok(PartnerPKResponse {
            id: v.id,
            partner_id: v.partner_id,
            public_key: v.public_key,
            keypair_hash: v.keypair_hash,
         }),
         Err(e) => Err(KeypairError::KeypairYabai(e.to_string())),
      };
   }

   async fn create_keypair(
      &self,
      payload: PartnerPKPayload,
   ) -> Result<PartnerPKResponse, KeypairError> {
      let key: GenericArray<u8, U32> =
         GenericArray::clone_from_slice(&general_purpose::STANDARD.decode(get("DB_KEY")).unwrap());

      let mut iv = [0u8; 16];
      OsRng.fill_bytes(&mut iv);

      let mut block = [0u8; 256];
      type Aes256Cbc = cbc::Encryptor<aes::Aes256>;

      block[..payload.public_key.len()].copy_from_slice(payload.public_key.as_bytes());
      let enc_pk = Aes256Cbc::new(&key.into(), &iv.into())
         .encrypt_padded_mut::<Pkcs7>(&mut block, payload.public_key.len())
         .map_err(|e| return KeypairError::KeypairCreationError(e.to_string()))?;

      let encoded_pk = general_purpose::STANDARD.encode(enc_pk);
      let encoded_iv = general_purpose::STANDARD.encode(iv);
      let hashed = sha256::digest(format!("{}|{}", encoded_pk, encoded_iv));

      let payload = PartnerKeyPair {
         id: 0,
         partner_id: payload.partner_id,
         public_key: format!("{}.{}", encoded_pk, encoded_iv),
         keypair_hash: hashed,
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
         Err(e) => Err(KeypairError::KeypairCreationError(e.to_string())),
      };
   }

   async fn update_keypair(&self, payload: PartnerPKPayload) -> Result<(), KeypairError> {
      let key: GenericArray<u8, U32> =
         GenericArray::clone_from_slice(&general_purpose::STANDARD.decode(get("DB_KEY")).unwrap());

      let mut iv = [0u8; 16];
      OsRng.fill_bytes(&mut iv);

      let mut block = [0u8; 256];
      type Aes256Cbc = cbc::Encryptor<aes::Aes256>;

      block[..payload.public_key.len()].copy_from_slice(payload.public_key.as_bytes());
      let enc_pk = Aes256Cbc::new(&key.into(), &iv.into())
         .encrypt_padded_mut::<Pkcs7>(&mut block, payload.public_key.len())
         .map_err(|e| return KeypairError::KeypairCreationError(e.to_string()))?;

      let encoded_pk = general_purpose::STANDARD.encode(enc_pk);
      let encoded_iv = general_purpose::STANDARD.encode(iv);
      let hashed = sha256::digest(format!("{}|{}", encoded_pk, encoded_iv));

      let payload = PartnerKeyPair {
         id: payload.id,
         partner_id: payload.partner_id,
         public_key: encoded_pk,
         keypair_hash: hashed,
      };

      match self
         .repository
         .update_partner_keypair(payload.clone())
         .await
      {
         Some(e) => Err(KeypairError::KeypairYabai(e.to_string())),
         None => Ok(()),
      }
   }

   async fn delete_keypair(&self, hash: String) -> Result<(), KeypairError> {
      match self.repository.delete_partner_keypair(hash).await {
         Some(e) => return Err(KeypairError::KeypairYabai(e.to_string())),
         _ => Ok(()),
      }
   }
}
