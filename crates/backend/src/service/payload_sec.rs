use std::sync::Arc;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use async_trait::async_trait;
use data_encoding::BASE64;
use corelib::security::aes256_decrypt;
use corelib::security;
use hkdf::Hkdf;
use log::info;
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use rand::seq::SliceRandom;
use uuid::Uuid;

use crate::config::database::Database;
use crate::config::parameter::get;
use crate::dto::payload_sec::{DecryptDataPayload, DecryptDataResponse};
use crate::dto::payload_sec::{EncryptDataPayload, EncryptDataResponse};
use crate::error::security_error::SecurityError;
use crate::repository::master_pk::{MasterPKRepository, MasterPKRepositoryTrait};
use crate::repository::partner_pk::{PartnerPKRepository, PartnerPKRepositoryTrait};


#[derive(Clone)]
pub struct PayloadSecurityService {
   partner_repository: PartnerPKRepository,
   master_repository: MasterPKRepository,
}

#[async_trait]
pub trait PayloadSecurityServiceTrait {
   fn new(db: &Arc<Database>) -> Self;

   async fn encrypt_payload(
      &self,
      payload: EncryptDataPayload,
   ) -> Result<EncryptDataResponse, SecurityError>;
   async fn decrypt_payload(
      &self,
      payload: DecryptDataPayload,
   ) -> Result<DecryptDataResponse, SecurityError>;
}

#[async_trait]
impl PayloadSecurityServiceTrait for PayloadSecurityService {
   fn new(db: &Arc<Database>) -> Self {
      Self {
         partner_repository: PartnerPKRepository::new(db),
         master_repository: MasterPKRepository::new(db),
      }
   }

   async fn encrypt_payload(
      &self,
      payload: EncryptDataPayload,
   ) -> Result<EncryptDataResponse, SecurityError> {
      let decoded_key = BASE64.decode(get("DB_KEY").as_bytes()).map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key); 

      let partner_data = self.partner_repository
         .find_partner_keypairs(Uuid::parse_str(&payload.partner_id).unwrap_or_else(|e|  panic!("invalid uuidv7: {e}"))).await
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      
      let master_keypair_list = self.master_repository.find_keypairs().await
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let master_data = master_keypair_list.choose(&mut OsRng)
         .ok_or(SecurityError::GenericError("no master key found".to_string()))?;

      let dec_secret_key = aes256_decrypt(key, &master_data.private_key).unwrap_or_else(|e| panic!("{e}"));
      let secret_key = SecretKey::from_slice(&dec_secret_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      
      let dec_public_key = aes256_decrypt(key, &partner_data.public_key).unwrap_or_else(|e| panic!("{e}"));
      let public_key = PublicKey::from_sec1_bytes(&dec_public_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let shared_secret = security::ecdh_generate_secret(secret_key, public_key);
      let (enc_key, mac_key) = security::generate_shared_key(&shared_secret).map_err(SecurityError::from)?;

      let data = BASE64.decode(payload.data.as_bytes())
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let enc_key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&enc_key);
      let (ct, iv) = security::aes256_iv_encrypt(enc_key, &data);
      let mac = security::hmac512_hash(&mac_key, &ct).map_err(SecurityError::from)?;

      Ok(EncryptDataResponse {
         data: format!("{}.{}", BASE64.encode(&ct) ,BASE64.encode(&iv)),
         tag: BASE64.encode(&mac),
         secret_key: BASE64.encode(&master_data.keypair_hash),
      })
   }

   async fn decrypt_payload(
      &self,
      payload: DecryptDataPayload,
   ) -> Result<DecryptDataResponse, SecurityError> {
      let master_data = match self.master_repository.find_keypair_by_hash(
         BASE64.decode(payload.keypair_hash.as_bytes()).
         map_err(|e| SecurityError::GenericError(e.to_string()))?
      ).await {
         Ok(v) => v,
         Err(e) => {
            log::error!("{e}");
            return Err(SecurityError::GenericError(e.to_string()))
         },
      };

      let partner_data = match self
         .partner_repository
         .find_partner_keypairs(Uuid::parse_str(&payload.partner_id).unwrap_or_else(|e|  panic!("invalid uuidv7: {e}")))
         .await
      {
         Ok(v) => v,
         Err(e) => {
            log::error!("{e}");
            return Err(SecurityError::GenericError(e.to_string()))
         },
      };

      let decoded_key = BASE64.decode(get("DB_KEY").as_bytes()).map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key); 

      let dec_secret_key = security::aes256_decrypt(key, &master_data.private_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      
      let secret_key = SecretKey::from_slice(&dec_secret_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let dec_public_key = security::aes256_decrypt(key, &partner_data.public_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let public_key = PublicKey::from_sec1_bytes(&dec_public_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let shared_secret = security::ecdh_generate_secret(secret_key, public_key);
      let (enc_key, mac_key) = security::generate_shared_key(&shared_secret).map_err(SecurityError::from)?;

      let (encoded_data, encoded_iv) = payload.data.split_once('.')
         .unwrap_or_else(|| panic!("invalid structure"));

      let ct = BASE64.decode(encoded_data.as_bytes())
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let tag = BASE64.decode(payload.tag.as_bytes())
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      security::hmac512_verify(&mac_key, &ct, &tag).map_err(SecurityError::from)?;

      let enc_key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&enc_key);
      let iv = BASE64.decode(encoded_iv.as_bytes())
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let ct = BASE64.decode(encoded_data.as_bytes())
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let pt = security::aes256_iv_decrypt(enc_key, &iv, &ct)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      Ok(DecryptDataResponse {
         data: BASE64.encode(&pt),
      })
   }
}
