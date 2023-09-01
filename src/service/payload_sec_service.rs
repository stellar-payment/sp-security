use std::sync::Arc;

use aes::cipher::generic_array::GenericArray;
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};

use crate::config::database::Database;
use crate::dto::payload_sec::{DecryptDataPayload, DecryptDataResponse};
use crate::dto::payload_sec::{EncryptDataPayload, EncryptDataResponse};
use crate::error::security_error::SecurityError;
use crate::repository::master_pk_repository::{MasterPKRepository, MasterPKRepositoryTrait};
use crate::repository::partner_pk_repository::{PartnerPKRepository, PartnerPKRepositoryTrait};
use corelib;

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
      let partner_data = match self
         .partner_repository
         .find_partner_keypair_by_id(payload.partner_id)
         .await
      {
         Ok(v) => v,
         Err(e) => return Err(SecurityError::GenericError(e.to_string())),
      };

      let master_data = match self.master_repository.find_keypair_by_id(1).await {
         Ok(v) => v,
         Err(e) => return Err(SecurityError::GenericError(e.to_string())),
      };

      let decoded_secret_key = general_purpose::STANDARD
         .decode(master_data.private_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let secret_key = SecretKey::from_slice(&decoded_secret_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let decoded_public_key = general_purpose::STANDARD
         .decode(partner_data.public_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let public_key = PublicKey::from_sec1_bytes(&decoded_public_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let shared_secret = corelib::security::ecdh_generate_secret(secret_key, public_key);
      let enc_key = corelib::security::generate_shared_key(&shared_secret).map_err(SecurityError::from)?;
      let mac_key = corelib::security::generate_shared_key(&shared_secret).map_err(SecurityError::from)?;

      let mut iv = [0u8; 16];
      OsRng.fill_bytes(&mut iv);

      let ct = corelib::security::aes256_encrypt(
         GenericArray::clone_from_slice(&enc_key),
         iv,
         payload.data.as_bytes(),
      );
      let mac = corelib::security::hmac512_hash(&mac_key, &ct).map_err(SecurityError::from)?;

      Ok(EncryptDataResponse {
         data: format!(
            "{}.{}",
            general_purpose::STANDARD.encode(ct),
            general_purpose::STANDARD.encode(iv)
         ),
         tag: general_purpose::STANDARD.encode(mac),
         secret_key: master_data.public_key,
      })
   }

   async fn decrypt_payload(
      &self,
      payload: DecryptDataPayload,
   ) -> Result<DecryptDataResponse, SecurityError> {
      let master_data = match self.master_repository.find_keypair_by_id(1).await {
         Ok(v) => v,
         Err(e) => return Err(SecurityError::GenericError(e.to_string())),
      };

      let partner_data = match self
         .partner_repository
         .find_partner_keypair_by_id(payload.partner_id)
         .await
      {
         Ok(v) => v,
         Err(e) => return Err(SecurityError::GenericError(e.to_string())),
      };

      let decoded_secret_key = general_purpose::STANDARD
         .decode(master_data.private_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let secret_key = SecretKey::from_slice(&decoded_secret_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let decoded_public_key = general_purpose::STANDARD
         .decode(partner_data.public_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let public_key = PublicKey::from_sec1_bytes(&decoded_public_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let shared_secret = corelib::security::ecdh_generate_secret(secret_key, public_key);
      let enc_key = corelib::security::generate_shared_key(&shared_secret).map_err(SecurityError::from)?;
      let mac_key = corelib::security::generate_shared_key(&shared_secret).map_err(SecurityError::from)?;

      let (encoded_data, encoded_iv) = payload
         .data
         .split_once('.')
         .unwrap_or_else(|| panic!("invalid structure"));

      let ct = general_purpose::STANDARD
         .decode(encoded_data)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let tag = general_purpose::STANDARD
         .decode(payload.tag)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      corelib::security::hmac512_verify(&mac_key, &ct, &tag).map_err(SecurityError::from)?;

      let iv = general_purpose::STANDARD
         .decode(encoded_iv)
         .map(|v| {
            let mut buf = [0u8; 16];
            buf[..16].copy_from_slice(&v);
            buf
         })
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let ct = corelib::security::aes256_decrypt(
         GenericArray::clone_from_slice(&enc_key),
         iv,
         payload.data.as_bytes(),
      )
      .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      Ok(DecryptDataResponse {
         data: general_purpose::STANDARD.encode(ct),
      })
   }
}
