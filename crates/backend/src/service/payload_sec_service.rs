use std::sync::Arc;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use corelib::{security, mapper};
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};

use crate::config::database::Database;
use crate::config::parameter::get;
use crate::dto::payload_sec::{DecryptDataPayload, DecryptDataResponse};
use crate::dto::payload_sec::{EncryptDataPayload, EncryptDataResponse};
use crate::error::security_error::SecurityError;
use crate::repository::master_pk_repository::{MasterPKRepository, MasterPKRepositoryTrait};
use crate::repository::partner_pk_repository::{PartnerPKRepository, PartnerPKRepositoryTrait};


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

      let shared_secret = security::ecdh_generate_secret(secret_key, public_key);
      let enc_key = security::generate_shared_key(&shared_secret).map_err(SecurityError::from)?;
      let mac_key = security::generate_shared_key(&shared_secret).map_err(SecurityError::from)?;

      let mut iv = [0u8; 16];
      OsRng.fill_bytes(&mut iv);

      let ct = security::aes256_encrypt(
         GenericArray::clone_from_slice(&enc_key),
         iv,
         payload.data.as_bytes(),
      );
      let mac = security::hmac512_hash(&mac_key, &ct).map_err(SecurityError::from)?;

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
      let master_data = match self.master_repository.find_keypair_by_id(9).await {
         Ok(v) => v,
         Err(e) => {
            log::error!("{e}");
            return Err(SecurityError::GenericError(e.to_string()))
         },
      };

      let partner_data = match self
         .partner_repository
         .find_partner_keypair_by_id(payload.partner_id)
         .await
      {
         Ok(v) => v,
         Err(e) => {
            log::error!("{e}");
            return Err(SecurityError::GenericError(e.to_string()))
         },
      };

      println!("PHash: {}", partner_data.keypair_hash);
      println!("MHash: {}", master_data.keypair_hash);

      let decoded_key = general_purpose::STANDARD.decode(get("DB_KEY")).map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key); 

      let (encoded_private_key, encoded_ppk_iv) = master_data.private_key.split_once('.').unwrap_or_else(|| panic!("invalid structure"));
      let (encoded_public_key, encoded_pk_iv) = partner_data.public_key.split_once('.').unwrap_or_else(|| panic!("invalid structure"));

      let ppk_iv = general_purpose::STANDARD
         .decode(encoded_ppk_iv)
         .map(mapper::vec_to_arr::<16>)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let enc_private_key = general_purpose::STANDARD.decode(encoded_private_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let pk_iv = general_purpose::STANDARD
         .decode(encoded_pk_iv)
         .map(mapper::vec_to_arr::<16>)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let enc_public_key = general_purpose::STANDARD
         .decode(encoded_public_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let dec_secret_key = security::aes256_decrypt(key, ppk_iv, &enc_private_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      
      let secret_key = SecretKey::from_slice(&dec_secret_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let dec_public_key = security::aes256_decrypt(key, pk_iv, &enc_public_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let public_key = PublicKey::from_sec1_bytes(&dec_public_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let shared_secret = security::ecdh_generate_secret(secret_key, public_key);
      let secret_key = security::generate_shared_key(&shared_secret).map_err(SecurityError::from)?;

      let enc_key = &secret_key[0..32];
      let mac_key = &secret_key[32..64];
      
      println!("enc key: {}", general_purpose::STANDARD.encode(enc_key));
      println!("mac key: {}", general_purpose::STANDARD.encode(mac_key));

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
      let mtag = security::hmac512_hash(mac_key, &ct).map_err(SecurityError::from)?;

      println!("mtag: {}", general_purpose::STANDARD.encode(mtag.clone()));
      security::hmac512_verify(mac_key, &ct, &mtag).map_err(SecurityError::from)?;
      security::hmac512_verify(mac_key, &ct, &tag).map_err(SecurityError::from)?;

      let enc_key: GenericArray<u8, U32> = GenericArray::clone_from_slice(enc_key);
      let iv = general_purpose::STANDARD
         .decode(encoded_iv)
         .map(mapper::vec_to_arr::<16>)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let ct = general_purpose::STANDARD.decode(encoded_data)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let pt = security::aes256_decrypt(enc_key, iv, &ct)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      Ok(DecryptDataResponse {
         data: general_purpose::STANDARD.encode(pt),
      })
   }
}
