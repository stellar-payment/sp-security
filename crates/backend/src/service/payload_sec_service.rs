use std::sync::Arc;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use corelib::security::aes256_decrypt;
use corelib::{security, mapper};
use log::info;
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
      let decoded_key = general_purpose::STANDARD.decode(get("DB_KEY")).map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key); 

      let partner_data = self
         .partner_repository
         .find_partner_keypairs(payload.partner_id)
         .await.map_err(|e| SecurityError::GenericError(e.to_string()))?;
      
      let master_data = self.master_repository.find_keypair_by_id(9)
         .await.map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let (encoded_secret_key, encoded_iv_sk) = master_data.private_key.split_once('.').unwrap_or_else(|| panic!("invalid structure"));
      let (encoded_public_key, encoded_iv_pk) = partner_data.public_key.split_once('.').unwrap_or_else(|| panic!("invalid structure"));
      let (encoded_master_pk, encoded_mpk_iv) = master_data.public_key.split_once('.').unwrap_or_else(|| panic!("invalid structure"));

      let decoded_secret_key = general_purpose::STANDARD
         .decode(encoded_secret_key)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let iv_sk = general_purpose::STANDARD
         .decode(encoded_iv_sk)
         .map(mapper::vec_to_arr::<16>)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let dec_secret_key = aes256_decrypt(key, iv_sk, &decoded_secret_key).unwrap_or_else(|e| panic!("{e}"));
      let secret_key = SecretKey::from_slice(&dec_secret_key)
      .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      
      let decoded_public_key = general_purpose::STANDARD
      .decode(encoded_public_key)
      .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let iv_pk = general_purpose::STANDARD
      .decode(encoded_iv_pk)
      .map(mapper::vec_to_arr::<16>)
      .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let dec_public_key = aes256_decrypt(key, iv_pk, &decoded_public_key).unwrap_or_else(|e| panic!("{e}"));
      let public_key = PublicKey::from_sec1_bytes(&dec_public_key)
      .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let decoded_mpk = general_purpose::STANDARD
         .decode(encoded_master_pk)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let iv_mpk = general_purpose::STANDARD
         .decode(encoded_mpk_iv)
         .map(mapper::vec_to_arr::<16>)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let dec_mpk = aes256_decrypt(key, iv_mpk, &decoded_mpk).unwrap_or_else(|e| panic!("{e}"));

      let shared_secret = security::ecdh_generate_secret(secret_key, public_key);
      let secret_key = security::generate_shared_key(&shared_secret).map_err(SecurityError::from)?;

      let enc_key = &secret_key[0..32];
      let mac_key = &secret_key[32..64];
         
      println!("enc key: {} len: {}", general_purpose::STANDARD.encode(enc_key), enc_key.len());
      println!("mac key: {} len: {}", general_purpose::STANDARD.encode(mac_key), mac_key.len());
      println!("pk key: {} len: {}", general_purpose::STANDARD.encode(dec_public_key), mac_key.len());
      println!("sk key: {} len: {}", general_purpose::STANDARD.encode(dec_secret_key), mac_key.len());
   
      let mut iv = [0u8; 16];
      OsRng.fill_bytes(&mut iv);

      let data = general_purpose::STANDARD.decode(payload.data.as_bytes())
         .unwrap_or_else(|e| panic!("{e}"));
      let enc_key: GenericArray<u8, U32> = GenericArray::clone_from_slice(enc_key);
      let ct = security::aes256_encrypt(
         enc_key,
         iv,
         &data,
      );
      let mac = security::hmac512_hash(mac_key, &ct).map_err(SecurityError::from)?;

      Ok(EncryptDataResponse {
         data: format!(
            "{}.{}",
            general_purpose::STANDARD.encode(ct),
            general_purpose::STANDARD.encode(iv)
         ),
         tag: general_purpose::STANDARD.encode(mac),
         secret_key: general_purpose::STANDARD.encode(dec_mpk),
      })
   }

   async fn decrypt_payload(
      &self,
      payload: DecryptDataPayload,
   ) -> Result<DecryptDataResponse, SecurityError> {
      let master_data = match self.master_repository.find_keypair_by_hash(payload.keypair_hash).await {
         Ok(v) => v,
         Err(e) => {
            log::error!("{e}");
            return Err(SecurityError::GenericError(e.to_string()))
         },
      };

      let partner_data = match self
         .partner_repository
         .find_partner_keypairs(payload.partner_id)
         .await
      {
         Ok(v) => v,
         Err(e) => {
            log::error!("{e}");
            return Err(SecurityError::GenericError(e.to_string()))
         },
      };

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
