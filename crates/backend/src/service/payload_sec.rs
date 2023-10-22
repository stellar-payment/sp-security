use std::sync::Arc;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use async_trait::async_trait;
use data_encoding::BASE64;
use corelib::security::aes256_decrypt;
use corelib::{security, mapper};
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
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

      let partner_data = self
         .partner_repository
         .find_partner_keypairs(Uuid::parse_str(&payload.partner_id).unwrap_or_else(|e|  panic!("invalid uuidv7: {e}")))
         .await.map_err(|e| SecurityError::GenericError(e.to_string()))?;
      
      let master_data = self.master_repository.find_keypair_by_id(Uuid::parse_str(&payload.partner_id).unwrap_or_else(|e|  panic!("invalid uuidv7: {e}")))
         .await.map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let (encoded_secret_key, encoded_iv_sk) = master_data.private_key.split_once('.').unwrap_or_else(|| panic!("invalid structure"));
      let (encoded_public_key, encoded_iv_pk) = partner_data.public_key.split_once('.').unwrap_or_else(|| panic!("invalid structure"));
      let (encoded_master_pk, encoded_mpk_iv) = master_data.public_key.split_once('.').unwrap_or_else(|| panic!("invalid structure"));

      let decoded_secret_key = BASE64.decode(encoded_secret_key.as_bytes()).map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let iv_sk = BASE64.decode(encoded_iv_sk.as_bytes())
         .map(mapper::vec_to_arr::<16>)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let dec_secret_key = aes256_decrypt(key, iv_sk, &decoded_secret_key).unwrap_or_else(|e| panic!("{e}"));
      let secret_key = SecretKey::from_slice(&dec_secret_key)
      .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      
      let decoded_public_key = BASE64.decode(encoded_public_key.as_bytes())
      .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let iv_pk = BASE64.decode(encoded_iv_pk.as_bytes())
      .map(mapper::vec_to_arr::<16>)
      .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let dec_public_key = aes256_decrypt(key, iv_pk, &decoded_public_key).unwrap_or_else(|e| panic!("{e}"));
      let public_key = PublicKey::from_sec1_bytes(&dec_public_key)
      .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let decoded_mpk = BASE64.decode(encoded_master_pk.as_bytes())
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let iv_mpk = BASE64.decode(encoded_mpk_iv.as_bytes())
         .map(mapper::vec_to_arr::<16>)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let dec_mpk = aes256_decrypt(key, iv_mpk, &decoded_mpk).unwrap_or_else(|e| panic!("{e}"));

      let shared_secret = security::ecdh_generate_secret(secret_key, public_key);
      let secret_key = security::generate_shared_key(&shared_secret).map_err(SecurityError::from)?;

      let enc_key = &secret_key[0..32];
      let mac_key = &secret_key[32..64];
            
      let mut iv = [0u8; 16];
      OsRng.fill_bytes(&mut iv);

      let data = BASE64.decode(payload.data.as_bytes())
         .unwrap_or_else(|e| panic!("{e}"));
      let enc_key: GenericArray<u8, U32> = GenericArray::clone_from_slice(enc_key);
      let ct = security::aes256_encrypt(
         enc_key,
         iv,
         &data,
      );
      let mac = security::hmac512_hash(mac_key, &ct).map_err(SecurityError::from)?;

      Ok(EncryptDataResponse {
         data: format!("{}.{}", BASE64.encode(&ct) ,BASE64.encode(&iv)),
         tag: BASE64.encode(&mac),
         secret_key: BASE64.encode(&dec_mpk),
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

      let (encoded_private_key, encoded_ppk_iv) = master_data.private_key.split_once('.').unwrap_or_else(|| panic!("invalid structure"));
      let (encoded_public_key, encoded_pk_iv) = partner_data.public_key.split_once('.').unwrap_or_else(|| panic!("invalid structure"));

      let ppk_iv = BASE64.decode(encoded_ppk_iv.as_bytes())
         .map(mapper::vec_to_arr::<16>)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let enc_private_key = BASE64.decode(encoded_private_key.as_bytes())
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      let pk_iv = BASE64.decode(encoded_pk_iv.as_bytes())
         .map(mapper::vec_to_arr::<16>)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let enc_public_key = BASE64.decode(encoded_public_key.as_bytes())
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

      let ct = BASE64.decode(encoded_data.as_bytes())
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let tag = BASE64.decode(payload.tag.as_bytes())
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let mtag = security::hmac512_hash(mac_key, &ct).map_err(SecurityError::from)?;

      security::hmac512_verify(mac_key, &ct, &mtag).map_err(SecurityError::from)?;
      security::hmac512_verify(mac_key, &ct, &tag).map_err(SecurityError::from)?;

      let enc_key: GenericArray<u8, U32> = GenericArray::clone_from_slice(enc_key);
      let iv = BASE64.decode(encoded_iv.as_bytes())
         .map(mapper::vec_to_arr::<16>)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let ct = BASE64.decode(encoded_data.as_bytes())
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let pt = security::aes256_decrypt(enc_key, iv, &ct)
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;

      Ok(DecryptDataResponse {
         data: BASE64.encode(&pt),
      })
   }
}
