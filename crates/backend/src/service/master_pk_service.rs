use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use async_trait::async_trait;
use base64::Engine;
use p256::SecretKey;
use std::sync::Arc;

use crate::config::database::Database;
use crate::config::parameter::get;
use crate::dto::master_keypair::{ListMasterPKResponse, MasterPKResponse};
use crate::entity::security::MasterKeyPair;
use crate::error::db_error::DBError;
use crate::error::keypair_error::KeypairError;
use corelib;
use crate::repository::master_pk_repository::{MasterPKRepository, MasterPKRepositoryTrait};
use base64::engine::general_purpose;
use rand_core::{OsRng, RngCore};

#[derive(Clone)]
pub struct MasterPKService {
   repository: MasterPKRepository,
}

#[async_trait]
pub trait MasterPKServiceTrait {
   fn new(db: &Arc<Database>) -> Self;
   async fn get_keypairs(&self) -> Result<ListMasterPKResponse, KeypairError>;
   async fn get_keypair_by_hash(&self, hash: String) -> Result<MasterPKResponse, KeypairError>;
   async fn create_keypair(&self) -> Result<MasterPKResponse, KeypairError>;
   // async fn update_keypair(&self, payload: MasterPKPayload) -> Option<KeypairError>;
   async fn delete_keypair(&self, hash: String) -> Option<KeypairError>;
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
         return Err(KeypairError::Invalid);
      };
      let meta = match self.repository.find_keypair_by_hash(hash).await {
         Ok(v) => v,
         Err(e) => match e {
            DBError::Yabaii(err) => return Err(KeypairError::Yabai(err)),
            DBError::NotFound => return Err(KeypairError::NotFound),
         },
      };

      let decoded_key = general_purpose::STANDARD.decode(get("DB_KEY")).map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key); 

      let (encoded_pk, encoded_pk_iv) = meta.public_key.split_once('.').unwrap_or_else(|| panic!("invalid structure"));
      let (encoded_ppk, encoded_ppk_iv) = meta.private_key.split_once('.').unwrap_or_else(|| panic!("invalid structure"));

      if encoded_pk_iv != encoded_ppk_iv {
         return Err(KeypairError::IntegrityCheckFailed("iv missmatch".to_string()));
      }

      let pk_iv = general_purpose::STANDARD.decode(encoded_pk_iv).map(|v| {
         let mut buf = [0u8; 16];
         buf[..16].copy_from_slice(&v);
         buf
      }).map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let pk_ct = general_purpose::STANDARD.decode(encoded_pk).map_err(|e| KeypairError::Yabai(e.to_string()))?;
      
      let ppk_iv = general_purpose::STANDARD.decode(encoded_ppk_iv).map(|v| {
         let mut buf = [0u8; 16];
         buf[..16].copy_from_slice(&v);
         buf
      }).map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let ppk_ct = general_purpose::STANDARD.decode(encoded_ppk).map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let mut msg = pk_ct.clone();
      msg.extend(ppk_ct.clone());
      msg.extend_from_slice(&pk_iv);

      let pk_hash = general_purpose::STANDARD.decode(meta.keypair_hash.clone()).map_err(|e| KeypairError::Yabai(e.to_string()))?;
      corelib::security::hmac256_verify(get("HASH_KEY").as_bytes(), &msg, &pk_hash)
         .map_err(|e| KeypairError::IntegrityCheckFailed(e.to_string()))?;

      let pk = corelib::security::aes256_decrypt(key, pk_iv, &pk_ct)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let ppk = corelib::security::aes256_decrypt(key, ppk_iv, &ppk_ct)
      .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      Ok(MasterPKResponse {
         id: meta.id,
         public_key: general_purpose::STANDARD.encode(pk),
         private_key: general_purpose::STANDARD.encode(ppk),
         keypair_hash: meta.keypair_hash,
      })
   }

   async fn get_keypairs(&self) -> Result<ListMasterPKResponse, KeypairError> {
      return match self.repository.find_keypairs().await {
         Ok(v) => Ok(ListMasterPKResponse {
            keys: v
               .into_iter()
               .map(|kp| MasterPKResponse {
                  id: kp.id,
                  public_key: kp.public_key,
                  private_key: kp.private_key,
                  keypair_hash: kp.keypair_hash,
               })
               .collect(),
         }),
         Err(e) => Err(KeypairError::Yabai(e.to_string())),
      };
   }

   async fn create_keypair(&self) -> Result<MasterPKResponse, KeypairError> {
      let secret = SecretKey::random(&mut OsRng);
      let pk = secret.public_key().to_sec1_bytes();
      let ppk = secret.to_bytes();
      let mut iv = [0x24; 16];
      OsRng.fill_bytes(&mut iv);

      let decoded_key = general_purpose::STANDARD.decode(get("DB_KEY")).map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key);

      let enc_secret = corelib::security::aes256_encrypt(key, iv, &ppk.clone());
      let enc_pk = corelib::security::aes256_encrypt(key, iv, &pk);

      let encoded_secret = general_purpose::STANDARD.encode(enc_secret.clone());
      let encoded_pk = general_purpose::STANDARD.encode(enc_pk.clone());
      let encoded_iv = general_purpose::STANDARD.encode(iv);

      let mut msg = enc_pk.clone();
      msg.extend(enc_secret.clone());
      msg.extend_from_slice(&iv);
      let hashed = corelib::security::hmac256_hash(get("HASH_KEY").as_bytes(), &msg)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let payload = MasterKeyPair {
         id: 0,
         public_key: format!("{}.{}", encoded_pk, encoded_iv),
         private_key: format!("{}.{}", encoded_secret, encoded_iv),
         keypair_hash: general_purpose::STANDARD.encode(hashed),
      };

      return match self.repository.insert_keypair(payload.clone()).await {
         Ok(v) => Ok(MasterPKResponse {
            id: v,
            public_key: payload.public_key,
            private_key: payload.private_key,
            keypair_hash: payload.keypair_hash,
         }),
         Err(e) => Err(KeypairError::CreationError(e.to_string())),
      };
   }

   async fn delete_keypair(&self, hash: String) -> Option<KeypairError> {
      let keypair = match self.repository.find_keypair_by_hash(hash).await {
         Ok(v) => v,
         Err(e) => return Some(KeypairError::Yabai(e.to_string())),
      };

      match self.repository.delete_keypair(keypair.id).await {
         Some(e) => return Some(KeypairError::Yabai(e.to_string())),
         _ => None,
      }
   }
}
