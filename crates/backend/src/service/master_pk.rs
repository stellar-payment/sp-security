use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use async_trait::async_trait;

use p256::{SecretKey, PublicKey};
use uuid::Uuid;
use std::sync::Arc;

use crate::config::database::Database;
use crate::config::parameter::get;
use crate::dto::master_keypair::{ListMasterPKResponse, MasterPKResponse};
use crate::entity::security::MasterKeyPair;
use crate::error::db_error::DBError;
use crate::error::keypair_error::KeypairError;
use corelib;
use crate::repository::master_pk::{MasterPKRepository, MasterPKRepositoryTrait};
use rand_core::{OsRng, RngCore};
use data_encoding::BASE64;

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

   async fn get_keypairs(&self) -> Result<ListMasterPKResponse, KeypairError> {
      let keypairs = match self.repository.find_keypairs().await {
         Ok(v) => v,
         Err(e) => return Err(KeypairError::Yabai(e.to_string())),
      };

      let mut res = ListMasterPKResponse { keys: Vec::new() };

      for meta in keypairs {
         let decoded_key = BASE64.decode(get("DB_KEY").as_bytes()).map_err(|e| KeypairError::Yabai(format!("failed to decode key: {e}")))?;
         let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key); 
   
         let mut hashmsg = meta.public_key.clone();
         hashmsg.extend(meta.private_key.clone());
   
         corelib::security::hmac256_verify(get("HASH_KEY").as_bytes(), &hashmsg, &meta.keypair_hash)
            .map_err(|e| KeypairError::IntegrityCheckFailed(e.to_string()))?;
         
         let pk = corelib::security::aes256_decrypt(key, &meta.public_key)
            .map_err(|e| KeypairError::Yabai(e.to_string()))?;
         
         // validate key
         let _ = PublicKey::from_sec1_bytes(&pk).map_err(|e| KeypairError::IntegrityCheckFailed(e.to_string()))?;

         res.keys.push(MasterPKResponse{
            id: meta.id.into(),
            public_key: BASE64.encode(&pk),
            keypair_hash: BASE64.encode(&meta.keypair_hash)
         });
      }
      
      Ok(res)
   }

   async fn get_keypair_by_hash(&self, hash: String) -> Result<MasterPKResponse, KeypairError> {
      if hash.is_empty() {
         return Err(KeypairError::Invalid);
      };

      let meta = match self.repository.find_keypair_by_hash(BASE64.decode(hash.as_bytes()).map_err(|_e| KeypairError::Invalid)?).await {
         Ok(v) => v,
         Err(e) => match e {
            DBError::Yabaii(err) => return Err(KeypairError::Yabai(err)),
            DBError::NotFound => return Err(KeypairError::NotFound),
         },
      };

      let decoded_key = BASE64.decode(get("DB_KEY").as_bytes()).map_err(|e| KeypairError::Yabai(format!("failed to decode key: {e}")))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key); 

      let mut hashmsg = meta.public_key.clone();
      hashmsg.extend(meta.private_key.clone());

      corelib::security::hmac256_verify(get("HASH_KEY").as_bytes(), &hashmsg, &meta.keypair_hash)
         .map_err(|e| KeypairError::IntegrityCheckFailed(e.to_string()))?;
      
      let pk = corelib::security::aes256_decrypt(key, &meta.public_key)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let ppk = corelib::security::aes256_decrypt(key, &meta.private_key)
      .map_err(|e| KeypairError::Yabai(e.to_string()))?;


      // validate key
      let _ = SecretKey::from_slice(&ppk).map_err(|e| KeypairError::IntegrityCheckFailed(e.to_string()))?;
      let _ = PublicKey::from_sec1_bytes(&pk).map_err(|e| KeypairError::IntegrityCheckFailed(e.to_string()))?;

      Ok(MasterPKResponse {
         id: meta.id.to_string(),
         public_key: BASE64.encode(&pk),
         keypair_hash: BASE64.encode(&meta.keypair_hash),
      })
   }

   async fn create_keypair(&self) -> Result<MasterPKResponse, KeypairError> {
      let secret = SecretKey::random(&mut OsRng);
      let pk = secret.public_key().to_sec1_bytes();
      let ppk = secret.to_bytes();
      let mut iv = [0x24; 16];
      OsRng.fill_bytes(&mut iv);

      let decoded_key = BASE64.decode(get("DB_KEY").as_bytes()).map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key);

      let enc_secret = corelib::security::aes256_encrypt(key, &ppk.clone());
      let enc_pk = corelib::security::aes256_encrypt(key, &pk);

      let mut msg = enc_pk.clone();
      msg.extend(enc_secret.clone());
      let hashed = corelib::security::hmac256_hash(get("HASH_KEY").as_bytes(), &msg)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let payload = MasterKeyPair {
         id: Uuid::now_v7(),
         public_key: enc_pk,
         private_key: enc_secret,
         keypair_hash: hashed,
      };

      return match self.repository.insert_keypair(payload.clone()).await {
         Ok(v) => Ok(MasterPKResponse {
            id: v.to_string(),
            public_key: BASE64.encode(&payload.public_key),
            keypair_hash: BASE64.encode(&payload.keypair_hash)
         }),
         Err(e) => Err(KeypairError::CreationError(e.to_string())),
      };
   }

   async fn delete_keypair(&self, hash: String) -> Option<KeypairError> {
      let keypair = match self.repository.find_keypair_by_hash(BASE64.decode(hash.as_bytes()).unwrap()).await {
         Ok(v) => v,
         Err(e) => return Some(KeypairError::Yabai(e.to_string())),
      };

      match self.repository.delete_keypair(keypair.id).await {
         Some(e) => return Some(KeypairError::Yabai(e.to_string())),
         _ => None,
      }
   }
}
