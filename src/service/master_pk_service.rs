use aes::cipher::block_padding::Pkcs7;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use aes::cipher::{BlockEncryptMut, KeyIvInit};
use async_trait::async_trait;
use base64::Engine;
use p256::SecretKey;
use std::sync::Arc;

use crate::config::database::Database;
use crate::config::parameter::get;
use crate::dto::master_keypair::{ListMasterPKResponse, MasterPKResponse};
use crate::entity::security::MasterKeyPair;
use crate::error::keypair_error::KeypairError;
use crate::repository::master_pk_repository::{MasterPKRepository, MasterPKRepositoryTrait};
use base64::{engine::general_purpose, Engine as _};
use rand_core::OsRng;
use sha256;

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
         return Err(KeypairError::KeypairInvalid);
      };

      return match self.repository.find_keypair_by_hash(hash).await {
         Ok(v) => Ok(MasterPKResponse {
            id: v.id,
            public_key: v.public_key,
            private_key: v.private_key,
            keypair_hash: v.keypair_hash,
         }),
         Err(e) => Err(KeypairError::KeypairYabai(e.to_string())),
      };
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
         Err(e) => Err(KeypairError::KeypairYabai(e.to_string())),
      };
   }

   async fn create_keypair(&self) -> Result<MasterPKResponse, KeypairError> {
      let secret = SecretKey::random(&mut OsRng);

      let pk = secret.public_key().to_sec1_bytes();
      let ppk = secret.to_bytes();

      let key: GenericArray<u8, U32> =
         GenericArray::clone_from_slice(&general_purpose::STANDARD.decode(get("DB_KEY")).unwrap());
      let iv = [0x24; 16];
      let key_len = key.len();

      let mut ppk_block = [0u8; 256];
      type Aes256Cbc = cbc::Encryptor<aes::Aes256>;

      ppk_block[..ppk.len()].copy_from_slice(&ppk);
      let enc_secret = Aes256Cbc::new(&key.into(), &iv.into())
         .encrypt_padded_mut::<Pkcs7>(&mut ppk_block, ppk.len())
         .map_err(|e| return KeypairError::KeypairCreationError(e.to_string()))?;

      let mut pk_block = [0u8; 256];
      pk_block[..pk.len()].copy_from_slice(&pk);
      let enc_pk = Aes256Cbc::new(&key.into(), &iv.into())
         .encrypt_padded_mut::<Pkcs7>(&mut pk_block, pk.len())
         .map_err(|e| return KeypairError::KeypairCreationError(e.to_string()))?;

      let encoded_secret = general_purpose::STANDARD.encode(enc_secret);
      let encoded_pk = general_purpose::STANDARD.encode(enc_pk);
      let hashed = sha256::digest(format!("{}|{}", encoded_secret, encoded_pk));

      let payload = MasterKeyPair {
         id: 0,
         public_key: encoded_pk,
         private_key: encoded_secret,
         keypair_hash: hashed,
      };

      return match self.repository.insert_keypair(payload.clone()).await {
         Ok(v) => Ok(MasterPKResponse {
            id: v,
            public_key: payload.public_key,
            private_key: payload.private_key,
            keypair_hash: payload.keypair_hash,
         }),
         Err(e) => Err(KeypairError::KeypairCreationError(e.to_string())),
      };
   }

   async fn delete_keypair(&self, hash: String) -> Option<KeypairError> {
      let keypair = match self.repository.find_keypair_by_hash(hash).await {
         Ok(v) => v,
         Err(e) => return Some(KeypairError::KeypairYabai(e.to_string())),
      };

      match self.repository.delete_keypair(keypair.id).await {
         Some(e) => return Some(KeypairError::KeypairYabai(e.to_string())),
         _ => None,
      }
   }
}
