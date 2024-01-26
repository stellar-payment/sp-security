use std::sync::Arc;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use async_trait::async_trait;
use data_encoding::{BASE64, BASE64URL};
use corelib::security::aes256_decrypt;
use corelib::security;
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use uuid::Uuid;

use crate::config::cache::Cache;
use crate::config::database::Database;
use crate::config::parameter::get;
use crate::dto::master_keypair::MasterPKResponse;
use crate::dto::payload_sec::{DecryptDataPayload, DecryptDataResponse};
use crate::dto::payload_sec::{EncryptDataPayload, EncryptDataResponse};
use crate::entity::security::EphemeralMasterKeyPair;
use crate::error::db_error::DBError;
use crate::error::keypair_error::KeypairError;
use crate::error::security_error::SecurityError;
use crate::repository::master_epk::{MasterEPKRepository, MasterEPKRepositoryTrait};
use crate::repository::partner_pk::{PartnerPKRepository, PartnerPKRepositoryTrait};


#[derive(Clone)]
pub struct PayloadSecurityService {
   partner_repository: PartnerPKRepository,
   master_repository: MasterEPKRepository,
}

#[async_trait]
pub trait PayloadSecurityServiceTrait {
   fn new(db: &Arc<Database>, cache: Cache) -> Self;

   async fn encrypt_payload(
      &mut self,
      payload: EncryptDataPayload,
   ) -> Result<EncryptDataResponse, SecurityError>;
   async fn decrypt_payload(
      &mut self,
      payload: DecryptDataPayload,
   ) -> Result<DecryptDataResponse, SecurityError>;

   async fn get_keypair_by_hash(&mut self, hash: String) -> Result<MasterPKResponse, KeypairError>;
   async fn create_keypair(&mut self) -> Result<MasterPKResponse, KeypairError>;


   async fn _create_keypair(&mut self) -> Result<(SecretKey, String), KeypairError>;
   async fn _get_keypair_by_hash(&mut self, hash: String) -> Result<SecretKey, KeypairError>;
}

#[async_trait]
impl PayloadSecurityServiceTrait for PayloadSecurityService {
   fn new(db: &Arc<Database>, cache: Cache) -> Self {
      Self {
         partner_repository: PartnerPKRepository::new(db, cache.clone()),
         master_repository: MasterEPKRepository::new(cache),
      }
   }

   async fn encrypt_payload(
      &mut self,
      payload: EncryptDataPayload,
   ) -> Result<EncryptDataResponse, SecurityError> {
      let decoded_key = BASE64.decode(get("DB_KEY").as_bytes()).map_err(|e| SecurityError::GenericError(e.to_string()))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key); 

      let partner_data = self.partner_repository
         .find_partner_keypairs(Uuid::parse_str(&payload.partner_id).unwrap_or_else(|e|  panic!("invalid uuidv7: {e}"))).await
         .map_err(|e| SecurityError::GenericError(e.to_string()))?;
      
      let (secret_key, keyhash) = self._create_keypair()
         .await
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
         secret_key: keyhash,
      })
   }

   async fn decrypt_payload(
      &mut self,
      payload: DecryptDataPayload,
   ) -> Result<DecryptDataResponse, SecurityError> {
      let secret_key = match self._get_keypair_by_hash(payload.keypair_hash)
         .await
         {
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

   async fn _create_keypair(&mut self) -> Result<(SecretKey, String), KeypairError> {
      let secret = SecretKey::random(&mut OsRng);
      let pk = secret.public_key().to_sec1_bytes();
      let ppk = secret.to_bytes();
      let mut iv = [0x24; 16];
      OsRng.fill_bytes(&mut iv);

      // let decoded_key = BASE64.decode(get("DB_KEY").as_bytes()).map_err(|e| KeypairError::Yabai(e.to_string()))?;
      // let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key);

      // let enc_secret = corelib::security::aes256_encrypt(key, &ppk.clone());
      // let enc_pk = corelib::security::aes256_encrypt(key, &pk);

      // let mut msg = enc_pk.clone();
      // msg.extend(enc_secret.clone());
      // let hashed = corelib::security::hmac256_hash(get("HASH_KEY").as_bytes(), &msg)
      //    .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      // let payload = EphemeralMasterKeyPair {
      //    public_key: enc_pk,
      //    private_key: enc_secret,
      //    keypair_hash: BASE64URL.encode(&hashed),
      // };

      let mut msg = pk.clone().to_vec();
      msg.extend(ppk);

      let hashed = corelib::security::hmac256_hash(get("HASH_KEY").as_bytes(), &msg)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let payload = EphemeralMasterKeyPair {
         public_key: pk.to_vec(),
         private_key: ppk.to_vec(),
         keypair_hash: BASE64URL.encode(&hashed),
      };

      return match self.master_repository.insert_keypair(payload).await {
         Ok(()) => Ok((secret, BASE64URL.encode(&hashed))),
         Err(e) => Err(KeypairError::CreationError(e.to_string())),
      };
   }

   async fn _get_keypair_by_hash(&mut self, hash: String) -> Result<SecretKey, KeypairError> {
      if hash.is_empty() {
         return Err(KeypairError::Invalid);
      };

      let meta = match self.master_repository.find_keypair_by_hash(hash.clone()).await {
         Ok(v) => v,
         Err(e) => match e {
            DBError::Yabaii(err) => return Err(KeypairError::Yabai(err)),
            DBError::NotFound => return Err(KeypairError::NotFound),
         },
      };

      // let decoded_key = BASE64.decode(get("DB_KEY").as_bytes()).map_err(|e| KeypairError::Yabai(format!("failed to decode key: {e}")))?;
      // let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key); 

      // let mut hashmsg = meta.public_key.clone();
      // hashmsg.extend(meta.private_key.clone());
      
      // let sk = corelib::security::aes256_decrypt(key, &meta.private_key)
      // .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let sk = meta.private_key;

      // validate key
      let key = SecretKey::from_slice(&sk).map_err(|e| KeypairError::IntegrityCheckFailed(e.to_string()))?;
      Ok(key)
   }

   async fn get_keypair_by_hash(&mut self, hash: String) -> Result<MasterPKResponse, KeypairError> {
      if hash.is_empty() {
         return Err(KeypairError::Invalid);
      };

      let meta = match self.master_repository.find_keypair_by_hash(hash.clone()).await {
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
      
      let pk = corelib::security::aes256_decrypt(key, &meta.public_key)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let ppk = corelib::security::aes256_decrypt(key, &meta.private_key)
      .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      // validate key
      let _ = SecretKey::from_slice(&ppk).map_err(|e| KeypairError::IntegrityCheckFailed(e.to_string()))?;
      let _ = PublicKey::from_sec1_bytes(&pk).map_err(|e| KeypairError::IntegrityCheckFailed(e.to_string()))?;

      Ok(MasterPKResponse {
         id: String::default(),
         public_key: BASE64.encode(&pk),
         keypair_hash: hash,
      })
   }

   async fn create_keypair(&mut self) -> Result<MasterPKResponse, KeypairError> {
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

      let payload = EphemeralMasterKeyPair {
         public_key: enc_pk.clone(),
         private_key: enc_secret,
         keypair_hash: BASE64URL.encode(&hashed),
      };

      return match self.master_repository.insert_keypair(payload.clone()).await {
         Ok(()) => Ok(MasterPKResponse {
            id: String::default(),
            public_key: BASE64.encode(&pk),
            keypair_hash: BASE64URL.encode(&hashed)
         }),
         Err(e) => Err(KeypairError::CreationError(e.to_string())),
      };
   }
}
