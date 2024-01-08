use core::panic;
use std::sync::Arc;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use async_trait::async_trait;
use corelib::security;
use data_encoding::{BASE64, BASE64URL};
use uuid::Uuid;

use crate::config::database::Database;
use crate::config::parameter::get;
use crate::dto::partner::{ListPartnerResponse, BriefPartnerResponse, PartnerPayload, PartnerResponse};
use crate::entity::partner::Partner;
use crate::error::db_error::DBError;
use crate::error::keypair_error::KeypairError;
use crate::repository::partner::{PartnerRepository, PartnerRepositoryTrait};

#[derive(Clone)]
pub struct PartnerService {
   repository: PartnerRepository,
}

#[async_trait]
pub trait PartnerServiceTrait {
   fn new(db: &Arc<Database>) -> Self;

   async fn get_partners(&self) -> Result<ListPartnerResponse, KeypairError>;
   async fn get_partner_by_id(&self, id: String) -> Result<PartnerResponse, KeypairError>;
   async fn create_partner(&self, payload: PartnerPayload) -> Result<PartnerResponse, KeypairError>;
   async fn update_partner(&self, payload: PartnerPayload) -> Result<(), KeypairError>;
   async fn delete_partner(&self, partner_id: String) -> Result<(), KeypairError>;
}

#[async_trait]
impl PartnerServiceTrait for PartnerService {
   fn new(db: &Arc<Database>) -> Self {
      Self {
         repository: PartnerRepository::new(db),
      }
   }

   async fn get_partners(&self) -> Result<ListPartnerResponse, KeypairError> {
      match self.repository.find_partners().await {
         Ok(v) => Ok(ListPartnerResponse { 
            partners: v.into_iter().map(|meta| BriefPartnerResponse { 
               id: meta.id.to_string(), 
               name: meta.name, 
               address: meta.address, 
               phone: meta.phone, 
               email: meta.email, 
            }).collect() 
         }),
         Err(e) => Err(KeypairError::Yabai(e.to_string())),
      }
   }

   async fn get_partner_by_id(&self, id: String) -> Result<PartnerResponse, KeypairError> {
      if id.is_empty() {
         return Err(KeypairError::Invalid);
      }

      let meta = match self.repository.find_partner_by_id(Uuid::parse_str(&id).unwrap_or_else(|_| panic!("invalid uuidv7"))).await {
         Ok(v) => v,
         Err(e) => match e {
            DBError::Yabaii(err) => return Err(KeypairError::Yabai(err)),
            DBError::NotFound => return Err(KeypairError::NotFound),
         },
      };

      let decoded_key = BASE64.decode(get("DB_KEY").as_bytes())
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key);

      let secret = security::aes256_decrypt(key, &meta.partner_secret).map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let pic_name = security::aes256_decrypt(key, &meta.pic_name).map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let pic_email = security::aes256_decrypt(key, &meta.pic_email).map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let pic_phone = security::aes256_decrypt(key, &meta.pic_phone).map_err(|e| KeypairError::Yabai(e.to_string()))?;

      Ok(PartnerResponse {
         id: meta.id.to_string(),
         name: meta.name,
         address: meta.address,
         phone: meta.phone,
         email: meta.email,
         pic_name: String::from_utf8(pic_name).unwrap_or_else(|_| panic!("invalid string")),
         pic_email: String::from_utf8(pic_email).unwrap_or_else(|_| panic!("invalid string")),
         pic_phone: String::from_utf8(pic_phone).unwrap_or_else(|_| panic!("invalid string")),
         partner_secret: String::from_utf8(secret).unwrap_or_else(|_| panic!("invalid string")),
      })
   }

   async fn create_partner(&self, payload: PartnerPayload) -> Result<PartnerResponse, KeypairError> {
      if payload.partner_secret.is_empty() {
         return Err(KeypairError::CreationError(
            "secret cannot empty".to_string(),
         ));
      }

      let decoded_key = BASE64.decode(get("DB_KEY").as_bytes())
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key);

      let secret = security::aes256_encrypt(key, payload.partner_secret.as_bytes());
      let pic_name = security::aes256_encrypt(key, payload.pic_name.as_bytes());
      let pic_email = security::aes256_encrypt(key, payload.pic_email.as_bytes());
      let pic_phone = security::aes256_encrypt(key, payload.pic_phone.as_bytes());
      
      let mut msg = secret.clone();
      msg.extend(pic_name.clone());
      msg.extend(pic_email.clone());
      msg.extend(pic_phone.clone());

      let hashed = security::hmac256_hash(get("HASH_KEY").as_bytes(), &msg)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let data = Partner {
         id: Uuid::now_v7(),
         name: payload.name,
         address: payload.address,
         phone: payload.phone,
         email: payload.email,
         pic_name: secret,
         pic_email: pic_name,
         pic_phone: pic_email,
         partner_secret: pic_phone,
         row_hash: hashed,
      };

      return match self.repository.insert_partner(data.clone()).await {
         Ok(v) => Ok(PartnerResponse {
            id: v.to_string(),
            name: data.name,
            address: data.address,
            phone: data.phone,
            email: data.email,
            pic_name: payload.pic_name,
            pic_email: payload.pic_email,
            pic_phone: payload.pic_phone,
            partner_secret: payload.partner_secret,
         }),
         Err(e) => Err(KeypairError::CreationError(e.to_string())),
      };
   }

   async fn update_partner(&self, payload: PartnerPayload) -> Result<(), KeypairError> {
      if payload.partner_secret.is_empty() {
         return Err(KeypairError::CreationError(
            "secret cannot empty".to_string(),
         ));
      }

      let decoded_key = BASE64.decode(get("DB_KEY").as_bytes())
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key);

      let secret = security::aes256_encrypt(key, payload.partner_secret.as_bytes());
      let pic_name = security::aes256_encrypt(key, payload.pic_name.as_bytes());
      let pic_email = security::aes256_encrypt(key, payload.pic_email.as_bytes());
      let pic_phone = security::aes256_encrypt(key, payload.pic_phone.as_bytes());
      
      let mut msg = secret.clone();
      msg.extend(pic_name.clone());
      msg.extend(pic_email.clone());
      msg.extend(pic_phone.clone());

      let hashed = security::hmac256_hash(get("HASH_KEY").as_bytes(), &msg)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let data = Partner {
         id: Uuid::now_v7(),
         name: payload.name,
         address: payload.address,
         phone: payload.phone,
         email: payload.email,
         pic_name: pic_name,
         pic_email: pic_email,
         pic_phone: pic_phone,
         partner_secret: secret,
         row_hash: hashed,
      };

      return match self.repository.insert_partner(data.clone()).await {
         Ok(_) => Ok(()),
         Err(e) => Err(KeypairError::CreationError(e.to_string())),
      };
   }

   async fn delete_partner(&self, partner_id: String) -> Result<(), KeypairError> {
      let id = Uuid::parse_str(&partner_id).unwrap_or_else(|_| panic!("invalid uuidv7"));

      match self.repository.find_partner_by_id(id).await {
         Ok(v) => v,
         Err(e) => return Err(KeypairError::Yabai(e.to_string())),
      };

      match self.repository.delete_partner(id).await {
         Some(e) => return Err(KeypairError::Yabai(e.to_string())),
         _ => Ok(()),
      }
   }
}
