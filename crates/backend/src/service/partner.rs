use core::panic;
use std::sync::Arc;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use async_trait::async_trait;
use corelib::{security, mapper};
use data_encoding::BASE64;
use rand_core::{OsRng, RngCore};
use uuid::Uuid;

use crate::config::database::Database;
use crate::config::parameter::get;
use crate::dto::partner::{ListPartnerResponse, PartnerPayload, PartnerResponse};
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
      return match self.repository.find_partners().await {
         Ok(v) => Ok(ListPartnerResponse {
            keys: v
               .into_iter()
               .map(|p| PartnerResponse {
                  id: p.id.to_string(),
                  name: p.name,
                  address: p.address,
                  phone: p.phone,
                  email: p.email,
                  pic_name: p.pic_name,
                  pic_email: p.pic_email,
                  pic_phone: p.pic_phone,
                  partner_secret: p.partner_secret,
               })
               .collect(),
         }),
         Err(e) => Err(KeypairError::Yabai(e.to_string())),
      };
   }

   async fn get_partner_by_id(&self, id: String) -> Result<PartnerResponse, KeypairError> {
      if id.is_empty() {
         return Err(KeypairError::Invalid);
      }

      let meta = match self
         .repository
         .find_partner_by_id(Uuid::parse_str(&id).unwrap_or_else(|_| panic!("invalid uuidv7")))
         .await
      {
         Ok(v) => v,
         Err(e) => match e {
            DBError::Yabaii(err) => return Err(KeypairError::Yabai(err)),
            DBError::NotFound => return Err(KeypairError::NotFound),
         },
      };

      let decoded_key = BASE64.decode(get("DB_KEY").as_bytes())
      .map_err(|e| KeypairError::Yabai(e.to_string()))?;
      let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&decoded_key);

      let (decoded_secret, decoded_iv) = meta.partner_secret
         .split_once('.')
         .unwrap_or_else(|| panic!("invalid structure"));
      
      let secret_ct = BASE64
         .decode(decoded_secret.as_bytes())
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let secret_iv = BASE64
         .decode(decoded_iv.as_bytes())
         .map(mapper::vec_to_arr)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      let secret = security::aes256_decrypt(key, secret_iv, &secret_ct)
         .map_err(|e| KeypairError::Yabai(e.to_string()))?;

      Ok(PartnerResponse {
         id: meta.id.to_string(),
         name: meta.name,
         address: meta.address,
         phone: meta.phone,
         email: meta.email,
         pic_name: meta.pic_name,
         pic_email: meta.pic_email,
         pic_phone: meta.pic_phone,
         partner_secret: String::from_utf8(secret).unwrap_or_else(|_| panic!("invalid structure")),
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

      let mut iv = [0u8; 16];
      OsRng.fill_bytes(&mut iv);

      let enc_secret = security::aes256_encrypt(key, iv, payload.partner_secret.as_bytes());
      let encoded_secret = BASE64.encode(&enc_secret.clone());
      let encoded_iv = BASE64.encode(&iv);
      
      let data = Partner {
         id: Uuid::now_v7(),
         name: payload.name,
         address: payload.address,
         phone: payload.phone,
         email: payload.email,
         pic_name: payload.pic_name,
         pic_email: payload.pic_email,
         pic_phone: payload.pic_phone,
         partner_secret: format!("{}.{}", encoded_secret, encoded_iv),
      };

      return match self.repository.insert_partner(data.clone()).await {
         Ok(v) => Ok(PartnerResponse {
            id: v.to_string(),
            name: data.name,
            address: data.address,
            phone: data.phone,
            email: data.email,
            pic_name: data.pic_name,
            pic_email: data.pic_email,
            pic_phone: data.pic_phone,
            partner_secret: data.partner_secret,
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

      let data = Partner {
         id: Uuid::now_v7(),
         name: payload.name,
         address: payload.address,
         phone: payload.phone,
         email: payload.email,
         pic_name: payload.pic_name,
         pic_email: payload.pic_email,
         pic_phone: payload.pic_phone,
         partner_secret: payload.partner_secret,
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
