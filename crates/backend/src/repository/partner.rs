use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use sqlx::Row;
use uuid::Uuid;

use crate::{
   config::database::{Database, DatabaseTrait},
   entity::partner::Partner,
   error::db_error::DBError,
};

#[derive(Clone)]
pub struct PartnerRepository {
   pub(crate) db: Arc<Database>,
}

#[async_trait]
pub trait PartnerRepositoryTrait {
   fn new(conn: &Arc<Database>) -> Self;

   async fn find_partners(&self) -> Result<Vec<Partner>, DBError>;
   async fn find_partner_by_id(&self, id: Uuid) -> Result<Partner, DBError>;
   async fn insert_partner(&self, data: Partner) -> Result<Uuid, DBError>;
   async fn update_partner(&self, data: Partner) -> Option<DBError>;
   async fn delete_partner(&self, id: Uuid) -> Option<DBError>;
}

#[async_trait]
impl PartnerRepositoryTrait for PartnerRepository {
   fn new(conn: &Arc<Database>) -> Self {
      Self {
         db: Arc::clone(conn),
      }
   }

   async fn find_partners(&self) -> Result<Vec<Partner>, DBError> {
      let res = sqlx::query_as::<_, Partner>(r#"
            select id, name, address, phone, email, pic_name, pic_email, pic_phone, partner_secret, row_hash from partners where deleted_at is null
        "#).fetch_all(self.db.get_pool()).await;

      match res {
         Ok(v) => Ok(v),
         Err(e) => Err(DBError::Yabaii(e.to_string())),
      }
   }

   async fn find_partner_by_id(&self, id: Uuid) -> Result<Partner, DBError> {
      let res = sqlx::query_as::<_, Partner>(r#"
            select id, name, address, phone, email, pic_name, pic_email, pic_phone, partner_secret, row_hash from partners
            where id = $1
            and deleted_at is null
        "#).bind(id).fetch_optional(self.db.get_pool()).await;

      match res {
         Ok(v) => match v {
            Some(v) => Ok(v),
            None => Err(DBError::NotFound),
         },
         Err(e) => Err(DBError::Yabaii(e.to_string())),
      }
   }

   async fn insert_partner(&self, data: Partner) -> Result<Uuid, DBError> {
      let res = sqlx::query(
         r#"
            insert into partners(id, name, address, phone, email, pic_name, pic_phone, pic_email, partner_secret, row_hash) 
            values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) returning id
        "#,
      )
      .bind(data.id)
      .bind(data.name)
      .bind(data.address)
      .bind(data.phone)
      .bind(data.email)
      .bind(data.pic_name)
      .bind(data.pic_phone)
      .bind(data.pic_email)
      .bind(data.partner_secret)
      .bind(data.row_hash)
      .fetch_one(self.db.get_pool())
      .await
      .map_err(|e| DBError::Yabaii(e.to_string()))?;

      Ok(res.get::<Uuid, _>(0))
   }

   async fn update_partner(&self, data: Partner) -> Option<DBError> {
      let curr_time = Utc::now();

      let res = sqlx::query(
         "update partners set
                name = $1,
                address = $2,
                phone = $3,
                email = $4,
                pic_name = $5,
                pic_name = $6,
                pic_email = $7, 
                partner_secret = $8,
                row_hash = $9,
                updated_at = $10
            where id = $11
            and deleted_at is null",
      )
      .bind(data.name)
      .bind(data.address)
      .bind(data.phone)
      .bind(data.email)
      .bind(data.pic_name)
      .bind(data.pic_phone)
      .bind(data.pic_email)
      .bind(data.partner_secret)
      .bind(data.row_hash)
      .bind(curr_time)
      .bind(data.id)
      .execute(self.db.get_pool())
      .await;

      match res {
         Err(e) => Some(DBError::Yabaii(e.to_string())),
         _ => None,
      }
   }

   async fn delete_partner(&self, id: Uuid) -> Option<DBError> {
      let res = sqlx::query(
         "update partners set
                updated_at = $1,
                deleted_at = $1
            where id = $2
            and deleted_at is null",
      )
      .bind(Utc::now())
      .bind(id)
      .execute(self.db.get_pool())
      .await;

      match res {
         Err(e) => Some(DBError::Yabaii(e.to_string())),
         _ => None,
      }
   }
}
