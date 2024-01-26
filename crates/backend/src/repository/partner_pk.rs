use crate::{
    config::{
        cache::{Cache, CacheTrait},
        database::{Database, DatabaseTrait},
    },
    entity::security::PartnerKeyPair,
    error::db_error::DBError,
};
use async_trait::async_trait;
use chrono::Utc;
use data_encoding::BASE64;
use log::{error, info};
use redis::AsyncCommands;
use sqlx::Row;
use std::{str::FromStr, sync::Arc};
use uuid::Uuid;

#[derive(Clone)]
pub struct PartnerPKRepository {
    pub(crate) db: Arc<Database>,
    pub(crate) cache: Cache,
}

#[async_trait]
pub trait PartnerPKRepositoryTrait {
    fn new(db: &Arc<Database>, cache: Cache) -> Self;

    async fn find_partner_keypairs(&mut self, partner_id: Uuid) -> Result<PartnerKeyPair, DBError>;
    async fn find_partner_keypair_by_id(&self, id: Uuid) -> Result<PartnerKeyPair, DBError>;
    async fn find_partner_keypair_by_hash(
        &mut self,
        hash: String,
    ) -> Result<PartnerKeyPair, DBError>;
    async fn insert_partner_keypair(&self, keypair: PartnerKeyPair) -> Result<Uuid, DBError>;
    async fn update_partner_keypair(&self, keypair: PartnerKeyPair) -> Option<DBError>;
    async fn delete_partner_keypair(&self, hash: String) -> Option<DBError>;
}

#[async_trait]
impl PartnerPKRepositoryTrait for PartnerPKRepository {
    fn new(db: &Arc<Database>, cache: Cache) -> Self {
        Self {
            db: Arc::clone(db),
            cache: cache,
        }
    }

    async fn find_partner_keypairs(&mut self, partner_id: Uuid) -> Result<PartnerKeyPair, DBError> {
        let conn = self.cache.get_cache();

        let cached_key: Option<PartnerKeyPair> = {
            let res: String = conn
                .get(format!("partner:{}", partner_id))
                .await
                .unwrap_or(String::default());

            // match serde_json::from_str::<PartnerKeyPair>(&res)
            //     .map_err(|e| DBError::Yabaii(e.to_string()))
            // {
            //     Ok(v) => Some(v),
            //     Err(e) => {
            //         error!("failed to unmarshal data from cache err: {}", e);
            //         None
            //     }
            // }
            
            if let [id, pid, pk, kh] = res.splitn(4, ':').take(4).collect::<Vec<&str>>()[..] {
               Some(PartnerKeyPair{
                id: Uuid::from_str(id).unwrap(),
                partner_id: Uuid::from_str(pid).unwrap(),
                public_key: BASE64.decode(pk.as_bytes()).unwrap(), 
                keypair_hash: BASE64.decode(kh.as_bytes()).unwrap(),
               }) 
            } else {
                None
            }
        };

        if let Some(key) = cached_key {
            info!("fetched from cache!");
            return Ok(key);
        }
        info!("not fetched from cache. :(");

        let res = sqlx::query_as::<_, PartnerKeyPair>(
            r#"select id, partner_id, public_key, keypair_hash from partner_keypairs
         where partner_id = $1
         and deleted_at is null"#,
        )
        .bind(partner_id)
        .fetch_optional(self.db.get_pool())
        .await;

        match res {
            Ok(v) => match v {
                Some(v) => {
                    async {
                        let _: () = conn
                            .set_ex(
                                format!("partner:{}", partner_id),
                                format!("{}:{}:{}:{}", v.id, v.partner_id, BASE64.encode(&v.public_key), BASE64.encode(&v.keypair_hash)),
                                // serde_json::to_string(&v.clone()).unwrap(),
                                2 * 60u64,
                            )
                            .await
                            .unwrap();
                        Ok(v)
                    }
                    .await
                }
                None => Err(DBError::NotFound),
            },
            Err(e) => Err(DBError::Yabaii(e.to_string())),
        }
    }

    async fn find_partner_keypair_by_id(&self, id: Uuid) -> Result<PartnerKeyPair, DBError> {
        let res = sqlx::query_as::<_, PartnerKeyPair>(
            r#"
      select id, partner_id, public_key, keypair_hash from partner_keypairs
      where id = $1 and deleted_at is null
   "#,
        )
        .bind(id)
        .fetch_optional(self.db.get_pool())
        .await;

        match res {
            Ok(v) => match v {
                Some(v) => Ok(v),
                None => Err(DBError::NotFound),
            },
            Err(e) => Err(DBError::Yabaii(e.to_string())),
        }
    }

    async fn find_partner_keypair_by_hash(
        &mut self,
        hash: String,
    ) -> Result<PartnerKeyPair, DBError> {
        let res = sqlx::query_as::<_, PartnerKeyPair>(
            r#"
      select id, partner_id, public_key, keypair_hash from partner_keypairs
      where keypair_hash = $1 and deleted_at is null
   "#,
        )
        .bind(hash.clone())
        .fetch_optional(self.db.get_pool())
        .await;

        match res {
            Ok(v) => match v {
                Some(v) => Ok(v),
                None => Err(DBError::NotFound),
            },
            Err(e) => Err(DBError::Yabaii(e.to_string())),
        }
    }

    async fn insert_partner_keypair(&self, keypair: PartnerKeyPair) -> Result<Uuid, DBError> {
        let res = sqlx::query("insert into partner_keypairs(id, partner_id, public_key, keypair_hash) values ($1, $2, $3, $4) returning id")
      .bind(keypair.id)
      .bind(keypair.partner_id)
      .bind(keypair.public_key)
      .bind(keypair.keypair_hash)
      .fetch_one(self.db.get_pool())
      .await.map_err(|e| DBError::Yabaii(e.to_string()))?;

        Ok(res.get::<Uuid, _>(0))
    }

    async fn update_partner_keypair(&self, keypair: PartnerKeyPair) -> Option<DBError> {
        let current_time = Utc::now();

        let res = sqlx::query(
            r#"
         update partner_keypairs set
            public_key = $1,
            keypair_hash = $2,
            updated_at = $3
         where
            id = $4 and partner_id = $5 
            and deleted_at is null
      "#,
        )
        .bind(keypair.public_key)
        .bind(keypair.keypair_hash)
        .bind(current_time)
        .bind(keypair.id)
        .bind(keypair.partner_id)
        .execute(self.db.get_pool())
        .await;

        match res {
            Err(e) => Some(DBError::Yabaii(e.to_string())),
            _ => None,
        }
    }

    async fn delete_partner_keypair(&self, hash: String) -> Option<DBError> {
        let res = sqlx::query(
            r#"
      update partner_keypairs set
         updated_at = $1,
         deleted_at = $1,
      where keypair_hash = $2 and deleted_at is null"#,
        )
        .bind(hash)
        .execute(self.db.get_pool())
        .await;

        match res {
            Err(e) => Some(DBError::Yabaii(e.to_string())),
            _ => None,
        }
    }
}
