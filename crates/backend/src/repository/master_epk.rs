use data_encoding::BASE64;
use redis::AsyncCommands;
use async_trait::async_trait;

use crate::config::cache::{Cache, CacheTrait};
use crate::entity::security::EphemeralMasterKeyPair;
use crate::error::db_error::DBError;

#[derive(Clone)]
pub struct MasterEPKRepository {
    pub(crate) cache: Cache,
}

#[async_trait]
pub trait MasterEPKRepositoryTrait {
    fn new(conn: Cache) -> Self;

    async fn find_keypair_by_hash(&mut self, hash: String) -> Result<EphemeralMasterKeyPair, DBError>;
    async fn insert_keypair(&mut self, keypair: EphemeralMasterKeyPair) -> Result<(), DBError>;
}

#[async_trait]
impl MasterEPKRepositoryTrait for MasterEPKRepository {
    fn new(conn: Cache) -> Self {
        Self {
            cache: conn,
        }
    }

    async fn find_keypair_by_hash(&mut self, hash: String) -> Result<EphemeralMasterKeyPair, DBError> {
        let conn = self.cache.get_cache();

        let res: String = conn.get(format!("epk:{}", hash)).await.unwrap_or(String::default());
        if res.is_empty() {
            return Err(DBError::NotFound);
        }
        
        let (pk, sk) = res.split_once(':').unwrap();

        Ok(EphemeralMasterKeyPair {
            keypair_hash: hash,
            private_key: BASE64.decode(sk.as_bytes()).unwrap(),
            public_key: BASE64.decode(pk.as_bytes()).unwrap(),
        })
    }

    async fn insert_keypair(&mut self, epk: EphemeralMasterKeyPair) -> Result<(), DBError> {
        let conn = self.cache.get_cache();
        
        let keypair = format!("{}:{}", BASE64.encode(&epk.public_key), BASE64.encode(&epk.private_key));
        let key  = format!("epk:{}", epk.keypair_hash);

        let _: () = conn.set_ex(key, keypair, 10*60u64).await.unwrap();

        Ok(())
    }
}
