use crate::parameter;
use async_trait::async_trait;
use redis::aio::ConnectionManager;

#[derive(Clone)]
pub struct Cache {
   conn: ConnectionManager,
}

#[async_trait]
pub trait CacheTrait {
   async fn init() -> Result<Self, redis::RedisError>
   where
      Self: Sized;
   fn get_cache(&mut self) -> &mut ConnectionManager;
}

#[async_trait]
impl CacheTrait for Cache {
   async fn init() -> Result<Self, redis::RedisError> {
      let cache = parameter::get("CACHE_URL");
      let client = redis::Client::open(cache)
         .unwrap_or_else(|e| panic!("preparing connection to cache err: {}", e));

      let cache_conn = client.get_connection_manager()
         .await
         .unwrap_or_else(|e| panic!("connection to cache err: {}", e));
   
      Ok(Self { conn: cache_conn })
   }

   fn get_cache(&mut self) -> &mut ConnectionManager {
      &mut self.conn
   }
}
