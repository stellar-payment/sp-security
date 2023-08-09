use crate::parameter;
use async_trait::async_trait;
use sqlx::{Error, MySql, MySqlPool, Pool};

pub struct Database {
   pool: Pool<MySql>,
}

#[async_trait]
pub trait DatabaseTrait {
   async fn init() -> Result<Self, Error>
   where
      Self: Sized;
   fn get_pool(&self) -> &Pool<MySql>;
}

#[async_trait]
impl DatabaseTrait for Database {
   async fn init() -> Result<Self, Error> {
      let db = parameter::get("DATABASE_URL");
      let pool = MySqlPool::connect(&db).await?;
      
      sqlx::migrate!().run(&pool).await.unwrap_or_else(|e| panic!("migration err: {}", e));
      Ok(Self { pool })
   }

   fn get_pool(&self) -> &Pool<MySql> {
      &self.pool
   }
}
