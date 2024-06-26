use crate::parameter;
use async_trait::async_trait;
use sqlx::{Error, Postgres, PgPool, Pool};

pub struct Database {
   pool: Pool<Postgres>,
}

#[async_trait]
pub trait DatabaseTrait {
   async fn init() -> Result<Self, Error>
   where
      Self: Sized;
   fn get_pool(&self) -> &Pool<Postgres>;
}

#[async_trait]
impl DatabaseTrait for Database {
   async fn init() -> Result<Self, Error> {
      let db = parameter::get("DATABASE_URL");
      let pool = PgPool::connect(&db)
         .await
         .unwrap_or_else(|e| panic!("connect to database err: {}", e));

      sqlx::migrate!("../../migrations")
         .run(&pool)
         .await
         .unwrap_or_else(|e| panic!("migration err: {}", e));
      Ok(Self { pool })
   }

   fn get_pool(&self) -> &Pool<Postgres> {
      &self.pool
   }
}
