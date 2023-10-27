use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Deserialize, Serialize, sqlx::FromRow)]
pub struct Partner {
   pub id: Uuid,
   pub name: String, 
   pub address: String, 
   pub phone: String,
   pub email: String, 
   pub pic_name: Vec<u8>,
   pub pic_email: Vec<u8>,
   pub pic_phone: Vec<u8>,
   pub partner_secret: Vec<u8>,
   pub row_hash: Vec<u8>,
}
