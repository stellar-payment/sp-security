use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Deserialize, Serialize, sqlx::FromRow)]
pub struct Partner {
   pub id: Uuid,
   pub name: String, 
   pub address: String, 
   pub email: String, 
   pub pic_name: String,
   pub pic_email: String,
   pub pic_phone: String,
   pub partner_secret: String,
}
