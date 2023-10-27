use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Deserialize, Serialize, sqlx::FromRow)]
pub struct PartnerKeyPair {
   pub id: Uuid,
   pub partner_id: Uuid,
   pub public_key: Vec<u8>,
   pub keypair_hash: Vec<u8>,
   // pub created_at: DateTime<Utc>,
   // pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Deserialize, Serialize, sqlx::FromRow)]
pub struct MasterKeyPair {
   pub id: Uuid,
   pub public_key: Vec<u8>,
   pub private_key: Vec<u8>,
   pub keypair_hash: Vec<u8>,
   // pub created_at: DateTime<Utc>,
   // pub updated_at: DateTime<Utc>,
}

