use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Deserialize, Serialize, sqlx::FromRow)]
pub struct PartnerKeyPair {
   pub id: Uuid,
   pub partner_id: Uuid,
   pub public_key: String,
   pub keypair_hash: String,
   // pub created_at: DateTime<Utc>,
   // pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Deserialize, Serialize, sqlx::FromRow)]
pub struct MasterKeyPair {
   pub id: Uuid,
   pub public_key: String,
   pub private_key: String,
   pub keypair_hash: String,
   // pub created_at: DateTime<Utc>,
   // pub updated_at: DateTime<Utc>,
}

