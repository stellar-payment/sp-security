use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PartnerPKPayload {
   pub id: String,
   pub partner_id: String,
   pub hash: String,
   pub public_key: String,   
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PartnerPKResponse {
   pub id: String,
   pub partner_id: String,
   pub public_key: String,
   pub keypair_hash: String,
}


#[derive(Clone, Serialize, Deserialize)]
pub struct ListPartnerPKResponse {
   pub keys: Vec<PartnerPKResponse>
}