use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MasterPKPayload {
   pub id: String,
   pub hash: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MasterPKResponse {
   pub id: String,
   pub public_key: String,
   pub keypair_hash: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ListMasterPKResponse {
   pub keys: Vec<MasterPKResponse>,
}
