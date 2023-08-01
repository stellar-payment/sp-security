use serde::{Deserialize, Serialize};


#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptPayloadDto {
    pub data: String
}

