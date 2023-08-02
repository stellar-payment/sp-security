use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptPayloadDto {
   pub data: String,
}
