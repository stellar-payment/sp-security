use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PartnerPayload {
    pub id: String,
    pub name: String, 
    pub address: String, 
    pub phone: String,
    pub email: String, 
    pub pic_name: String,
    pub pic_email: String,
    pub pic_phone: String,
    pub partner_secret: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PartnerResponse {
    pub id: String,
    pub name: String, 
    pub address: String, 
    pub phone: String,
    pub email: String, 
    pub pic_name: String,
    pub pic_email: String,
    pub pic_phone: String,
    pub partner_secret: String,
}


#[derive(Clone, Serialize, Deserialize)]
pub struct ListPartnerResponse {
   pub keys: Vec<PartnerResponse>
}