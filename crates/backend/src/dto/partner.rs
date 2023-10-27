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
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pic_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pic_email: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pic_phone: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub partner_secret: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BriefPartnerResponse {
    pub id: String,
    pub name: String, 
    pub address: String, 
    pub phone: String,
    pub email: String, 
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ListPartnerResponse {
   pub partners: Vec<BriefPartnerResponse>
}