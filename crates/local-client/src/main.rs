use std::collections::hash_map;

use corelib::{security::{aes256_encrypt, ecdh_generate_secret, generate_shared_key, hmac512_hash, hmac512_verify, aes256_decrypt}, mapper};
use p256::{elliptic_curve::generic_array::GenericArray, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use aes::cipher::typenum::U32;
use data_encoding::BASE64;

use rand_core::{OsRng, RngCore};

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct PartnerPKPayload {
   pub public_key: String,   
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct DecryptDataPayload {
   pub keypair_hash: String,
   pub partner_id: u64,
   pub data: String,
   pub tag: String
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ApiResponse<T> {
   data: Option<T>,
   error: Option<ErrorResponse>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ErrorResponse {
   code: u16,
   #[serde(rename = "msg")]
   message: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptDataPayload {
   pub data: String,
   pub partner_id: u64,
}


#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptDataResponse {
   pub data: String,
   pub tag: String,
   pub secret_key: String,
}


#[derive(Clone, Serialize, Deserialize)]
pub struct DecryptDataResponse {
    pub data: String
}


#[derive(Clone, Serialize, Deserialize)]
pub struct MasterPKResponse {
   pub id: u64,
   pub public_key: String,
   pub keypair_hash: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ListMasterPKResponse {
   pub keys: Vec<MasterPKResponse>,
}


// public_key: BAH2f+ax4WLMiYS76my8Pq3kbhIqTppThVcjh7GHHER2cijI0kKf3B9Zbya9cAuyy6Qi4OUoZ2qGnAQTpm4OnTM=
// secret_key: 2K/vz6mPlr3rlyDtu76LxJG5jMeDL7TsgzeTeoC5Ifo=

// #[tokio::main]
// async fn main() {
//    //  let secret = SecretKey::random(&mut OsRng);
//    //  let pk = secret.public_key().to_sec1_bytes();
//    //  let ppk = secret.to_bytes();

//    //  let encoded_pk = BASE64.encode(pk);
//    //  let encoded_ppk = BASE64.encode(ppk);
    
//    //  println!("public_key: {}", encoded_pk);
//    //  println!("secret_key: {}", encoded_ppk);

//    //  let client = reqwest::Client::new();
    
//    //  let pk_payload = PartnerPKPayload{public_key: encoded_pk};
//    //  let res = client.post("http://localhost:7780/api/v1/keypairs/partners/99")
//    //      .json(&pk_payload)
//    //      .send()
//    //      .await
//    //      .unwrap_or_else(|e| panic!("{e}"));
//    //  println!("resp: {}", res.text().await.unwrap_or_else(|e| panic!("{e}")));

//    // fetch public key
//    let list_mpk = reqwest::get("http://localhost:7780/api/v1/keypairs/master").await
//       .map_err(|e| panic!("{e}"))
//       .unwrap()
//       .json::<ApiResponse<ListMasterPKResponse>>().await
//       .unwrap()
//       .data.unwrap();
//    let mpk_hash = list_mpk.keys.last().unwrap();

//    let mpk = reqwest::get(format!("http://localhost:7780/api/v1/keypairs/master/hash/{}", mpk_hash.keypair_hash.clone())).await
//       .map_err(|e| panic!("{e}"))
//       .unwrap()
//       .json::<ApiResponse<MasterPKResponse>>().await
//       .unwrap();
//    let master_pk = BASE64.decode(mpk.data.unwrap().public_key).unwrap_or_else(|e| panic!("{e}"));

//     // public key
//    // let master_pk = BASE64.decode("BHyX9xmySecQZ0Aizhk4ZxlQQKLv2K32FOj3StCuTAFJAVDsu1qpvivw5Nzg80qETLoSRHUpR931+QOQlhRKeCM=")
//    //  .unwrap_or_else(|e| panic!("{e}"));

//     // secret key
//    let partner_pk = BASE64.decode("2K/vz6mPlr3rlyDtu76LxJG5jMeDL7TsgzeTeoC5Ifo=")
//     .unwrap_or_else(|e| panic!("{e}"));

//    let secret_key = SecretKey::from_slice(&partner_pk).unwrap_or_else(|e| panic!("{e}"));
//    let public_key = PublicKey::from_sec1_bytes(&master_pk).unwrap_or_else(|e| panic!("{e}"));

//    let shared_secret = ecdh_generate_secret(secret_key, public_key);
   
//    let secret_key = generate_shared_key(&shared_secret).unwrap_or_else(|e| panic!("{e}"));
//    let enc_key = &secret_key[0..32];
//    let mac_key = &secret_key[32..64];

//    println!("enc key: {} len: {}", BASE64.encode(enc_key), enc_key.len());
//    println!("mac key: {} len: {}", BASE64.encode(mac_key), mac_key.len());

//    let mut iv = [0u8; 16];
//    OsRng.fill_bytes(&mut iv);

//    let msg = r#"{
//         "data": {
//             "message": "kyaaNakaWaZettaiDame!",
//             "unix_timestamp": 1693817589948,
//             "timestamp": "04/09/2023 08:53"
//         },
//         "error": null
//     }"#;


//    let enc_key: GenericArray<u8, U32> = GenericArray::clone_from_slice(enc_key);
//    let ct = aes256_encrypt(enc_key, iv, msg.as_bytes());
//    let mac = hmac512_hash(mac_key, &ct)
//    .unwrap_or_else(|e| panic!("{e}"));

//    println!("tag: {}", BASE64.encode(mac.clone()));
//    let payload = DecryptDataPayload {
//       data: format!(
//          "{}.{}",
//          BASE64.encode(ct),
//          BASE64.encode(iv)
//       ),
//       tag: BASE64.encode(mac),
//       partner_id: 99,
//       keypair_hash: mpk_hash.keypair_hash.clone()
//    };


//    let client = reqwest::Client::new();
//    let dec_res = client.post("http://localhost:7780/api/v1/payload/decrypt")
//       .json(&payload)
//       .send()
//       .await
//       .unwrap_or_else(|e| panic!("{e}"));
   
//    let decrypted = BASE64.decode(dec_res.json::<ApiResponse<DecryptDataResponse>>().await.unwrap().data.unwrap().data.as_bytes()).unwrap();

//    println!("{}", String::from_utf8_lossy(&decrypted));
// //    reqwest::get("http://example.com");
// }

#[tokio::main]
async fn main() {
   //  let secret = SecretKey::random(&mut OsRng);
   //  let pk = secret.public_key().to_sec1_bytes();
   //  let ppk = secret.to_bytes();

   //  let encoded_pk = BASE64.encode(pk);
   //  let encoded_ppk = BASE64.encode(ppk);
    
   //  println!("public_key: {}", encoded_pk);
   //  println!("secret_key: {}", encoded_ppk);

   //  let client = reqwest::Client::new();
    
   //  let pk_payload = PartnerPKPayload{public_key: encoded_pk};
   //  let res = client.post("http://localhost:7780/api/v1/keypairs/partners/99")
   //      .json(&pk_payload)
   //      .send()
   //      .await
   //      .unwrap_or_else(|e| panic!("{e}"));
   //  println!("resp: {}", res.text().await.unwrap_or_else(|e| panic!("{e}")));


   let msg = r#"{
      "data": {
          "message": "kyaaNakaWaZettaiDame!",
          "unix_timestamp": 1693817589948,
          "timestamp": "04/09/2023 08:53"
      },
      "error": null
  }"#;

  let payload = EncryptDataPayload {
      data: BASE64.encode(msg.as_bytes()),
      partner_id: 99,
   };

   let client = reqwest::Client::new();
   let enc_res = client.post("http://localhost:7780/api/v1/payload/encrypt")
      .json(&payload)
      .send()
      .await
      .unwrap_or_else(|e| panic!("{e}"));
   
   let encrypted = enc_res.json::<ApiResponse<EncryptDataResponse>>().await.unwrap().data.expect("failed");
   let (ct, iv) = encrypted.data.split_once('.').unwrap_or_else(|| panic!("invalid structure"));

   let master_pk = BASE64.decode(encrypted.secret_key.as_bytes())
      .unwrap_or_else(|e| panic!("{e}"));

    // secret key
   let partner_pk = BASE64.decode("2K/vz6mPlr3rlyDtu76LxJG5jMeDL7TsgzeTeoC5Ifo=".as_bytes())
      .unwrap_or_else(|e| panic!("{e}"));

   let secret_key = SecretKey::from_slice(&partner_pk).unwrap_or_else(|e| panic!("{e}"));
   let public_key = PublicKey::from_sec1_bytes(&master_pk).unwrap_or_else(|e| panic!("{e}"));

   let shared_secret = ecdh_generate_secret(secret_key, public_key);
   
   let secret_key = generate_shared_key(&shared_secret).unwrap_or_else(|e| panic!("{e}"));
   let enc_key = &secret_key[0..32];
   let mac_key = &secret_key[32..64];

   println!("enc key: {} len: {}", BASE64.encode(enc_key), enc_key.len());
   println!("mac key: {} len: {}", BASE64.encode(mac_key), mac_key.len());
   println!("pk key: {} len: {}", BASE64.encode(&master_pk), mac_key.len());
   println!("sk key: {} len: {}", BASE64.encode(&partner_pk), mac_key.len());
   

   let ct = BASE64.decode(ct.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
   let enc_mac = BASE64.decode(encrypted.tag.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
   let iv = BASE64.decode(iv.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
   
   let enc_key: GenericArray<u8, U32> = GenericArray::clone_from_slice(enc_key);
   hmac512_verify(mac_key, &ct, &enc_mac).unwrap_or_else(|e| panic!("{e}"));

   let pt = aes256_decrypt(enc_key, mapper::vec_to_arr(iv), &ct).unwrap_or_else(|e| panic!("{e}"));
   println!("{}", String::from_utf8_lossy(&pt));
//    reqwest::get("http://example.com");
}
