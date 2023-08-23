use aes::cipher::block_padding::{Pkcs7, UnpadError};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::Mac;

use crate::error::security_error::SecurityError;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub fn aes256_encrypt(key: GenericArray<u8, U32>, iv: [u8; 16], msg: &[u8]) -> Vec<u8> {
   Aes256CbcEnc::new(&key, &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(msg)
}

pub fn aes256_decrypt(key: GenericArray<u8, U32>,iv: [u8; 16], msg: &[u8]) -> Result<Vec<u8>, UnpadError> {
   Aes256CbcDec::new(&key, &iv.into()).decrypt_padded_vec_mut::<Pkcs7>(msg)
}

type HMAC256 = hmac::Hmac<sha2::Sha256>;

pub fn hmac256_hash(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, SecurityError> {
   let mut hash = HMAC256::new_from_slice(key).map_err(|e| SecurityError::GenericError(e.to_string()))?;
   hash.update(msg);
   Ok(hash.finalize().into_bytes().to_vec())
}


pub fn hmac256_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), SecurityError> {
   let mut hash = HMAC256::new_from_slice(key).map_err(|e| SecurityError::GenericError(e.to_string()))?;
   hash.update(msg);
   match hash.verify_slice(tag) {
      Ok(_) => Ok(()),
      Err(e) => Err(SecurityError::GenericError(e.to_string()))
   }  
}