use aes::cipher::block_padding::{NoPadding, Pkcs7, UnpadError};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub fn aes256_encrypt(key: GenericArray<u8, U32>, iv: [u8; 16], msg: &[u8]) -> Vec<u8> {
   Aes256CbcEnc::new(&key, &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(msg)
}

pub fn aes256_decrypt(key: GenericArray<u8, U32>,iv: [u8; 16], msg: &[u8]) -> Result<Vec<u8>, UnpadError> {
   Aes256CbcDec::new(&key, &iv.into()).decrypt_padded_vec_mut::<Pkcs7>(msg)
}
