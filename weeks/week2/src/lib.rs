#[cfg(test)]
pub mod testing;

use openssl::{
    error::ErrorStack,
    symm::{decrypt, encrypt, Cipher},
};

pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    encrypt(Cipher::aes_256_cbc(), key, None, plaintext)
}

pub fn aes_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    decrypt(Cipher::aes_256_cbc(), key, None, ciphertext)
}

pub fn des_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    encrypt(Cipher::des_cbc(), key, None, plaintext)
}

pub fn des_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    decrypt(Cipher::des_cbc(), key, None, ciphertext)
}

#[cfg(test)]
mod tests {
    use openssl::rsa::{Padding, Rsa};

    use crate::{aes_decrypt, aes_encrypt, des_decrypt, des_encrypt};

    #[test]
    fn ch3_4() {
        let key = b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
        let ciphertext = b"\x53\x9B\x33\x3B\x39\x70\x6D\x14\x90\x28\xCF\xE1\xD9\xD4\xA4\x07";

        let plaintext = aes_decrypt(key, ciphertext).unwrap();

        assert_eq!(aes_encrypt(key, &plaintext).unwrap(), ciphertext);
    }

    #[test]
    fn ch3_9() {
        let key = b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
        let plaintext = b"\x29\x6C\x93\xFD\xF4\x99\xAA\xEB\x41\x94\xBA\xBC\x2E\x63\x56\x1D";

        let ciphertext = aes_encrypt(key, plaintext).unwrap();

        let rsa = Rsa::generate(3072).unwrap();
        let mut buf = vec![0; rsa.size() as usize];
        let encrypted_len = rsa
            .public_encrypt(&ciphertext, &mut buf, Padding::PKCS1)
            .unwrap();

        let mut buf2 = vec![0; rsa.size() as usize];
        let decrypted_len = rsa
            .private_decrypt(&buf[0..encrypted_len], &mut buf2, Padding::PKCS1)
            .unwrap();

        assert_eq!(ciphertext, buf2[0..decrypted_len].to_vec());
    }

    #[test]
    fn ch3_10() {
        let key = b"\x00\x00\x00\x00\x00\x00\x00\x01";
        let plaintext = b"\x00\x00\x00\x00\x00\x00\x00\x01";

        let ciphertext: Vec<u8> = des_encrypt(key, plaintext).unwrap();

        println!("{:?}", ciphertext);

        let inv_key = key.map(|b| !b);
        let inv_pt = plaintext.map(|b| !b);
        let inv_ct: Vec<u8> = ciphertext.iter().map(|b| !b).collect();
        assert_eq!(des_encrypt(&inv_key, &inv_pt).unwrap(), inv_ct);
    }

    #[test]
    fn ch4_4() {
        let key = b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
        let ciphertext = b"\x87\xF3\x48\xFF\x79\xB8\x11\xAF\x38\x57\xD6\x71\x8E\x5F\x0F\x91\x7C\x3D\x26\xF7\x73\x77\x63\x5A\x5E\x43\xE9\xB5\xCC\x5D\x05\x92\x6E\x26\xFF\xC5\x22\x0D\xC7\xD4\x05\xF1\x70\x86\x70\xE6\xE0\x17";
        let plaintext = aes_decrypt(key, ciphertext).unwrap();
    }
}
