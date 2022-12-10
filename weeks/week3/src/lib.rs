#[cfg(test)]
pub mod testing;

use openssl::sha::Sha512;
use random_string::generate;

pub fn convert_string_to_bits(buf: &[u8]) -> String {
    let buf_string = String::from_utf8_lossy(buf).into_owned();
    let mut buf_in_binary = "".to_string();
    for character in buf_string.clone().into_bytes() {
        buf_in_binary += &format!("0{:b} ", character);
    }
    buf_in_binary
}

pub fn birthday_attack_first_n_bits(n: usize) -> usize {
    let charset = "1234567890abcdefghijklmnopqrstuvwxyz";
    let mut hashfn = Sha512::new();
    let orig_msg_string = generate(20, charset);
    let orig_msg = orig_msg_string.as_bytes();
    let mut msg_string;
    let mut msg = orig_msg.clone();
    hashfn.update(msg);
    let fixed_hash = hashfn.finish();
    let fixed_hash_first_n_bits = convert_string_to_bits(&fixed_hash);
    let mut output;
    let mut iterations = 0;
    while true {
        hashfn = Sha512::new();
        // create new msg
        msg_string = generate(20, charset);
        // println!("{}", msg_string);
        msg = msg_string.as_bytes();
        if orig_msg == msg {
            continue;
        }

        hashfn.update(msg);

        output = hashfn.finish();
        // convert into bit arrays
        let output_in_bits = convert_string_to_bits(&output);
        if output_in_bits[..n] == fixed_hash_first_n_bits[..n] {
            // println!("found!");
            return iterations;
        }
        iterations += 1;
    }
    0
}

pub fn preimage_attack(hashvalue: &[u8]) -> usize {
    let charset = "1234567890abcdefghijklmnopqrstuvwxyz";
    let mut hashfn;
    let mut msg_string;
    let mut msg;
    let mut output;
    let mut iterations = 0;
    while true {
        hashfn = Sha512::new();
        // create new msg
        msg_string = generate(20, charset);
        msg = msg_string.as_bytes();
        hashfn.update(msg);
        output = hashfn.finish();
        // println!("{}", output);
        if &output[..hashvalue.len()] == hashvalue {
            // println!("found!");
            return iterations;
        }
        iterations += 1;
    }
    0
}

#[cfg(test)]
mod tests {

    use hex_literal::hex;
    use openssl::{aes::AesKey, cipher};

    use crate::preimage_attack;

    use super::birthday_attack_first_n_bits;

    #[test]
    fn ch5_3() {
        let mut sum = 0;
        for _ in 0..5 {
            sum += birthday_attack_first_n_bits(8);
        }
        println!("8 bits: {}", sum / 5);
        sum = 0;
        for _ in 0..5 {
            sum += birthday_attack_first_n_bits(16);
        }
        println!("16 bits: {}", sum / 5);
        sum = 0;
        for _ in 0..5 {
            sum += birthday_attack_first_n_bits(24);
        }
        println!("24 bits: {}", sum / 5);
        sum = 0;
        for _ in 0..5 {
            sum += birthday_attack_first_n_bits(32);
        }
        println!("32 bits: {}", sum / 5);
        sum = 0;
        for _ in 0..5 {
            sum += birthday_attack_first_n_bits(40);
        }
        println!("40 bits: {}", sum / 5);
        sum = 0;
        for _ in 0..5 {
            sum += birthday_attack_first_n_bits(48);
        }
        println!("48 bits: {}", sum / 5);
    }

    #[test]
    fn ch5_4() {
        let mut sum = 0;
        let mut hashvalue: &[u8] = b"\xA9";
        for _ in 0..5 {
            sum += preimage_attack(hashvalue);
        }
        println!("A9: {}", sum / 5);
        sum = 0;
        hashvalue = b"\x3D\x4B";
        for _ in 0..5 {
            sum += preimage_attack(hashvalue);
        }
        println!("A9: {}", sum / 5);
        sum = 0;
        hashvalue = b"\x3D\x4B";
        for _ in 0..5 {
            sum += preimage_attack(hashvalue);
        }
        println!("A9: {}", sum / 5);
        sum = 0;
        hashvalue = b"\x3D\x4B";
        for _ in 0..5 {
            sum += preimage_attack(hashvalue);
        }
        println!("A9: {}", sum / 5);
    }

    #[test]
    fn ch6_5() {
        use openssl::symm::{encrypt, Cipher};

        let key = hex!("80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01");
        let msg = hex!("4D 41 43 73 20 61 72 65 20 76 65 72 79 20 75 73 65 66 75 6C 20 69 6E 20 63 72 79 70 74 6F 67 72 61 70 68 79 21 20 20 20 20 20 20 20 20 20 20 20");
        let ciphertext = encrypt(Cipher::aes_256_cbc(), &key, None, &msg).unwrap();
        let mac = &ciphertext[ciphertext.len() - 16..];
        println!("{:?}", mac);
    }
}
