#[cfg(test)]
pub mod testing;

// Tweakable Encryption Standard:
// I think this would be the standard: https://people.eecs.berkeley.edu/~daw/papers/tweak-crypto02.pdf
// Judging by the paper, the signatures should be:
fn _encrypt(_key: Vec<u8>, _tweak: Vec<u8>, _plaintext: Vec<u8>) -> Vec<u8> {
    //...
    return vec![];
}
fn _decrypt(_key: Vec<u8>, _tweak: Vec<u8>, _ciphertext: Vec<u8>) -> Vec<u8> {
    //...
    return vec![];
}

/// Encrypts chosen `plaintext` with the chosen `key` using the Vigenere cipher. It is assumed that
/// both of these inputs only contain letters from the alphabet.
pub fn vigenere_encrypt(key: String, plaintext: String) -> String {
    let key = key.to_lowercase();
    let plaintext = plaintext.to_lowercase();

    let key = key.as_bytes();

    let mut cipher_vec: Vec<char> = vec![];
    for (i, m_i) in plaintext.chars().enumerate() {
        let k_i: u32 = encode_char(key[i % key.len()] as char);
        let m_i: u32 = encode_char(m_i);
        let c_i = (m_i + k_i) % 26;

        cipher_vec.push(decode_u32(c_i));
    }

    return cipher_vec.into_iter().collect();
}

/// Decrypts chosen `ciphertext` with the chosen `key` using the Vigenere cipher. It is assumed that
/// both of these inputs only contain letters from the alphabet.
pub fn vigenere_decrypt(key: String, ciphertext: String) -> String {
    let key = key.to_lowercase();
    let ciphertext = ciphertext.to_lowercase();

    let key = key.as_bytes();

    let mut plaintext_vec: Vec<char> = vec![];
    for (i, c_i) in ciphertext.chars().enumerate() {
        let k_i: u32 = encode_char(key[i % key.len()] as char);
        let c_i: u32 = encode_char(c_i);
        // rem_euclid acts as a modulus operator when we have negative results.
        let m_i = (c_i as i32 - k_i as i32).rem_euclid(26) as u32;

        plaintext_vec.push(decode_u32(m_i));
    }

    return plaintext_vec.into_iter().collect();
}

/// Encodes a character to a u32 by subtracting by 97 to normalize to range of 0 - 25.
/// Source: https://www.asciitable.com/
fn encode_char(c: char) -> u32 {
    (c as u32)
        .checked_sub(97)
        .expect("Error encoding char to u32!")
}

/// Encodes a u32 to a char by adding 97 to undo normalization of the chosen range of 0 - 25.
/// Source: https://www.asciitable.com/
fn decode_u32(n: u32) -> char {
    std::char::from_u32(n + 97).expect("Error decoding u32 to char!")
}

#[cfg(test)]
mod tests {
    use crate::decode_u32;
    use crate::encode_char;

    #[test]
    fn test_encode_char() {
        assert_eq!(0, encode_char('a'));
        assert_eq!(25, encode_char('z'));
    }

    #[test]
    fn test_decode_u32() {
        assert_eq!('a', decode_u32(0));
        assert_eq!('z', decode_u32(25));
    }
}
