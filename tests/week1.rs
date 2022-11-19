use cryptography_study_group::week1::{vigenere_decrypt, vigenere_encrypt};

#[test]
fn test_vigenere() {
    let plaintext = "attackatdawn".to_string();
    let key = "LEMON".to_string();

    let ciphertext = vigenere_encrypt(key.clone(), plaintext);
    assert_eq!("lxfopvefrnhr", ciphertext);

    // k_i = M = 11
    // c_i = f = 5
    assert_eq!("attackatdawn", vigenere_decrypt(key, ciphertext))
}
