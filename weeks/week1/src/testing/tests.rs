use crate::{vignere_decrypt, vignere_encrypt};

#[test]
fn test_vignere() {
    let plaintext = "attackatdawn".to_string();
    let key = "LEMON".to_string();

    let ciphertext = vignere_encrypt(&key, &plaintext);
    assert_eq!("lxfopvefrnhr", ciphertext);

    assert_eq!("attackatdawn", vignere_decrypt(&key, &ciphertext))
}
