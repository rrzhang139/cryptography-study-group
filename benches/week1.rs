use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use sha2::Digest;

struct Lib1Keys {
    pub_key: RsaPublicKey,
    priv_key: RsaPrivateKey,
}

pub fn benchmark_rsa_lib1(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let mut keys: Option<Lib1Keys> = None;
    c.bench_function("lib1 generate keys", |b| {
        b.iter(|| {
            let priv_key = RsaPrivateKey::new(black_box(&mut rng), black_box(bits))
                .expect("failed to generate a key");
            let pub_key = RsaPublicKey::from(black_box(&priv_key));
            // To use in future steps
            keys = Some(Lib1Keys { pub_key, priv_key });
        })
    });

    let keys = keys.unwrap();
    let data = b"hello world";

    let mut enc_data: Vec<u8> = vec![];

    c.bench_function("lib1 encrypt", |b| {
        b.iter(|| {
            enc_data = keys
                .pub_key
                .encrypt(
                    black_box(&mut rng),
                    black_box(PaddingScheme::new_oaep::<sha2::Sha256>()),
                    black_box(&data[..]),
                )
                .expect("failed to encrypt");
        })
    });

    // Verify that the data was changed.
    assert_ne!(&data[..], &enc_data[..]);

    let mut dec_data: Vec<u8> = vec![];

    c.bench_function("lib1 decrypt", |b| {
        b.iter(|| {
            dec_data = keys
                .priv_key
                .decrypt(
                    black_box(PaddingScheme::new_oaep::<sha2::Sha256>()),
                    black_box(&enc_data[..]),
                )
                .expect("failed to decrypt");
        })
    });

    assert_eq!(&data[..], &dec_data[..])
}

struct Lib2Keys {
    pub_key: rsa_oaep_pss::RsaPublicKey,
    priv_key: rsa_oaep_pss::RsaPrivateKey,
}

pub fn benchmark_rsa_lib2(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let mut keys: Option<Lib2Keys> = None;
    c.bench_function("lib 2 generate keys", |b| {
        b.iter(|| {
            let (pub_key, priv_key) =
                rsa_oaep_pss::generate_rsa_keys(black_box(&mut rng), black_box(2048))
                    .expect("keys generation error");
            keys = Some(Lib2Keys { pub_key, priv_key });
        })
    });

    let keys = keys.unwrap();
    let data = b"hello world";

    let mut cipher_text: Vec<u8> = vec![];

    c.bench_function("lib 2 encrypt", |b| {
        b.iter(|| {
            let mut oaep = rsa_oaep_pss::RsaOaep::new(
                black_box(rand::rngs::OsRng),
                black_box(&sha2::Sha256::new()),
            );

            cipher_text = oaep
                .encrypt(black_box(&keys.pub_key), black_box(data))
                .expect("encryption error");
        })
    });

    assert_ne!(&data[..], &cipher_text[..]);

    let mut dec_text: Vec<u8> = vec![];

    c.bench_function("lib 2 decrypt", |b| {
        b.iter(|| {
            let mut oaep = rsa_oaep_pss::RsaOaep::new(
                black_box(rand::rngs::OsRng),
                black_box(&sha2::Sha256::new()),
            );

            dec_text = oaep
                .decrypt(black_box(&keys.priv_key), black_box(&cipher_text))
                .expect("decryption error");
        })
    });

    assert_eq!(&data[..], &dec_text[..]);
}

criterion_group! {
    name= benches;
    config = Criterion::default().measurement_time(Duration::from_secs(100));
    targets = benchmark_rsa_lib1, benchmark_rsa_lib2
}
criterion_main!(benches);
