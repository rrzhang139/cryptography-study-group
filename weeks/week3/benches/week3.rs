use criterion::{black_box, criterion_group, criterion_main, Criterion};

use blake3::hash;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};

const INPUT: &[u8] = b"abc";

fn blake3_hash(c: &mut Criterion) {
    c.bench_function("blake3 hash", |b| b.iter(|| hash(black_box(INPUT))));
}

fn sha3_256(c: &mut Criterion) {
    c.bench_function("sha3 256", |b| {
        b.iter(|| {
            let mut hasher = Sha3_256::new();

            // write input message
            hasher.update(black_box(INPUT));

            // read hash digest
            hasher.finalize();
        })
    });
}

fn sha2_256(c: &mut Criterion) {
    c.bench_function("sha2 256", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();

            // write input message
            hasher.update(black_box(INPUT));

            // read hash digest
            hasher.finalize();
        })
    });
}

criterion_group!(benches, blake3_hash, sha3_256, sha2_256);

criterion_main!(benches);
