use criterion::{black_box, criterion_group, criterion_main, Criterion};
use silencia_identity::{Identity, Prover};

fn bench_identity_create(c: &mut Criterion) {
    c.bench_function("identity_create", |b| {
        b.iter(|| Identity::create(black_box("password123")))
    });
}

fn bench_proof_generation(c: &mut Criterion) {
    let prover = Prover::setup().unwrap();
    let identity = Identity::create("password123").unwrap();

    c.bench_function("proof_generate", |b| {
        b.iter(|| prover.prove(black_box(identity.secret()), black_box(&identity.id)))
    });
}

fn bench_proof_verification(c: &mut Criterion) {
    let prover = Prover::setup().unwrap();
    let identity = Identity::create("password123").unwrap();
    let proof = prover.prove(identity.secret(), &identity.id).unwrap();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    c.bench_function("proof_verify", |b| {
        b.iter(|| {
            prover.verify(
                black_box(&proof),
                black_box(&identity.id),
                black_box(timestamp),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_identity_create,
    bench_proof_generation,
    bench_proof_verification
);
criterion_main!(benches);
