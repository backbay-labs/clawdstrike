#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Criterion benchmarks for hush-core cryptographic primitives.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use hush_core::canonical::canonicalize;
use hush_core::merkle::MerkleTree;
use hush_core::receipt::{Receipt, Verdict};
use hush_core::signing::Keypair;
use hush_core::{keccak256, sha256, SignedReceipt};

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");
    for size in [32, 256, 1024, 4096, 16384] {
        let data = vec![0xABu8; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| sha256(black_box(data)));
        });
    }
    group.finish();
}

fn bench_keccak256(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak256");
    for size in [32, 256, 1024, 4096, 16384] {
        let data = vec![0xABu8; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| keccak256(black_box(data)));
        });
    }
    group.finish();
}

fn bench_signing(c: &mut Criterion) {
    let keypair = Keypair::generate();
    let message = b"benchmark message for signing";

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| keypair.sign(black_box(message)));
    });

    let signature = keypair.sign(message);
    let pubkey = keypair.public_key();

    c.bench_function("ed25519_verify", |b| {
        b.iter(|| pubkey.verify(black_box(message), black_box(&signature)));
    });
}

fn bench_receipt_sign_verify(c: &mut Criterion) {
    let keypair = Keypair::generate();
    let content_hash = sha256(b"benchmark content");

    let receipt = Receipt::new(content_hash, Verdict::pass());

    c.bench_function("receipt_sign", |b| {
        b.iter(|| {
            let _ = SignedReceipt::sign(black_box(receipt.clone()), &keypair);
        });
    });

    let signed = SignedReceipt::sign(receipt, &keypair).unwrap();
    let keys = hush_core::receipt::PublicKeySet::new(keypair.public_key());

    c.bench_function("receipt_verify", |b| {
        b.iter(|| {
            let _ = signed.verify(black_box(&keys));
        });
    });
}

fn bench_canonical_json(c: &mut Criterion) {
    let small = serde_json::json!({
        "action": "file_access",
        "path": "/app/src/main.rs",
        "allowed": true,
    });

    let medium = serde_json::json!({
        "version": "1.0.0",
        "receipt_id": "test-receipt-001",
        "timestamp": "2026-01-01T00:00:00Z",
        "content_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "verdict": { "passed": true, "gate_id": "test-gate" },
        "provenance": {
            "clawdstrike_version": "0.1.0",
            "provider": "local",
            "policy_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "ruleset": "default",
        },
    });

    c.bench_function("canonical_json_small", |b| {
        b.iter(|| canonicalize(black_box(&small)).unwrap());
    });

    c.bench_function("canonical_json_medium", |b| {
        b.iter(|| canonicalize(black_box(&medium)).unwrap());
    });
}

fn bench_merkle_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_tree");

    for leaf_count in [4, 16, 64, 256] {
        let leaves: Vec<Vec<u8>> = (0..leaf_count)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();

        group.bench_with_input(
            BenchmarkId::new("build", leaf_count),
            &leaves,
            |b, leaves| {
                b.iter(|| MerkleTree::from_leaves(black_box(leaves)).unwrap());
            },
        );
    }
    group.finish();

    let leaves: Vec<Vec<u8>> = (0..64).map(|i| format!("leaf-{i}").into_bytes()).collect();
    let tree = MerkleTree::from_leaves(&leaves).unwrap();
    let root = tree.root();
    let proof = tree.inclusion_proof(32).unwrap();

    c.bench_function("merkle_proof_generate", |b| {
        b.iter(|| tree.inclusion_proof(black_box(32)).unwrap());
    });

    c.bench_function("merkle_proof_verify", |b| {
        b.iter(|| proof.verify(black_box(&leaves[32]), black_box(&root)));
    });
}

criterion_group!(
    benches,
    bench_sha256,
    bench_keccak256,
    bench_signing,
    bench_receipt_sign_verify,
    bench_canonical_json,
    bench_merkle_tree,
);
criterion_main!(benches);
