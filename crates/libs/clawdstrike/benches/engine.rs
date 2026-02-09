#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Criterion benchmarks for the clawdstrike policy engine.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use clawdstrike::engine::HushEngine;
use clawdstrike::guards::{GuardAction, GuardContext};
use clawdstrike::policy::Policy;

const SAMPLE_POLICY_YAML: &str = r#"
version: "1.1.0"
name: bench-policy
description: Benchmark policy
guards:
  forbidden_path:
    enabled: true
  egress_allowlist:
    enabled: true
  secret_leak:
    enabled: true
  patch_integrity:
    enabled: true
  mcp_tool:
    enabled: true
settings:
  fail_fast: false
"#;

fn bench_policy_parsing(c: &mut Criterion) {
    c.bench_function("policy_parse_yaml", |b| {
        b.iter(|| {
            let _policy = Policy::from_yaml(black_box(SAMPLE_POLICY_YAML)).unwrap();
        });
    });
}

fn bench_guard_forbidden_path(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let engine = HushEngine::new();
    let context = GuardContext::new();

    c.bench_function("guard_forbidden_path_allow", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = engine
                    .check_file_access(black_box("/app/src/main.rs"), &context)
                    .await;
            });
        });
    });

    c.bench_function("guard_forbidden_path_deny", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = engine
                    .check_file_access(black_box("/home/user/.ssh/id_rsa"), &context)
                    .await;
            });
        });
    });
}

fn bench_guard_egress(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let engine = HushEngine::new();
    let context = GuardContext::new();

    c.bench_function("guard_egress_allow", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = engine
                    .check_egress(black_box("api.openai.com"), 443, &context)
                    .await;
            });
        });
    });

    c.bench_function("guard_egress_deny", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = engine
                    .check_egress(black_box("evil.example.com"), 443, &context)
                    .await;
            });
        });
    });
}

fn bench_guard_secret_leak(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let engine = HushEngine::new();
    let context = GuardContext::new();

    let clean_diff = r#"
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
+fn main() { println!("hello"); }
"#;

    let leaky_diff = r#"
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
+api_key = "sk-0123456789abcdef0123456789abcdef0123456789abcdef"
"#;

    c.bench_function("guard_secret_leak_clean", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = engine
                    .check_patch(black_box("src/lib.rs"), black_box(clean_diff), &context)
                    .await;
            });
        });
    });

    c.bench_function("guard_secret_leak_detected", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = engine
                    .check_patch(black_box("src/lib.rs"), black_box(leaky_diff), &context)
                    .await;
            });
        });
    });
}

fn bench_guard_patch_integrity(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let engine = HushEngine::new();
    let context = GuardContext::new();

    let normal_diff = r#"
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,4 @@
 fn main() {
+    println!("hello");
 }
"#;

    c.bench_function("guard_patch_integrity", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = engine
                    .check_patch(black_box("src/lib.rs"), black_box(normal_diff), &context)
                    .await;
            });
        });
    });
}

fn bench_guard_mcp_tool(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let engine = HushEngine::new();
    let context = GuardContext::new();
    let args = serde_json::json!({"path": "/app/src/main.rs"});

    c.bench_function("guard_mcp_tool", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = engine
                    .check_mcp_tool(black_box("read_file"), black_box(&args), &context)
                    .await;
            });
        });
    });
}

fn bench_full_check_cycle(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    c.bench_function("full_cycle_parse_and_check", |b| {
        b.iter(|| {
            let policy = Policy::from_yaml(black_box(SAMPLE_POLICY_YAML)).unwrap();
            let engine = HushEngine::with_policy(policy);
            let context = GuardContext::new();
            rt.block_on(async {
                let _ = engine
                    .check_action(
                        black_box(&GuardAction::FileAccess("/app/src/main.rs")),
                        &context,
                    )
                    .await;
            });
        });
    });
}

criterion_group!(
    benches,
    bench_policy_parsing,
    bench_guard_forbidden_path,
    bench_guard_egress,
    bench_guard_secret_leak,
    bench_guard_patch_integrity,
    bench_guard_mcp_tool,
    bench_full_check_cycle,
);
criterion_main!(benches);
