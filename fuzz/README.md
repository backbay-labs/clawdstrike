# Fuzz

Rust fuzzing harnesses and targets for security-critical surfaces.

Layout:

1. `fuzz/fuzz_targets/` - fuzz entrypoints.

Typical workflow:

1. `cargo install cargo-fuzz --locked`
2. `cd fuzz && cargo +nightly fuzz run <target>`
