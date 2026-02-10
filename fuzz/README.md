# Fuzz

Rust fuzzing harnesses and targets for security-critical surfaces.

Layout:

1. `fuzz/fuzz_targets/` - fuzz entrypoints.
2. `fuzz/corpus/<target>/` - seed corpora per fuzz target.

Typical workflow:

1. `cargo install cargo-fuzz --locked`
2. `cd fuzz && cargo +nightly fuzz run <target>`

## Targets

- `fuzz_policy_parse`
- `fuzz_dns_parse`
- `fuzz_sni_parse`
- `fuzz_secret_leak`
- `fuzz_sha256`
- `fuzz_merkle`
- `fuzz_irm_fs_parse`
- `fuzz_irm_net_parse`
- `fuzz_remote_extends_parse`

## PR Smoke (recommended local parity with CI)

```bash
cd fuzz
cargo +nightly fuzz run fuzz_policy_parse -- -max_total_time=30
cargo +nightly fuzz run fuzz_irm_net_parse -- -max_total_time=30
cargo +nightly fuzz run fuzz_remote_extends_parse -- -max_total_time=30
```
