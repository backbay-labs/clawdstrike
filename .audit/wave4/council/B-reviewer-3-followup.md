# Wave B Council — Reviewer 3 Follow-up

**HEAD:** ed5e1b918eaa02bd07c5392db0a87262754b64be
**Verdict:** CONCUR

## Dissent item 1: control-api Default clippy fix
**No .expect in Default impl:** PASS — `crates/services/control-api/src/config.rs:48-91` is the `impl Default for Config` block. Line 51 reads:
`listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),`
`grep "expect("` over the file returns 7 hits, all in the `#[cfg(test)] mod tests` block starting at line 467 (env-lock + `Config::from_env().expect(...)` test helpers). Zero `.expect` in the Default impl.

**cargo clippy clean:** PASS — `cargo clippy -p clawdstrike-control-api` finishes with `Finished dev profile`. The only diagnostic is the pre-existing `clippy::too_many_arguments` warning on `crates/services/control-api/src/routes/policies.rs:2380` (an `observe` method with 9 args). No new errors or warnings from the Default impl change.

**Default still 127.0.0.1:8080:** PASS — Default impl line 51 uses `SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)`. `Ipv4Addr::LOCALHOST` is `127.0.0.1`, port 8080. Functionally identical to the prior `"127.0.0.1:8080".parse()`. Confirmed at runtime by the existing test `default_config_binds_localhost_with_empty_cors_allowlist` at line 805 which asserts `config.listen_addr.to_string() == "127.0.0.1:8080"`.

## Dissent item 2: registry host default fix
**Default impl uses 127.0.0.1:** PASS — `crates/services/clawdstrike-registry/src/config.rs:27` reads `host: "127.0.0.1".to_string(),` inside `impl Default for Config { fn default() -> Self { Self { ... } } }`.

**from_env uses 127.0.0.1:** PASS — `crates/services/clawdstrike-registry/src/config.rs:52` reads `let host = std::env::var("CLAWDSTRIKE_REGISTRY_HOST").unwrap_or_else(|_| "127.0.0.1".into());`.

**default_host_binds_localhost test:** PASS — Located at `crates/services/clawdstrike-registry/src/config.rs:169-173`:
```
#[test]
fn default_host_binds_localhost() {
    let config = Config::default();
    assert_eq!(config.host, "127.0.0.1");
}
```
`cargo test -p clawdstrike-registry default_host_binds_localhost` output: `test config::tests::default_host_binds_localhost ... ok` — `1 passed; 0 failed`.

**Full registry suite:** 182 passed / 0 failed (plus a 5-filtered audit-monitor bin with 0 tests and a 1-test filter pass under main.rs). `cargo test -p clawdstrike-registry` ends with `test result: ok. 182 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out`.

## Sanity
**cargo check workspace:** PASS with 0 new errors. `cargo check --workspace --all-targets` finishes with `Finished dev profile`. `grep -E "^error"` over the output returns zero matches. Only diagnostics are the pre-existing `clawdstrike-policy-event` `edr/mod.rs` dead-code/unused-import warnings (44 warnings, 39 duplicates) which are out of scope and predate Wave B.

**git log scope (9f668a7c6..HEAD):**
```
ed5e1b918 feat(registry): bind localhost by default (security)
85ab8e6b5 fix(control-api): use const SocketAddr in Default::default
```
Exactly the two expected fix commits, nothing else.

## Final verdict
CONCUR
