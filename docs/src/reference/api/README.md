# API Reference

Clawdstrike's stable surface area today is the Rust crates and the `clawdstrike` CLI.

## Rust crates

- `clawdstrike`: policy type, built-in guards, and `HushEngine`
- `hush-core`: hashing/signing, Merkle trees, and `SignedReceipt`
- `hush-proxy`: domain matching + DNS/SNI parsing utilities

## CLI

The `clawdstrike` binary is provided by the `hush-cli` crate.

## TypeScript / Python / Go

This repo contains SDKs under `packages/`. Receipts/crypto are intended to be compatible across languages, but policy-evaluation support still varies by runtime:

- TypeScript uses bridges to the Rust engine or `hushd` for authoritative policy evaluation.
- Python supports origin-aware enforcement on the bundled native backend and on `hushd`; the pure-Python backend fails closed for `policy.origins`.
- Go supports origin-aware enforcement through `hushd`; local Go engine usage fails closed for origin-aware requests until local-engine parity exists.

## Next Steps

- [Rust API](./rust.md)
- [CLI Reference](./cli.md)
- [TypeScript (experimental)](./typescript.md)
- [Python](./python.md)
- [Go](./go.md)
