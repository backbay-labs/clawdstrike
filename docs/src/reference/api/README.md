# API Reference

Clawdstrike's stable surface area today is the Rust crates and the `clawdstrike` CLI.

## Rust crates

- `clawdstrike`: policy type, built-in guards, and `HushEngine`
- `hush-core`: hashing/signing, Merkle trees, and `SignedReceipt`
- `hush-proxy`: domain matching + DNS/SNI parsing utilities

## CLI

The `clawdstrike` binary is provided by the `hush-cli` crate.

## TypeScript / Python

This repo contains experimental SDKs under `packages/`. Receipts/crypto are intended to be compatible across languages, but full policy-evaluation parity with the Rust engine is not yet guaranteed.

## Next Steps

- [Rust API](./rust.md)
- [CLI Reference](./cli.md)
- [TypeScript (experimental)](./typescript.md)
