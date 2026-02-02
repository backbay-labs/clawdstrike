# API Reference

Hushclaw’s stable surface area today is the Rust crates and the `hush` CLI.

## Rust crates

- `hushclaw`: policy type, built-in guards, and `HushEngine`
- `hush-core`: hashing/signing, Merkle trees, and `SignedReceipt`
- `hush-proxy`: domain matching + DNS/SNI parsing utilities

## CLI

The `hush` binary is provided by the `hush-cli` crate.

## TypeScript / Python

This repo contains experimental SDKs under `packages/`. They are not yet guaranteed to match the Rust policy schema or receipt schema described in this mdBook.

## Next Steps

- [Rust API](./rust.md)
- [CLI Reference](./cli.md)
- [TypeScript (experimental)](./typescript.md)
