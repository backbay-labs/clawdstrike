# Certification & Compliance (Specs)

This folder contains the source-of-truth product/engineering specs for the Clawdstrike
Certification & Compliance program:

- `overview.md` — program goals, tiers, and verification concepts
- `audit-framework.md` — tamper-evident audit model + evidence bundle format
- `certification-api.md` — `/v1/*` Certification API surface
- `certified-badge.md` — badge cryptography + lifecycle
- `hipaa-template.md` / `pci-dss-template.md` / `soc2-template.md` — compliance templates

## Code mapping (intended)

- Server/API: `crates/hushd/`
- Policy/guards: `crates/clawdstrike/`
- Crypto primitives (JCS, Ed25519, Merkle): `crates/hush-core/`
- TypeScript SDK: `packages/hush-ts/` (`@clawdstrike/sdk`)
- Python SDK: `packages/hush-py/`

## Notes

These docs are imported verbatim from a local working set and may reference legacy names such as
`OpenClaw` and example domains. Implementation should adapt naming to this repo (`hush`, `hushd`,
`clawdstrike`) while preserving the specified wire formats and cryptographic behaviors.
