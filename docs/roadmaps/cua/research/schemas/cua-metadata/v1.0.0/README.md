# CUA Metadata Schema v1.0.0

This directory contains the machine-checkable schema for the CUA metadata extension
embedded under `receipt.metadata` when `receipt_profile == "cua.v1"`.

Files:

- `cua-metadata.schema.json`: JSON Schema (draft 2020-12) for `receipt.metadata`.

Compatibility contract:

- Baseline receipts without `receipt_profile` remain valid via existing
  `SignedReceipt` validators.
- `receipt_profile` values other than `cua.v1` are unsupported and MUST fail closed.
- `cua_schema_version` values other than `1.0.0` are unsupported and MUST fail closed.
- Future additive fields must be introduced through explicit `extensions` objects.
