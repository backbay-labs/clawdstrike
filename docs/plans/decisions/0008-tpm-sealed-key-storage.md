# 0008 — TPM-sealed key storage (Ed25519 seed)

## Status
Accepted

## Context
Receipts are signed with Ed25519. TPM2 does not natively sign Ed25519, but can seal/unseal a seed.

## Decision
Implement TPM-sealed seed storage:

- Generate 32-byte seed
- Seal it in TPM with a policy (PCR policy optional later)
- At signing time, unseal seed, sign in-memory, then drop seed

This preserves Ed25519 compatibility across SDKs.

