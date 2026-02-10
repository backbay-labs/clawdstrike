# @clawdstrike/sdk

Official TypeScript SDK for Clawdstrike cryptography, receipts, and policy-check helper APIs.

## Install

```bash
npm install @clawdstrike/sdk
```

## Quick start

```ts
import { Clawdstrike } from '@clawdstrike/sdk';

const cs = Clawdstrike.withDefaults('strict');
const decision = await cs.checkFile('~/.ssh/id_rsa', 'read');

if (decision.status === 'deny') {
  console.error(decision.message);
}
```

## What is included

- Unified helper API (`Clawdstrike.withDefaults`, `fromPolicy`, `fromDaemon`)
- Cryptographic primitives (SHA-256, Keccak-256, Ed25519)
- Canonical JSON + Merkle helpers
- Receipt signing/verification types and helpers
- Guard utilities and prompt-security utilities
- Adapter-core re-exports under `adapters`

## Common imports

```ts
import { sha256, canonicalize, Receipt } from '@clawdstrike/sdk';
import { adapters } from '@clawdstrike/sdk';
```

## Scope

`@clawdstrike/sdk` is intentionally broad utility surface. If you need framework-specific enforcement wrappers, use the adapter packages (`@clawdstrike/vercel-ai`, `@clawdstrike/langchain`, etc.).
