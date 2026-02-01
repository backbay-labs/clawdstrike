# TypeScript API

TypeScript/JavaScript SDK for hushclaw.

## Installation

```bash
npm install @hushclaw/sdk
# or
yarn add @hushclaw/sdk
# or
pnpm add @hushclaw/sdk
```

## Quick Start

```typescript
import { HushEngine, Policy, Event, Decision } from '@hushclaw/sdk';

// Load policy
const policy = await Policy.fromYamlFile('./policy.yaml');

// Create engine
const engine = new HushEngine(policy);

// Create event
const event: Event = {
  event_id: crypto.randomUUID(),
  event_type: 'file_read',
  timestamp: new Date().toISOString(),
  data: {
    path: '~/.ssh/id_rsa',
  },
};

// Evaluate
const decision = await engine.evaluate(event);

if (decision.type === 'deny') {
  console.log(`Blocked: ${decision.reason}`);
}
```

## HushEngine

### Constructor

```typescript
const engine = new HushEngine(policy, {
  mode: 'deterministic', // or 'advisory', 'audit'
  guards: customGuards,
});
```

### Evaluation

```typescript
// Single event
const decision = await engine.evaluate(event);

// Batch
const decisions = await engine.evaluateBatch(events);

// Check if allowed
if (engine.isAllowed(event)) {
  // proceed
}
```

### Policy Management

```typescript
// Load from file
const policy = await Policy.fromYamlFile('./policy.yaml');

// Load from string
const policy = Policy.fromYaml(yamlString);

// Load from object
const policy = new Policy({
  version: 'hushclaw-v1.0',
  egress: {
    mode: 'allowlist',
    allowed_domains: ['api.github.com'],
  },
});

// Update engine policy
engine.setPolicy(newPolicy);
```

## Event Types

```typescript
import { Event, EventType } from '@hushclaw/sdk';

// File events
const fileRead: Event = {
  event_id: crypto.randomUUID(),
  event_type: 'file_read',
  timestamp: new Date().toISOString(),
  data: { path: '/path/to/file' },
};

// Network events
const networkEvent: Event = {
  event_id: crypto.randomUUID(),
  event_type: 'network_egress',
  timestamp: new Date().toISOString(),
  data: { host: 'api.github.com', port: 443 },
};

// Tool events
const toolEvent: Event = {
  event_id: crypto.randomUUID(),
  event_type: 'tool_call',
  timestamp: new Date().toISOString(),
  data: {
    tool_name: 'write_file',
    parameters: { path: './output.txt', content: 'hello' },
  },
};

// Helpers
import { createFileReadEvent, createEgressEvent } from '@hushclaw/sdk';

const event = createFileReadEvent('~/.ssh/id_rsa');
const event = createEgressEvent('api.github.com', 443);
```

## Decision Types

```typescript
import { Decision, Severity } from '@hushclaw/sdk';

const decision = await engine.evaluate(event);

switch (decision.type) {
  case 'allow':
    console.log('Allowed');
    break;
  case 'warn':
    console.log(`Warning: ${decision.message}`);
    break;
  case 'deny':
    console.log(`Denied: ${decision.reason}`);
    console.log(`Guard: ${decision.guard}`);
    console.log(`Severity: ${decision.severity}`);
    break;
}

// Type guards
import { isAllowed, isDenied } from '@hushclaw/sdk';

if (isAllowed(decision)) {
  // TypeScript knows decision is Allow or Warn
}

if (isDenied(decision)) {
  // TypeScript knows decision.reason exists
}
```

## Crypto

```typescript
import {
  generateKeypair,
  sign,
  verify,
  sha256,
  MerkleTree,
} from '@hushclaw/sdk';

// Generate keypair
const keypair = generateKeypair();
console.log(keypair.publicKey); // hex string

// Sign
const signature = sign(keypair.privateKey, 'data');

// Verify
const valid = verify(keypair.publicKey, 'data', signature);

// Hash
const hash = sha256('data');

// Merkle tree
const tree = new MerkleTree(hashes);
const root = tree.root;
const proof = tree.prove(index);
const valid = tree.verify(hash, proof);
```

## Receipt Verification

```typescript
import { verifyReceipt, Receipt } from '@hushclaw/sdk';

const receipt: Receipt = JSON.parse(receiptJson);

const result = verifyReceipt(receipt);

if (result.valid) {
  console.log('Receipt is authentic');
  console.log(`Run ID: ${receipt.run_id}`);
  console.log(`Events: ${receipt.events.length}`);
} else {
  console.log(`Invalid: ${result.error}`);
}
```

## Browser Usage

The SDK works in browsers via WASM:

```typescript
import { initWasm, HushEngine } from '@hushclaw/sdk';

// Initialize WASM (required once)
await initWasm();

// Then use normally
const engine = new HushEngine(policy);
```

## React Hooks

```typescript
import { useHush, useVerify } from '@hushclaw/react';

function Component() {
  const { evaluate, isLoading } = useHush(policy);
  const { verify, result } = useVerify();

  const handleAction = async () => {
    const decision = await evaluate(event);
    if (decision.type === 'deny') {
      alert(decision.reason);
    }
  };
}
```

## TypeScript Types

```typescript
import type {
  Event,
  EventType,
  EventData,
  FileEventData,
  NetworkEventData,
  ToolEventData,
  Decision,
  Severity,
  Policy,
  EgressPolicy,
  FilesystemPolicy,
  Receipt,
} from '@hushclaw/sdk';
```

## Error Handling

```typescript
import { HushError, PolicyError, CryptoError } from '@hushclaw/sdk';

try {
  const policy = await Policy.fromYamlFile('./policy.yaml');
} catch (error) {
  if (error instanceof PolicyError) {
    console.log(`Policy error: ${error.message}`);
  } else if (error instanceof CryptoError) {
    console.log(`Crypto error: ${error.message}`);
  } else {
    throw error;
  }
}
```

## Examples

See [TypeScript examples](https://github.com/hushclaw/hushclaw/tree/main/examples/typescript).
