# Browser Receipt Verification Example

Demonstrates how to verify hushclaw receipts in a web browser using the TypeScript SDK with WASM.

## What It Does

1. User selects a receipt JSON file
2. WASM module verifies the Ed25519 signature
3. WASM module validates the Merkle root
4. Results display in the browser

## Prerequisites

- Node.js 18+
- A hushclaw receipt file (`.json`)

## Setup

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

Open http://localhost:5173 in your browser.

## Usage

1. Click "Choose File" and select a receipt JSON file
2. Click "Verify Receipt"
3. View the verification results

## How It Works

The example uses the `@hushclaw/sdk` package which includes WASM bindings for cryptographic verification:

```typescript
import { initWasm, verifyReceipt, Receipt } from '@hushclaw/sdk';

// Initialize WASM (required once)
await initWasm();

// Parse and verify
const receipt: Receipt = JSON.parse(jsonText);
const result = verifyReceipt(receipt);

if (result.valid) {
  console.log('Receipt is authentic');
} else {
  console.error('Verification failed:', result.error);
}
```

## Sample Receipt

Create a `sample-receipt.json` file:

```json
{
  "run_id": "run_abc123",
  "started_at": "2026-01-31T14:00:00Z",
  "ended_at": "2026-01-31T14:30:00Z",
  "events": [],
  "event_count": 127,
  "denied_count": 2,
  "merkle_root": "0x7f3a4b2c...",
  "signature": "ed25519:abc...",
  "public_key": "ed25519:xyz..."
}
```

## Build for Production

```bash
npm run build
npm run preview
```

The build output will be in the `dist/` directory, ready for static hosting.

## Browser Compatibility

- Chrome 89+
- Firefox 89+
- Safari 15+
- Edge 89+

All modern browsers with WebAssembly support are compatible.
