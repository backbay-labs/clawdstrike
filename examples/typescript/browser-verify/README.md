# Browser Receipt Verification Example

Demonstrates how to verify clawdstrike **SignedReceipts** in a web browser using the TypeScript SDK (pure JS crypto).

## What It Does

1. User selects a receipt JSON file
2. User provides the signer public key (hex)
3. The SDK verifies the Ed25519 signature over canonical JSON (RFC 8785 / JCS)
4. Results display in the browser

## Prerequisites

- Node.js 18+
- A clawdstrike receipt file (`.json`)

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

The example uses the `@clawdstrike/sdk` package:

```typescript
import { SignedReceipt } from '@clawdstrike/sdk';

const signed = SignedReceipt.fromJSON(jsonText);
const result = await signed.verify({ signer: signerPublicKeyHex });

if (result.valid) {
  console.log('Receipt is authentic');
} else {
  console.error('Verification failed:', result.errors);
}
```

## Sample Receipt

Create a `sample-receipt.json` file:

```json
{
  "receipt": {
    "version": "1.0.0",
    "receipt_id": "run_abc123",
    "timestamp": "2026-01-31T14:00:00Z",
    "content_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "verdict": { "passed": true }
  },
  "signatures": {
    "signer": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

Note: this sample will **not** verify unless the signature matches the receipt content and the signer public key you provide.

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

All modern browsers with ES modules are compatible.
