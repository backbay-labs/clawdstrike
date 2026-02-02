/**
 * Browser-based receipt verification example
 *
 * This example verifies hushclaw SignedReceipts in a web browser
 * using the TypeScript SDK (pure JS crypto).
 */

import { SignedReceipt, type PublicKeySet } from '@hushclaw/sdk';

// DOM elements
const fileInput = document.getElementById('receipt-file') as HTMLInputElement;
const signerPkInput = document.getElementById('signer-pk') as HTMLInputElement;
const cosignerPkInput = document.getElementById('cosigner-pk') as HTMLInputElement;
const verifyButton = document.getElementById('verify-btn') as HTMLButtonElement;
const resultDiv = document.getElementById('result') as HTMLDivElement;

function canVerify(): boolean {
  return Boolean(fileInput.files?.length) && signerPkInput.value.trim().length > 0;
}

function refreshVerifyEnabled(): void {
  verifyButton.disabled = !canVerify();
}

fileInput.addEventListener('change', refreshVerifyEnabled);
signerPkInput.addEventListener('input', refreshVerifyEnabled);
cosignerPkInput.addEventListener('input', refreshVerifyEnabled);

// Handle verification
verifyButton.addEventListener('click', async () => {
  const file = fileInput.files?.[0];
  if (!file) return;

  resultDiv.innerHTML = '<p>Verifying...</p>';

  try {
    // Read file
    const text = await file.text();
    const signed = SignedReceipt.fromJSON(text);

    const publicKeys: PublicKeySet = {
      signer: signerPkInput.value.trim(),
      cosigner: cosignerPkInput.value.trim() || undefined,
    };

    // Display receipt info
    let html = `
      <h3>Receipt Details</h3>
      <table>
        <tr><td>Version:</td><td>${signed.receipt.version}</td></tr>
        <tr><td>Receipt ID:</td><td>${signed.receipt.receiptId ?? '(none)'}</td></tr>
        <tr><td>Timestamp:</td><td>${signed.receipt.timestamp}</td></tr>
        <tr><td>Content Hash:</td><td><code>${signed.receipt.contentHash}</code></td></tr>
        <tr><td>Verdict:</td><td>${signed.receipt.verdict.passed ? 'PASS' : 'FAIL'}</td></tr>
      </table>
    `;

    // Verify
    const result = await signed.verify(publicKeys);

    if (result.valid) {
      html += `
        <div class="success">
          <h3>Verification Passed</h3>
          <p>Signature: VALID</p>
          <p>Receipt is authentic and unmodified.</p>
        </div>
      `;
    } else {
      html += `
        <div class="error">
          <h3>Verification Failed</h3>
          <p>${result.errors.join('<br>')}</p>
        </div>
      `;
    }

    resultDiv.innerHTML = html;
  } catch (error) {
    resultDiv.innerHTML = `<p class="error">Error: ${error}</p>`;
  }
});

refreshVerifyEnabled();
