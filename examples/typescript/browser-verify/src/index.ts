/**
 * Browser-based receipt verification example
 *
 * This example shows how to verify hushclaw receipts in a web browser
 * using the TypeScript SDK with WASM.
 */

import { initWasm, verifyReceipt, Receipt } from '@hushclaw/sdk';

// DOM elements
const fileInput = document.getElementById('receipt-file') as HTMLInputElement;
const verifyButton = document.getElementById('verify-btn') as HTMLButtonElement;
const resultDiv = document.getElementById('result') as HTMLDivElement;

// Initialize WASM on page load
async function init() {
  try {
    await initWasm();
    console.log('WASM initialized');
    verifyButton.disabled = false;
  } catch (error) {
    console.error('Failed to initialize WASM:', error);
    resultDiv.innerHTML = '<p class="error">Failed to initialize. Please refresh.</p>';
  }
}

// Handle file selection
fileInput.addEventListener('change', () => {
  verifyButton.disabled = !fileInput.files?.length;
});

// Handle verification
verifyButton.addEventListener('click', async () => {
  const file = fileInput.files?.[0];
  if (!file) return;

  resultDiv.innerHTML = '<p>Verifying...</p>';

  try {
    // Read file
    const text = await file.text();
    const receipt: Receipt = JSON.parse(text);

    // Display receipt info
    let html = `
      <h3>Receipt Details</h3>
      <table>
        <tr><td>Run ID:</td><td>${receipt.run_id}</td></tr>
        <tr><td>Started:</td><td>${receipt.started_at}</td></tr>
        <tr><td>Ended:</td><td>${receipt.ended_at}</td></tr>
        <tr><td>Events:</td><td>${receipt.event_count}</td></tr>
        <tr><td>Denials:</td><td>${receipt.denied_count}</td></tr>
      </table>
    `;

    // Verify
    const result = verifyReceipt(receipt);

    if (result.valid) {
      html += `
        <div class="success">
          <h3>Verification Passed</h3>
          <p>Signature: VALID</p>
          <p>Merkle Root: VALID</p>
          <p>Receipt is authentic and unmodified.</p>
        </div>
      `;
    } else {
      html += `
        <div class="error">
          <h3>Verification Failed</h3>
          <p>${result.error}</p>
        </div>
      `;
    }

    resultDiv.innerHTML = html;
  } catch (error) {
    resultDiv.innerHTML = `<p class="error">Error: ${error}</p>`;
  }
});

// Initialize on load
init();
