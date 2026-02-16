// Output Sanitization Example
//
// Demonstrates Clawdstrike's output sanitization pipeline:
//   1. Pattern-based detection of secrets, PII, and internal data
//   2. Entropy analysis for high-randomness tokens
//   3. Streaming sanitization with cross-boundary detection
//   4. Category isolation and allowlist/denylist controls
//
// The sanitizer scans LLM output before it reaches the user,
// replacing sensitive data with safe redaction placeholders.

import { OutputSanitizer } from "@clawdstrike/sdk";

// Realistic LLM output containing various categories of sensitive data.
// Each item matches a specific built-in detection pattern.
const llmOutput = `Here are the credentials you requested:

API Key: sk-abc123def456ghi789jkl012mno345pqr678stu901vwxyz12
GitHub Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij

Contact the admin at admin@internal-corp.com or call 555-867-5309.
The customer's card number is 4532015112830366.

Internal services are running at http://localhost:8080/api and
the database is at 192.168.1.100. Config is at /etc/myapp/secrets.yaml.`;

async function main() {
  console.log("=== Clawdstrike Output Sanitization Example ===\n");

  // ── Phase 1: Full Batch Sanitization ──────────────────────────────────────

  console.log("Phase 1: Full Batch Sanitization");
  console.log("\u2500".repeat(80));
  console.log("Input:");
  console.log(llmOutput);
  console.log();

  const sanitizer = new OutputSanitizer({
    categories: { secrets: true, pii: true, internal: true },
    entropy: { enabled: true, threshold: 4.5, minTokenLen: 32 },
  });

  const result = sanitizer.sanitizeSync(llmOutput);
  console.log("Sanitized output:");
  console.log(result.sanitized);
  console.log();

  // Findings table
  console.log("Findings:");
  console.log(
    "ID".padEnd(30) +
      "Category".padEnd(10) +
      "Type".padEnd(20) +
      "Conf".padEnd(6) +
      "Preview",
  );
  console.log("\u2500".repeat(80));
  for (const f of result.findings) {
    console.log(
      f.id.padEnd(30) +
        f.category.padEnd(10) +
        f.dataType.padEnd(20) +
        f.confidence.toFixed(2).padEnd(6) +
        f.preview,
    );
  }
  console.log(
    `\nStats: ${result.stats.findingsCount} findings, ` +
      `${result.stats.redactionsCount} redactions, ` +
      `${result.stats.processingTimeMs}ms`,
  );

  // ── Phase 2: Streaming Sanitization ───────────────────────────────────────

  console.log("\n\nPhase 2: Streaming Sanitization");
  console.log("\u2500".repeat(80));

  // Split a GitHub token across two chunks to demonstrate that the
  // streaming buffer correctly detects secrets spanning chunk boundaries.
  const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
  const fullText = `The token is ${token} and it's secret.`;
  const splitPoint = fullText.indexOf(token) + 10; // split mid-token
  const chunk1 = fullText.slice(0, splitPoint);
  const chunk2 = fullText.slice(splitPoint);

  console.log(`Chunk 1: "${chunk1}"`);
  console.log(`Chunk 2: "${chunk2}"`);

  const streamSanitizer = new OutputSanitizer({
    categories: { secrets: true, pii: true, internal: true },
    streaming: { enabled: true, bufferSize: 50_000, carryBytes: 512 },
  });
  const stream = streamSanitizer.createStream();

  // write() returns the safe-to-emit portion; for small inputs the
  // buffer carries everything until end().
  const out1 = stream.write(chunk1);
  const out2 = stream.write(chunk2);
  const finalResult = stream.end();

  console.log(`\nStream output 1: "${out1}"`);
  console.log(`Stream output 2: "${out2}"`);
  console.log(`Stream final:    "${finalResult.sanitized}"`);
  console.log(`Combined:        "${out1}${out2}${finalResult.sanitized}"`);
  console.log(
    `Findings: ${finalResult.findings.length} sensitive item(s) detected across chunk boundaries`,
  );

  // ── Phase 3: Category Isolation ───────────────────────────────────────────

  console.log("\n\nPhase 3: Category Isolation");
  console.log("\u2500".repeat(80));

  const categories = ["secrets", "pii", "internal"] as const;
  for (const cat of categories) {
    const catSanitizer = new OutputSanitizer({
      categories: {
        secrets: cat === "secrets",
        pii: cat === "pii",
        internal: cat === "internal",
      },
    });
    const catResult = catSanitizer.sanitizeSync(llmOutput);
    console.log(`\n[${cat} only] ${catResult.stats.findingsCount} findings:`);
    for (const f of catResult.findings) {
      console.log(`  ${f.id} (${f.dataType}): ${f.preview}`);
    }
  }

  // ── Phase 4: Allowlist / Denylist ─────────────────────────────────────────

  console.log("\n\nPhase 4: Allowlist / Denylist");
  console.log("\u2500".repeat(80));

  const customSanitizer = new OutputSanitizer({
    categories: { secrets: true, pii: true, internal: true },
    allowlist: { exact: ["admin@internal-corp.com"] },
    denylist: { patterns: [/PROJECT_ATLAS/g] },
  });

  const customInput = llmOutput + "\nThe codename is PROJECT_ATLAS.";
  const customResult = customSanitizer.sanitizeSync(customInput);

  // The allowlisted email should not appear in findings
  const emailFindings = customResult.findings.filter(
    (f) => f.dataType === "email",
  );
  console.log(
    `Email findings: ${emailFindings.length} (admin@internal-corp.com was allowlisted)`,
  );

  // The denylisted term should be caught
  const denylistFindings = customResult.findings.filter(
    (f) => f.detector === "denylist",
  );
  console.log(
    `Denylist findings: ${denylistFindings.length} (PROJECT_ATLAS matched)`,
  );
  for (const f of denylistFindings) {
    console.log(`  ${f.id}: ${f.preview}`);
  }

  // ── Summary ───────────────────────────────────────────────────────────────

  console.log("\n\n" + "\u2500".repeat(80));
  console.log("Summary");
  console.log("\u2500".repeat(80));
  console.log("Total categories: secrets, pii, internal");
  console.log(`Batch findings: ${result.stats.findingsCount}`);
  console.log(
    `Stream cross-boundary detection: ${finalResult.findings.length > 0 ? "working" : "none detected"}`,
  );
  console.log("Allowlist: admin@internal-corp.com excluded from findings");
  console.log("Denylist: PROJECT_ATLAS caught as custom sensitive term");

  console.log("\n=== Done ===");
}

main().catch(console.error);
