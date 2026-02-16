import { PromptWatermarker, WatermarkExtractor } from '@clawdstrike/sdk';

async function main() {
  console.log('=== Clawdstrike Prompt Watermarking Example ===\n');

  // ── Phase 1: Basic round-trip ──────────────────────────────────────────
  console.log('Phase 1: Basic Watermark Round-Trip');
  console.log('\u2500'.repeat(70));

  const watermarker = await PromptWatermarker.create({
    customMetadata: { department: 'security', environment: 'production' },
  });

  const prompt = 'Summarize the quarterly earnings report for Q4 2025.';
  const payload = watermarker.generatePayload('finance-app', 'session-001');
  const result = await watermarker.watermark(prompt, payload);

  console.log(`Original:     "${result.original}"`);
  console.log(`Watermarked:  "${result.watermarked.slice(0, 80)}..."`);
  console.log(`Public Key:   ${watermarker.publicKeyHex().slice(0, 16)}...`);
  console.log(`Signature:    ${result.watermark.signature.slice(0, 16)}...`);
  console.log(`Payload:`);
  console.log(`  Application: ${result.watermark.payload.applicationId}`);
  console.log(`  Session:     ${result.watermark.payload.sessionId}`);
  console.log(`  Sequence:    ${result.watermark.payload.sequenceNumber}`);
  console.log(`  Metadata:    ${JSON.stringify(result.watermark.payload.metadata)}`);

  // Extract and verify
  const extractor = new WatermarkExtractor({
    trustedPublicKeys: [watermarker.publicKeyHex()],
  });
  const extracted = await extractor.extract(result.watermarked);
  console.log(`\nExtraction:`);
  console.log(`  Found:    ${extracted.found}`);
  console.log(`  Verified: ${extracted.verified}`);
  console.log(`  Errors:   ${extracted.errors.length === 0 ? 'none' : extracted.errors.join(', ')}`);

  // ── Phase 2: Custom metadata ───────────────────────────────────────────
  console.log('\n\nPhase 2: Custom Metadata');
  console.log('\u2500'.repeat(70));

  const metaWatermarker = await PromptWatermarker.create({
    customMetadata: {
      department: 'engineering',
      model: 'claude-opus-4-6',
      compliance: 'SOC2',
      region: 'us-east-1',
    },
  });

  const metaPayload = metaWatermarker.generatePayload('compliance-checker', 'audit-session-1');
  const metaResult = await metaWatermarker.watermark(
    'Check system compliance with SOC2 requirements.',
    metaPayload,
  );

  const metaExtractor = new WatermarkExtractor({
    trustedPublicKeys: [metaWatermarker.publicKeyHex()],
  });
  const metaExtracted = await metaExtractor.extract(metaResult.watermarked);

  console.log('Embedded metadata recovered:');
  if (metaExtracted.watermark?.payload.metadata) {
    for (const [k, v] of Object.entries(metaExtracted.watermark.payload.metadata)) {
      console.log(`  ${k}: ${v}`);
    }
  }

  // ── Phase 3: Multi-agent forensics ─────────────────────────────────────
  console.log('\n\nPhase 3: Multi-Agent Attribution');
  console.log('\u2500'.repeat(70));

  const agents = [
    { name: 'agent-planner', prompt: 'Create a deployment plan for the new microservice.' },
    { name: 'agent-coder', prompt: 'Implement the REST API endpoint for user registration.' },
    { name: 'agent-reviewer', prompt: 'Review the pull request for security vulnerabilities.' },
  ];

  // Create a watermarker per agent (each gets its own keypair)
  const agentWatermarkers = await Promise.all(
    agents.map((a) =>
      PromptWatermarker.create({ customMetadata: { agent: a.name } }),
    ),
  );

  // Watermark each agent's prompt
  const watermarkedPrompts = await Promise.all(
    agents.map(async (a, i) => {
      const wm = agentWatermarkers[i];
      const p = wm.generatePayload('multi-agent-system', 'collab-session-1');
      return {
        agent: a.name,
        result: await wm.watermark(a.prompt, p),
        publicKey: wm.publicKeyHex(),
      };
    }),
  );

  // Build a universal extractor that trusts all agents
  const allKeys = agentWatermarkers.map((w) => w.publicKeyHex());
  const forensicExtractor = new WatermarkExtractor({ trustedPublicKeys: allKeys });

  // Attribution table
  console.log(
    'Agent'.padEnd(18) +
    'Public Key'.padEnd(20) +
    'Verified'.padEnd(10) +
    'Prompt (truncated)',
  );
  console.log('\u2500'.repeat(70));

  for (const wp of watermarkedPrompts) {
    const ex = await forensicExtractor.extract(wp.result.watermarked);
    const matchedAgent = watermarkedPrompts.find(
      (w) => w.publicKey === ex.watermark?.publicKey,
    );
    console.log(
      (matchedAgent?.agent ?? 'unknown').padEnd(18) +
      ((ex.watermark?.publicKey.slice(0, 16) ?? '') + '...').padEnd(20) +
      String(ex.verified).padEnd(10) +
      wp.result.original.slice(0, 40),
    );
  }

  // ── Phase 4: Trust verification ────────────────────────────────────────
  console.log('\n\nPhase 4: Trust Verification');
  console.log('\u2500'.repeat(70));

  // Extractor that only trusts agent-planner
  const strictExtractor = new WatermarkExtractor({
    trustedPublicKeys: [agentWatermarkers[0].publicKeyHex()],
    allowUnverified: false,
  });

  console.log('Strict extractor (only trusts agent-planner):');
  for (const wp of watermarkedPrompts) {
    const ex = await strictExtractor.extract(wp.result.watermarked);
    const label = ex.verified ? 'TRUSTED' : 'REJECTED';
    console.log(
      `  ${wp.agent.padEnd(18)} ${label.padEnd(10)} errors: ${ex.errors.length === 0 ? 'none' : ex.errors.join(', ')}`,
    );
  }

  // Now with allowUnverified
  const lenientExtractor = new WatermarkExtractor({
    trustedPublicKeys: [agentWatermarkers[0].publicKeyHex()],
    allowUnverified: true,
  });

  console.log('\nLenient extractor (allowUnverified: true):');
  for (const wp of watermarkedPrompts) {
    const ex = await lenientExtractor.extract(wp.result.watermarked);
    const label = ex.verified ? 'TRUSTED' : 'UNVERIFIED';
    console.log(
      `  ${wp.agent.padEnd(18)} ${label.padEnd(12)} found: ${ex.found}  errors: ${ex.errors.length === 0 ? 'none' : ex.errors.join(', ')}`,
    );
  }

  // ── Phase 5: Fingerprint correlation ───────────────────────────────────
  console.log('\n\nPhase 5: Fingerprint Correlation');
  console.log('\u2500'.repeat(70));

  const sessionWatermarker = await PromptWatermarker.create({
    customMetadata: { pipeline: 'data-analysis' },
  });

  const sessionPrompts = [
    'Load the dataset from S3.',
    'Clean and normalize the data.',
    'Generate the summary report.',
  ];

  const sessionId = 'pipeline-run-42';
  const fpExtractor = new WatermarkExtractor({
    trustedPublicKeys: [sessionWatermarker.publicKeyHex()],
  });

  console.log('Seq'.padEnd(5) + 'Fingerprint'.padEnd(22) + 'Prompt');
  console.log('\u2500'.repeat(70));

  for (const p of sessionPrompts) {
    const pl = sessionWatermarker.generatePayload('pipeline', sessionId);
    const wResult = await sessionWatermarker.watermark(p, pl);
    const exResult = await fpExtractor.extract(wResult.watermarked);
    if (exResult.watermark) {
      const fp = fpExtractor.fingerprint(exResult.watermark);
      console.log(
        String(exResult.watermark.payload.sequenceNumber).padEnd(5) +
        (fp.slice(0, 16) + '...').padEnd(22) +
        p,
      );
    }
  }

  console.log(
    `\nAll fingerprints are unique but share the same session ID ("${sessionId}"),`,
  );
  console.log('enabling correlation of watermarks within a pipeline run.');

  console.log('\n=== Done ===');
}

main().catch(console.error);
