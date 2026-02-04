#!/usr/bin/env node

const path = require('path');

const { importAdapterCore, importHushCliEngine, ensureHushBuilt } = require('./tools/sdk');

async function main() {
  const hushPath = ensureHushBuilt();

  const { PolicyEventFactory } = await importAdapterCore();
  const { createHushCliEngine } = await importHushCliEngine();

  const policyRef = path.join(__dirname, 'policy.yaml');
  const engine = createHushCliEngine({
    hushPath,
    policyRef,
    resolve: true,
    timeoutMs: 10_000,
  });

  const factory = new PolicyEventFactory();
  const sessionId = `sess-${Date.now()}`;

  const cases = [
    {
      label: 'Forbidden file read',
      toolName: 'read_file',
      params: { path: '/home/user/.ssh/id_rsa' },
    },
    {
      label: 'Allowed file read',
      toolName: 'read_file',
      params: { path: '/workspace/src/main.rs' },
    },
    {
      label: 'Allowed egress',
      toolName: 'http_request',
      params: { url: 'https://api.github.com' },
    },
    {
      label: 'Blocked egress',
      toolName: 'http_request',
      params: { url: 'https://pastebin.com/raw/abc123' },
    },
    {
      label: 'Patch apply (dangerous)',
      toolName: 'apply_patch',
      params: {
        path: '/workspace/src/app.ts',
        patch: 'diff --git a/x b/x\\n+ rm -rf /\\n',
      },
    },
  ];

  for (const t of cases) {
    const event = factory.create(t.toolName, t.params, sessionId);
    const decision = await engine.evaluate(event);

    const status = decision.denied ? 'DENY' : decision.warn ? 'WARN' : 'ALLOW';
    const guard = decision.guard ? ` (${decision.guard})` : '';
    const msg = decision.message ? `: ${decision.message}` : '';

    console.log(`${status}${guard} - ${t.label}${msg}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

