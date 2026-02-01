#!/usr/bin/env node

/**
 * Hello Secure Agent
 *
 * A minimal demonstration of an OpenClaw agent with hushclaw security.
 * This script simulates agent behavior for testing purposes.
 */

const fs = require('fs');
const path = require('path');

// Simulated hushclaw client (in production, use @hushclaw/sdk)
class HushclawClient {
  constructor(endpoint) {
    this.endpoint = endpoint || 'localhost:9090';
    this.events = [];
  }

  async checkTool(tool, args) {
    const event = {
      timestamp: new Date().toISOString(),
      tool,
      args,
      decision: 'pending',
    };

    // Simulate policy check
    if (tool === 'execute_command') {
      event.decision = 'deny';
      event.reason = 'Shell execution disabled for security';
    } else if (tool === 'write_file' && !args.path.startsWith('./output/')) {
      event.decision = 'deny';
      event.reason = 'Write path not allowed';
    } else {
      event.decision = 'allow';
    }

    this.events.push(event);
    console.log(`[hush] ${event.decision.toUpperCase()}: ${tool}(${JSON.stringify(args)})`);

    return event.decision === 'allow';
  }

  async generateReceipt() {
    const receipt = {
      run_id: `run_${Date.now()}`,
      started_at: this.events[0]?.timestamp || new Date().toISOString(),
      ended_at: new Date().toISOString(),
      events: this.events,
      event_count: this.events.length,
      denied_count: this.events.filter((e) => e.decision === 'deny').length,
      merkle_root: '0x' + Buffer.from(JSON.stringify(this.events)).toString('hex').slice(0, 64),
      signature: 'ed25519:simulated_signature',
      public_key: 'ed25519:simulated_public_key',
    };

    return receipt;
  }
}

// Simulated tool implementations
const tools = {
  async read_file(hush, filePath) {
    const allowed = await hush.checkTool('read_file', { path: filePath });
    if (!allowed) throw new Error('Access denied by hushclaw');

    return fs.readFileSync(filePath, 'utf-8');
  },

  async write_file(hush, filePath, content) {
    const allowed = await hush.checkTool('write_file', { path: filePath });
    if (!allowed) throw new Error('Access denied by hushclaw');

    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(filePath, content);
    return `Wrote ${content.length} bytes to ${filePath}`;
  },

  async list_directory(hush, dirPath) {
    const allowed = await hush.checkTool('list_directory', { path: dirPath });
    if (!allowed) throw new Error('Access denied by hushclaw');

    return fs.readdirSync(dirPath);
  },
};

// Main agent loop
async function runAgent() {
  console.log('Hello Secure Agent');
  console.log('==================\n');

  const hush = new HushclawClient(process.env.HUSH_ENDPOINT);

  try {
    // Demonstrate allowed operations
    console.log('1. Reading skill definition...');
    const skill = await tools.read_file(hush, './skills/hello/SKILL.md');
    console.log(`   Read ${skill.length} bytes\n`);

    console.log('2. Listing workspace...');
    const files = await tools.list_directory(hush, '.');
    console.log(`   Found: ${files.join(', ')}\n`);

    console.log('3. Writing to allowed path...');
    const result = await tools.write_file(
      hush,
      './output/greeting.log',
      `Hello from secure agent at ${new Date().toISOString()}\n`
    );
    console.log(`   ${result}\n`);

    // Demonstrate denied operations
    console.log('4. Attempting forbidden write (should be denied)...');
    try {
      await tools.write_file(hush, '/etc/test', 'should fail');
    } catch (e) {
      console.log(`   Denied: ${e.message}\n`);
    }

    console.log('5. Attempting shell execution (should be denied)...');
    const shellAllowed = await hush.checkTool('execute_command', { cmd: 'ls -la' });
    if (!shellAllowed) {
      console.log('   Denied: Shell execution disabled\n');
    }
  } catch (error) {
    console.error('Agent error:', error.message);
  }

  // Generate receipt
  console.log('Generating receipt...');
  const receipt = await hush.generateReceipt();

  const receiptDir = './.hush/receipts';
  if (!fs.existsSync(receiptDir)) fs.mkdirSync(receiptDir, { recursive: true });

  const receiptPath = path.join(receiptDir, `${receipt.run_id}.json`);
  fs.writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));

  // Also write as latest
  fs.writeFileSync(path.join(receiptDir, 'latest.json'), JSON.stringify(receipt, null, 2));

  console.log(`\nReceipt: ${receiptPath}`);
  console.log(`  Events:  ${receipt.event_count}`);
  console.log(`  Denied:  ${receipt.denied_count}`);
  console.log(`  Status:  Complete`);
}

runAgent().catch(console.error);
