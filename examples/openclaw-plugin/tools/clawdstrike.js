#!/usr/bin/env node

const { runClawdstrikeCli } = require('./openclaw');

function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.error('usage: node ./tools/clawdstrike.js <command> [...args]');
    process.exit(2);
  }
  runClawdstrikeCli(args);
}

main();

