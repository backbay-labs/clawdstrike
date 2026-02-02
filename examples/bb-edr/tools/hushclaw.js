#!/usr/bin/env node

const { runHushclawCli } = require('./openclaw');

function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.error('usage: node ./tools/hushclaw.js <command> [...args]');
    process.exit(2);
  }
  runHushclawCli(args);
}

main();

