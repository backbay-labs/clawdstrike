const fs = require('fs');
const path = require('path');
const { execSync, spawnSync } = require('child_process');
const { pathToFileURL } = require('url');

function packageDir() {
  return path.resolve(__dirname, '../../../packages/hushclaw-openclaw');
}

function distPath(rel) {
  return path.join(packageDir(), 'dist', rel);
}

function ensureBuilt() {
  const entry = distPath('index.js');
  if (fs.existsSync(entry)) return;

  execSync('npm run build', { cwd: packageDir(), stdio: 'inherit' });

  if (!fs.existsSync(entry)) {
    throw new Error(`Build completed but missing expected file: ${entry}`);
  }
}

async function importOpenclawSdk() {
  ensureBuilt();
  return import(pathToFileURL(distPath('index.js')).href);
}

function runHushclawCli(args) {
  ensureBuilt();
  const cli = distPath(path.join('cli', 'bin.js'));
  const res = spawnSync('node', [cli, ...args], {
    cwd: path.resolve(__dirname, '..'),
    stdio: 'inherit',
  });
  if (res.status !== 0) {
    process.exit(res.status ?? 1);
  }
}

module.exports = {
  ensureBuilt,
  importOpenclawSdk,
  runHushclawCli,
};

