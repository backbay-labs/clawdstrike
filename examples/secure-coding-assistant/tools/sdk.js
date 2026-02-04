const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { pathToFileURL } = require('url');

function repoRoot() {
  return path.resolve(__dirname, '../../..');
}

function pkgDir(name) {
  return path.resolve(repoRoot(), 'packages', name);
}

function distPath(pkgName, rel) {
  return path.join(pkgDir(pkgName), 'dist', rel);
}

function ensureBuilt(pkgName) {
  const entry = distPath(pkgName, 'index.js');
  if (fs.existsSync(entry)) return;

  const cwd = pkgDir(pkgName);
  const nodeModules = path.join(cwd, 'node_modules');
  if (!fs.existsSync(nodeModules)) {
    execSync('npm ci', { cwd, stdio: 'inherit' });
  }
  execSync('npm run build', { cwd, stdio: 'inherit' });
  if (!fs.existsSync(entry)) {
    throw new Error(`Build completed but missing expected file: ${entry}`);
  }
}

async function importAdapterCore() {
  ensureBuilt('clawdstrike-adapter-core');
  return import(pathToFileURL(distPath('clawdstrike-adapter-core', 'index.js')).href);
}

async function importHushCliEngine() {
  ensureBuilt('clawdstrike-hush-cli-engine');
  return import(pathToFileURL(distPath('clawdstrike-hush-cli-engine', 'index.js')).href);
}

function hushBinaryPath() {
  const root = repoRoot();
  const binName = process.platform === 'win32' ? 'hush.exe' : 'hush';
  return path.join(root, 'target', 'debug', binName);
}

function ensureHushBuilt() {
  const bin = hushBinaryPath();
  if (fs.existsSync(bin)) return bin;
  execSync('cargo build -p hush-cli', { cwd: repoRoot(), stdio: 'inherit' });
  if (!fs.existsSync(bin)) {
    throw new Error(`Expected hush binary at: ${bin}`);
  }
  return bin;
}

module.exports = {
  importAdapterCore,
  importHushCliEngine,
  ensureHushBuilt,
};
