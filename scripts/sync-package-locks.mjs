#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");

const rootPackageJson = readJson(path.join(repoRoot, "package.json"));
const workspaceDirs = expandWorkspaces(rootPackageJson.workspaces ?? []);
const workspaceByName = new Map(
  workspaceDirs.map((dir) => {
    const manifest = readJson(path.join(repoRoot, dir, "package.json"));
    return [manifest.name, dir];
  }),
);

const lockTargets = findPackageLockTargets(["packages", "apps"]);

for (const target of lockTargets) {
  syncLockfile(target);
}

function syncLockfile({ lockPath, manifestPath, dir }) {
  const manifest = readJson(manifestPath);
  const lock = readJson(lockPath);
  const rootEntry = (lock.packages ??= {})[""] ?? (lock.packages[""] = {});

  lock.name = manifest.name;
  lock.version = manifest.version;
  lock.lockfileVersion ??= 3;
  lock.requires ??= true;

  syncManifestFields(lock, manifest, ["name", "version"]);
  syncManifestFields(rootEntry, manifest, [
    "name",
    "version",
    "license",
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "peerDependenciesMeta",
    "optionalDependencies",
    "engines",
    "bin",
  ]);

  const internalDependencyNames = new Set();
  for (const field of ["dependencies", "optionalDependencies"]) {
    const deps = manifest[field] ?? {};
    for (const depName of Object.keys(deps)) {
      if (workspaceByName.has(depName)) {
        internalDependencyNames.add(depName);
      }
    }
  }

  for (const depName of internalDependencyNames) {
    const workspaceDir = workspaceByName.get(depName);
    if (!workspaceDir) {
      continue;
    }

    const relativeTarget = toPosix(path.relative(dir, path.join(repoRoot, workspaceDir)));
    const targetManifest = readJson(path.join(repoRoot, workspaceDir, "package.json"));

    lock.packages[relativeTarget] = buildLinkedPackageEntry(targetManifest);
    lock.packages[`node_modules/${depName}`] = {
      resolved: relativeTarget,
      link: true,
    };

    for (const key of Object.keys(lock.packages)) {
      if (key !== `node_modules/${depName}` && key.endsWith(`/node_modules/${depName}`)) {
        delete lock.packages[key];
      }
    }
  }

  fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
}

function buildLinkedPackageEntry(manifest) {
  const entry = {};
  syncManifestFields(entry, manifest, [
    "name",
    "version",
    "license",
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "peerDependenciesMeta",
    "optionalDependencies",
    "engines",
    "bin",
  ]);
  return entry;
}

function syncManifestFields(target, manifest, fields) {
  for (const field of fields) {
    if (Object.hasOwn(manifest, field)) {
      target[field] = manifest[field];
    } else {
      delete target[field];
    }
  }
}

function findPackageLockTargets(roots) {
  const results = [];
  for (const relRoot of roots) {
    const absRoot = path.join(repoRoot, relRoot);
    if (!fs.existsSync(absRoot)) {
      continue;
    }
    walk(absRoot, (entryPath) => {
      if (path.basename(entryPath) !== "package-lock.json") {
        return;
      }
      const manifestPath = path.join(path.dirname(entryPath), "package.json");
      if (!fs.existsSync(manifestPath)) {
        return;
      }
      results.push({
        lockPath: entryPath,
        manifestPath,
        dir: path.dirname(entryPath),
      });
    });
  }
  return results.sort((a, b) => a.lockPath.localeCompare(b.lockPath));
}

function walk(dir, onFile) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === ".turbo") {
      continue;
    }
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(entryPath, onFile);
    } else if (entry.isFile()) {
      onFile(entryPath);
    }
  }
}

function expandWorkspaces(patterns) {
  const dirs = [];
  for (const pattern of patterns) {
    const parts = pattern.split("/");
    expandPattern(parts, 0, repoRoot, dirs);
  }
  return [...new Set(dirs)].sort();
}

function expandPattern(parts, index, currentDir, out) {
  if (index === parts.length) {
    const manifestPath = path.join(currentDir, "package.json");
    if (fs.existsSync(manifestPath)) {
      out.push(path.relative(repoRoot, currentDir));
    }
    return;
  }

  const part = parts[index];
  if (part === "*") {
    for (const entry of fs.readdirSync(currentDir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        expandPattern(parts, index + 1, path.join(currentDir, entry.name), out);
      }
    }
    return;
  }

  expandPattern(parts, index + 1, path.join(currentDir, part), out);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function toPosix(value) {
  return value.split(path.sep).join("/");
}
