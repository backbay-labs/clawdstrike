import { parsePluginManifest } from "./manifest.js";

test("parses minimal manifest and applies safe defaults", () => {
  const manifest = parsePluginManifest({
    version: "1.0.0",
    name: "acme-guard",
    guards: [{ name: "acme.deny", entrypoint: "./dist/guard.js" }],
    trust: { level: "trusted" },
  });

  expect(manifest.trust.sandbox).toBe("node");
  expect(manifest.capabilities.network).toBe(false);
  expect(manifest.capabilities.subprocess).toBe(false);
  expect(manifest.capabilities.filesystem.write).toBe(false);
  expect(manifest.capabilities.filesystem.read).toEqual([]);
  expect(manifest.capabilities.secrets.access).toBe(false);
  expect(manifest.resources.maxMemoryMb).toBe(64);
  expect(manifest.resources.maxCpuMs).toBe(100);
  expect(manifest.resources.maxTimeoutMs).toBe(5000);
});

test("rejects duplicate guard names", () => {
  expect(() =>
    parsePluginManifest({
      version: "1.0.0",
      name: "acme-guard",
      guards: [
        { name: "acme.deny", entrypoint: "./dist/a.js" },
        { name: "acme.deny", entrypoint: "./dist/b.js" },
      ],
      trust: { level: "trusted" },
    }),
  ).toThrow(/duplicates guard/i);
});

test("rejects invalid compatibility semver", () => {
  expect(() =>
    parsePluginManifest({
      version: "1.0.0",
      name: "acme-guard",
      clawdstrike: { minVersion: "1.x" },
      guards: [{ name: "acme.deny", entrypoint: "./dist/guard.js" }],
      trust: { level: "trusted" },
    }),
  ).toThrow(/minVersion must be strict semver/i);
});

test("default capabilities and resources are not aliased across parses", () => {
  const baseInput = {
    version: "1.0.0",
    guards: [{ name: "acme.deny", entrypoint: "./dist/guard.js" }],
    trust: { level: "trusted" },
  } as const;

  const first = parsePluginManifest({ name: "p1", ...baseInput });
  const second = parsePluginManifest({ name: "p2", ...baseInput });

  // Distinct object identities so per-manifest mutation cannot leak.
  expect(first.capabilities).not.toBe(second.capabilities);
  expect(first.resources).not.toBe(second.resources);
  expect(first.capabilities.filesystem).not.toBe(second.capabilities.filesystem);
  expect(first.capabilities.secrets).not.toBe(second.capabilities.secrets);

  const firstCaps = first.capabilities as Record<string, unknown>;
  firstCaps.network = true;
  (firstCaps.filesystem as Record<string, unknown>).write = true;
  (first.resources as Record<string, unknown>).maxMemoryMb = 9999;

  const third = parsePluginManifest({ name: "p3", ...baseInput });
  expect(third.capabilities.network).toBe(false);
  expect(third.capabilities.filesystem.write).toBe(false);
  expect(third.resources.maxMemoryMb).toBe(64);
});

test("accepts extended capability structure", () => {
  const manifest = parsePluginManifest({
    version: "1.0.0",
    name: "acme-guard",
    guards: [
      {
        name: "acme.deny",
        entrypoint: "./dist/guard.js",
        handles: ["tool_call", "file_write"],
      },
    ],
    capabilities: {
      network: true,
      filesystem: {
        read: ["**/*.md"],
        write: false,
      },
      secrets: { access: false },
      subprocess: false,
    },
    resources: {
      maxMemoryMb: 32,
      maxCpuMs: 50,
      maxTimeoutMs: 1000,
    },
    trust: { level: "trusted", sandbox: "node" },
  });

  expect(manifest.guards[0]?.handles).toEqual(["tool_call", "file_write"]);
  expect(manifest.capabilities.network).toBe(true);
  expect(manifest.capabilities.filesystem.read).toEqual(["**/*.md"]);
  expect(manifest.resources.maxMemoryMb).toBe(32);
});
