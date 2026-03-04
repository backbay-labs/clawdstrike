import { describe, it, expect, vi } from "vitest";
import { createHash } from "node:crypto";
import fs from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { SpiderSenseDetector, type PatternEntry } from "../src/spider-sense";
import { SpiderSenseGuard } from "../src/guards/spider-sense";
import { GuardAction, GuardContext } from "../src/guards/types";
import { toHex } from "../src/crypto/hash";
import { generateKeypair, signMessage } from "../src/crypto/sign";

// biome-ignore lint/suspicious/noExplicitAny: vitest global from setup.ts
const wasmAvailable = (globalThis as any).__WASM_SPIDER_SENSE_AVAILABLE__ as boolean;
const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "../../../../");

interface SpiderSenseManifestTamperVector {
  name: string;
  field: "pattern_db_version" | "not_before" | "not_after";
  value: string;
}

function loadManifestTamperVectors(): SpiderSenseManifestTamperVector[] {
  const vectorsPath = path.join(REPO_ROOT, "fixtures/spider-sense/manifest_tamper_vectors.json");
  return JSON.parse(fs.readFileSync(vectorsPath, "utf8")) as SpiderSenseManifestTamperVector[];
}

const testPatterns: PatternEntry[] = [
  {
    id: "p1",
    category: "prompt_injection",
    stage: "perception",
    label: "ignore previous",
    embedding: [1.0, 0.0, 0.0],
  },
  {
    id: "p2",
    category: "data_exfiltration",
    stage: "action",
    label: "exfil data",
    embedding: [0.0, 1.0, 0.0],
  },
  {
    id: "p3",
    category: "privilege_escalation",
    stage: "cognition",
    label: "escalate",
    embedding: [0.0, 0.0, 1.0],
  },
];

describe.skipIf(!wasmAvailable)("spider-sense detection", () => {
  it("constructs with default config", () => {
    const d = new SpiderSenseDetector();
    expect(d.patternCount()).toBe(0);
    expect(d.expectedDim()).toBeUndefined();
  });

  it("constructs with custom config", () => {
    const d = new SpiderSenseDetector({
      similarityThreshold: 0.90,
      ambiguityBand: 0.05,
      topK: 3,
    });
    expect(d.patternCount()).toBe(0);
  });

  it("loads patterns and reports count and dimension", () => {
    const d = new SpiderSenseDetector();
    d.loadPatterns(testPatterns);
    expect(d.patternCount()).toBe(3);
    expect(d.expectedDim()).toBe(3);
  });

  it("screens identical vectors as deny", () => {
    const d = new SpiderSenseDetector();
    d.loadPatterns(testPatterns);
    const result = d.screen([1.0, 0.0, 0.0]);
    expect(result.verdict).toBe("deny");
    expect(result.topScore).toBeCloseTo(1.0, 5);
    expect(result.topMatches.length).toBeGreaterThan(0);
    expect(result.topMatches[0].entry.id).toBe("p1");
  });

  it("screens orthogonal vectors as allow", () => {
    const d = new SpiderSenseDetector();
    d.loadPatterns(testPatterns);
    // This vector is equidistant from all basis vectors (cos sim ~0.577)
    // With default threshold 0.85 and band 0.10, lower bound is 0.75
    // 0.577 < 0.75 => allow
    const result = d.screen([0.577, 0.577, 0.577]);
    expect(result.verdict).toBe("allow");
    expect(result.topScore).toBeLessThan(0.75);
  });

  it("screens ambiguous vectors correctly", () => {
    const d = new SpiderSenseDetector({
      similarityThreshold: 0.50,
      ambiguityBand: 0.10,
      topK: 5,
    });
    d.loadPatterns(testPatterns);
    // Equidistant vector: cos sim ~0.577, within band [0.40, 0.60]
    const result = d.screen([0.577, 0.577, 0.577]);
    expect(result.verdict).toBe("ambiguous");
    expect(result.topScore).toBeGreaterThan(0.40);
    expect(result.topScore).toBeLessThan(0.60);
  });

  it("returns result shape with expected fields", () => {
    const d = new SpiderSenseDetector();
    d.loadPatterns(testPatterns);
    const result = d.screen([1.0, 0.0, 0.0]);
    expect(result).toHaveProperty("verdict");
    expect(result).toHaveProperty("topScore");
    expect(result).toHaveProperty("threshold");
    expect(result).toHaveProperty("ambiguityBand");
    expect(result).toHaveProperty("topMatches");
    expect(Array.isArray(result.topMatches)).toBe(true);
  });

  it("throws when screening without loaded patterns", () => {
    const d = new SpiderSenseDetector();
    expect(() => d.screen([1.0, 0.0, 0.0])).toThrow(/patterns/i);
  });

  it("respects topK config", () => {
    const d = new SpiderSenseDetector({ topK: 1 });
    d.loadPatterns(testPatterns);
    const result = d.screen([1.0, 0.0, 0.0]);
    expect(result.topMatches.length).toBe(1);
  });

  it("rejects empty patterns array", () => {
    const d = new SpiderSenseDetector();
    expect(() => d.loadPatterns([])).toThrow();
  });

  it("rejects dimension mismatch in patterns", () => {
    const d = new SpiderSenseDetector();
    const bad: PatternEntry[] = [
      { id: "a", category: "x", stage: "y", label: "z", embedding: [1.0, 0.0] },
      { id: "b", category: "x", stage: "y", label: "z", embedding: [1.0, 0.0, 0.0] },
    ];
    expect(() => d.loadPatterns(bad)).toThrow(/dimension/i);
  });

  it("returns topMatches with entry and score fields", () => {
    const d = new SpiderSenseDetector();
    d.loadPatterns(testPatterns);
    const result = d.screen([1.0, 0.0, 0.0]);
    const match = result.topMatches[0];
    expect(match).toHaveProperty("entry");
    expect(match).toHaveProperty("score");
    expect(match.entry).toHaveProperty("id");
    expect(match.entry).toHaveProperty("category");
    expect(match.entry).toHaveProperty("stage");
    expect(match.entry).toHaveProperty("label");
    expect(match.entry).toHaveProperty("embedding");
    expect(typeof match.score).toBe("number");
  });

  it("rejects invalid config values", () => {
    // Threshold outside [0, 1] should fail
    expect(
      () => {
        const d = new SpiderSenseDetector({ similarityThreshold: 1.5 });
        d.loadPatterns(testPatterns);
      },
    ).toThrow();
  });
});

describe("spider-sense guard", () => {
  it("keeps sdk bundled s2bench pattern DB in sync with canonical ruleset source", async () => {
    const canonicalPath = path.join(REPO_ROOT, "rulesets/patterns/s2bench-v1.json");
    const bundledPath = path.join(REPO_ROOT, "packages/sdk/hush-ts/src/guards/patterns/s2bench-v1.json");
    expect((await readFile(bundledPath, "utf8")).trim()).toBe((await readFile(canonicalPath, "utf8")).trim());
  });

  const ctx = new GuardContext();

  function makeGuard(): SpiderSenseGuard {
    const guard = new SpiderSenseGuard();
    guard.loadPatterns(testPatterns);
    return guard;
  }

  it("handles all action types", () => {
    const guard = makeGuard();
    expect(guard.handles(GuardAction.fileAccess("/tmp/test"))).toBe(true);
    expect(guard.handles(GuardAction.shellCommand("ls"))).toBe(true);
    expect(guard.handles(GuardAction.custom("any_type", {}))).toBe(true);
  });

  it("allows when no embedding is present", async () => {
    const guard = makeGuard();
    const action = GuardAction.custom("test", { text: "hello" });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(true);
  });

  it("blocks when embedding matches a threat pattern", async () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [1.0, 0.0, 0.0] },
    });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(false);
    expect(result.message).toContain("threat detected");
    expect(result.details?.verdict).toBe("deny");
  });

  it("warns on ambiguous embeddings", async () => {
    const guard = new SpiderSenseGuard({
      similarityThreshold: 0.50,
      ambiguityBand: 0.10,
    });
    guard.loadPatterns(testPatterns);
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [0.577, 0.577, 0.577] },
    });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe("warning");
    expect(result.details?.verdict).toBe("ambiguous");
  });

  it("allows safe embeddings", async () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [0.577, 0.577, 0.577] },
    });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe("info");
  });

  it("allows when disabled", async () => {
    const guard = new SpiderSenseGuard({ enabled: false });
    guard.loadPatterns(testPatterns);
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [1.0, 0.0, 0.0] },
    });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(true);
  });

  it("ignores non-array embedding data", async () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: "not an array" },
    });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(true);
  });

  it("includes details on block result", async () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [1.0, 0.0, 0.0] },
    });
    const result = await guard.check(action, ctx);
    expect(result.details).toBeDefined();
    expect(result.details?.top_score).toBeCloseTo(1.0, 5);
    expect(result.details?.threshold).toBeDefined();
    expect(result.details?.ambiguity_band).toBeDefined();
    expect(Array.isArray(result.details?.top_matches)).toBe(true);
  });

  it("fails closed when patterns are not loaded", async () => {
    const guard = new SpiderSenseGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [1.0, 0.0, 0.0] },
    });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(false);
    expect(result.severity).toBe("error");
    expect(result.message).toContain("pattern DB missing");
    expect(result.details?.analysis).toBe("configuration");
  });

  it("ignores mixed-type arrays in embedding data", async () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [1.0, "bad", 0.0] },
    });
    const result = await guard.check(action, ctx);
    // extractEmbedding validates every element is a number
    expect(result.allowed).toBe(true);
  });

  it("ignores null customData", async () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
    });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(true);
  });

  it("ignores empty embedding array", async () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [] },
    });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(false);
  });

  it("uses embedding provider when action embedding is missing", async () => {
    const guard = new SpiderSenseGuard({
      patterns: testPatterns,
      embeddingApiUrl: "https://api.openai.com/v1/embeddings",
      embeddingApiKey: "test-key",
      embeddingModel: "text-embedding-3-small",
      fetchFn: async () =>
        new Response(
          JSON.stringify({
            data: [{ embedding: [1.0, 0.0, 0.0] }],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    });
    const result = await guard.check(GuardAction.custom("user_input", { text: "hello" }), ctx);
    expect(result.allowed).toBe(false);
    expect(result.details?.embedding_from).toBe("provider");
  });

  it("fails closed on provider failure", async () => {
    const guard = new SpiderSenseGuard({
      patterns: testPatterns,
      embeddingApiUrl: "https://api.openai.com/v1/embeddings",
      embeddingApiKey: "test-key",
      embeddingModel: "text-embedding-3-small",
      fetchFn: async () => new Response("boom", { status: 500 }),
    });
    const result = await guard.check(GuardAction.custom("user_input", { text: "hello" }), ctx);
    expect(result.allowed).toBe(false);
    expect(result.message).toContain("provider error");
  });

  it("uses embedding cache with normalized key to avoid duplicate provider calls", async () => {
    let callCount = 0;
    const guard = new SpiderSenseGuard({
      patterns: testPatterns,
      embeddingApiUrl: "https://api.openai.com/v1/embeddings?unused=true",
      embeddingApiKey: "test-key",
      embeddingModel: "text-embedding-3-small",
      async: {
        cache: {
          enabled: true,
          ttl_seconds: 3600,
        },
      },
      fetchFn: async () => {
        callCount += 1;
        return new Response(
          JSON.stringify({
            data: [{ embedding: [1.0, 0.0, 0.0] }],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      },
    });

    const action = GuardAction.custom("user_input", { text: "   hello world   " });
    const first = await guard.check(action, ctx);
    const second = await guard.check(action, ctx);
    expect(first.allowed).toBe(false);
    expect(second.allowed).toBe(false);
    expect(callCount).toBe(1);
  });

  it("retries embedding provider with backoff and succeeds", async () => {
    let callCount = 0;
    const guard = new SpiderSenseGuard({
      patterns: testPatterns,
      embeddingApiUrl: "https://api.openai.com/v1/embeddings",
      embeddingApiKey: "test-key",
      embeddingModel: "text-embedding-3-small",
      async: {
        retry: {
          max_retries: 2,
          initial_backoff_ms: 1,
          max_backoff_ms: 2,
          multiplier: 1,
        },
      },
      fetchFn: async () => {
        callCount += 1;
        if (callCount < 3) {
          return new Response("temporary failure", { status: 500 });
        }
        return new Response(
          JSON.stringify({
            data: [{ embedding: [1.0, 0.0, 0.0] }],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      },
    });

    const result = await guard.check(GuardAction.custom("user_input", { text: "hello" }), ctx);
    expect(result.allowed).toBe(false);
    expect(result.details?.embedding_from).toBe("provider");
    expect(callCount).toBe(3);
  });

  it("honors Retry-After with cap for provider retries", async () => {
    vi.useFakeTimers();
    try {
      let callCount = 0;
      const guard = new SpiderSenseGuard({
        patterns: testPatterns,
        embeddingApiUrl: "https://api.openai.com/v1/embeddings",
        embeddingApiKey: "test-key",
        embeddingModel: "text-embedding-3-small",
        async: {
          retry: {
            max_retries: 1,
            initial_backoff_ms: 1,
            max_backoff_ms: 2,
            multiplier: 1,
            honor_retry_after: true,
            retry_after_cap_ms: 5,
          },
        },
        fetchFn: async () => {
          callCount += 1;
          if (callCount === 1) {
            return new Response("rate limited", {
              status: 429,
              headers: { "Retry-After": "1" },
            });
          }
          return new Response(
            JSON.stringify({
              data: [{ embedding: [1.0, 0.0, 0.0] }],
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        },
      });

      const checkPromise = guard.check(GuardAction.custom("user_input", { text: "hello" }), ctx);
      await vi.advanceTimersByTimeAsync(4);
      expect(callCount).toBe(1);
      await vi.advanceTimersByTimeAsync(1);
      const result = await checkPromise;
      expect(result.allowed).toBe(false);
      expect(callCount).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("supports circuit breaker on_open warn mode", async () => {
    let callCount = 0;
    const guard = new SpiderSenseGuard({
      patterns: testPatterns,
      embeddingApiUrl: "https://api.openai.com/v1/embeddings",
      embeddingApiKey: "test-key",
      embeddingModel: "text-embedding-3-small",
      async: {
        retry: {
          max_retries: 0,
        },
        circuit_breaker: {
          failure_threshold: 1,
          reset_timeout_ms: 60_000,
          success_threshold: 1,
          on_open: "warn",
        },
      },
      fetchFn: async () => {
        callCount += 1;
        return new Response("failure", { status: 500 });
      },
    });

    const first = await guard.check(GuardAction.custom("user_input", { text: "first" }), ctx);
    expect(first.allowed).toBe(false);

    const second = await guard.check(GuardAction.custom("user_input", { text: "second" }), ctx);
    expect(second.allowed).toBe(true);
    expect(second.severity).toBe("warning");
    expect(second.details?.on_open).toBe("warn");
    expect(callCount).toBe(1);
  });

  it("supports key-id trust store verification for pattern DB", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "spider-sense-ts-trust-"));
    const dbPath = path.join(dir, "patterns.json");
    const trustStorePath = path.join(dir, "trust-store.json");
    const dbJson = JSON.stringify([
      {
        id: "p1",
        category: "prompt_injection",
        stage: "perception",
        label: "ignore previous",
        embedding: [1.0, 0.0, 0.0],
      },
    ]);
    await writeFile(dbPath, dbJson, "utf8");
    const checksum = createHash("sha256").update(dbJson).digest("hex");

    const keypair = await generateKeypair();
    const publicKeyHex = toHex(keypair.publicKey);
    const keyId = createHash("sha256")
      .update(publicKeyHex.toLowerCase())
      .digest("hex")
      .slice(0, 16);
    const message = new TextEncoder().encode(`spider_sense_db:v1:test-v1:${checksum}`);
    const signature = await signMessage(message, keypair.privateKey);

    await writeFile(
      trustStorePath,
      JSON.stringify({
        keys: [
          {
            key_id: keyId,
            public_key: publicKeyHex,
            status: "active",
          },
        ],
      }),
      "utf8",
    );

    const guard = new SpiderSenseGuard({
      patternDbPath: dbPath,
      patternDbVersion: "test-v1",
      patternDbChecksum: checksum,
      patternDbSignature: toHex(signature),
      patternDbSignatureKeyId: keyId,
      patternDbTrustStorePath: trustStorePath,
    });

    const result = await guard.check(
      GuardAction.custom("embedding_check", { embedding: [1.0, 0.0, 0.0] }),
      ctx,
    );
    expect(result.allowed).toBe(false);
    await rm(dir, { recursive: true, force: true });
  });

  it("allows custom trust-store key IDs", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "spider-sense-ts-trust-custom-"));
    const dbPath = path.join(dir, "patterns.json");
    const trustStorePath = path.join(dir, "trust-store.json");
    const dbJson = JSON.stringify([
      {
        id: "p1",
        category: "prompt_injection",
        stage: "perception",
        label: "ignore previous",
        embedding: [1.0, 0.0, 0.0],
      },
    ]);
    await writeFile(dbPath, dbJson, "utf8");
    const checksum = createHash("sha256").update(dbJson).digest("hex");

    const keypair = await generateKeypair();
    const publicKeyHex = toHex(keypair.publicKey);
    const keyId = "external-kid-01";
    const message = new TextEncoder().encode(`spider_sense_db:v1:test-v1:${checksum}`);
    const signature = await signMessage(message, keypair.privateKey);

    await writeFile(
      trustStorePath,
      JSON.stringify({
        keys: [
          {
            key_id: keyId,
            public_key: publicKeyHex,
            status: "active",
          },
        ],
      }),
      "utf8",
    );

    const guard = new SpiderSenseGuard({
      patternDbPath: dbPath,
      patternDbVersion: "test-v1",
      patternDbChecksum: checksum,
      patternDbSignature: toHex(signature),
      patternDbSignatureKeyId: keyId,
      patternDbTrustStorePath: trustStorePath,
    });

    const result = await guard.check(
      GuardAction.custom("embedding_check", { embedding: [1.0, 0.0, 0.0] }),
      ctx,
    );
    expect(result.allowed).toBe(false);
    await rm(dir, { recursive: true, force: true });
  });

  it("supports signed pattern DB manifests for trust-store metadata", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "spider-sense-ts-manifest-"));
    const dbPath = path.join(dir, "patterns.json");
    const trustStorePath = path.join(dir, "trust-store.json");
    const manifestPath = path.join(dir, "manifest.json");
    const dbJson = JSON.stringify([
      {
        id: "p1",
        category: "prompt_injection",
        stage: "perception",
        label: "ignore previous",
        embedding: [1.0, 0.0, 0.0],
      },
    ]);
    await writeFile(dbPath, dbJson, "utf8");
    const checksum = createHash("sha256").update(dbJson).digest("hex");

    const dbKeypair = await generateKeypair();
    const dbPublicKeyHex = toHex(dbKeypair.publicKey);
    const dbKeyId = createHash("sha256")
      .update(dbPublicKeyHex.toLowerCase())
      .digest("hex")
      .slice(0, 16);
    const dbMessage = new TextEncoder().encode(`spider_sense_db:v1:test-v1:${checksum}`);
    const dbSignature = await signMessage(dbMessage, dbKeypair.privateKey);

    await writeFile(
      trustStorePath,
      JSON.stringify({
        keys: [
          {
            key_id: dbKeyId,
            public_key: dbPublicKeyHex,
            status: "active",
          },
        ],
      }),
      "utf8",
    );

    const rootKeypair = await generateKeypair();
    const rootPublicKeyHex = toHex(rootKeypair.publicKey);
    const rootKeyId = createHash("sha256")
      .update(rootPublicKeyHex.toLowerCase())
      .digest("hex")
      .slice(0, 16);

    const manifest = {
      pattern_db_path: path.basename(dbPath),
      pattern_db_version: "test-v1",
      pattern_db_checksum: checksum,
      pattern_db_signature: toHex(dbSignature),
      pattern_db_signature_key_id: dbKeyId,
      pattern_db_trust_store_path: path.basename(trustStorePath),
      manifest_signature_key_id: rootKeyId,
      not_before: "",
      not_after: "",
    };
    const trustedDigest = createHash("sha256").update("").digest("hex");
    const manifestMessage = new TextEncoder().encode(
      [
        "spider_sense_manifest:v1",
        manifest.pattern_db_path,
        manifest.pattern_db_version,
        checksum,
        toHex(dbSignature).toLowerCase(),
        dbKeyId,
        "",
        manifest.pattern_db_trust_store_path,
        trustedDigest,
        manifest.not_before,
        manifest.not_after,
      ].join(":"),
    );
    const manifestSignature = await signMessage(manifestMessage, rootKeypair.privateKey);
    await writeFile(
      manifestPath,
      JSON.stringify({
        ...manifest,
        manifest_signature: toHex(manifestSignature),
      }),
      "utf8",
    );

    const guard = new SpiderSenseGuard({
      patternDbManifestPath: manifestPath,
      patternDbManifestTrustedKeys: [
        {
          key_id: rootKeyId,
          public_key: rootPublicKeyHex,
          status: "active",
        },
      ],
    });
    const result = await guard.check(
      GuardAction.custom("embedding_check", { embedding: [1.0, 0.0, 0.0] }),
      ctx,
    );
    expect(result.allowed).toBe(false);

    const expectManifestTamperFailure = async (tampered: Record<string, unknown>): Promise<void> => {
      await writeFile(
        manifestPath,
        JSON.stringify({
          ...tampered,
          manifest_signature: toHex(manifestSignature),
        }),
        "utf8",
      );
      await expect(
        new SpiderSenseGuard({
          patternDbManifestPath: manifestPath,
          patternDbManifestTrustedKeys: [
            {
              key_id: rootKeyId,
              public_key: rootPublicKeyHex,
              status: "active",
            },
          ],
        }).check(GuardAction.custom("embedding_check", { embedding: [1.0, 0.0, 0.0] }), ctx),
      ).rejects.toThrow(/manifest signature verification failed/i);
    };

    for (const vector of loadManifestTamperVectors()) {
      await expectManifestTamperFailure({
        ...manifest,
        [vector.field]: vector.value,
      });
    }
    await rm(dir, { recursive: true, force: true });
  });

  it("uses deep path on ambiguous results and applies deny verdict", async () => {
    const guard = new SpiderSenseGuard({
      patterns: testPatterns,
      similarityThreshold: 0.5,
      ambiguityBand: 0.1,
      llmApiUrl: "https://api.openai.com/v1/chat/completions",
      llmApiKey: "llm-key",
      llmModel: "gpt-4.1-mini",
      llmPromptTemplateId: "spider_sense.deep_path.json_classifier",
      llmPromptTemplateVersion: "1.0.0",
      deepPathFetchFn: async () =>
        new Response(
          JSON.stringify({
            choices: [
              {
                message: {
                  content: JSON.stringify({
                    verdict: "deny",
                    reason: "policy confidence high",
                  }),
                },
              },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    });

    const result = await guard.check(
      GuardAction.custom("embedding_check", { embedding: [0.577, 0.577, 0.577] }),
      ctx,
    );
    expect(result.allowed).toBe(false);
    expect(result.details?.analysis).toBe("deep_path");
    expect(result.details?.verdict).toBe("deny");
  });

  it("applies deep path fail-mode allow on deep path failure", async () => {
    const guard = new SpiderSenseGuard({
      patterns: testPatterns,
      similarityThreshold: 0.5,
      ambiguityBand: 0.1,
      llmApiUrl: "https://api.openai.com/v1/chat/completions",
      llmApiKey: "llm-key",
      llmFailMode: "allow",
      llmPromptTemplateId: "spider_sense.deep_path.json_classifier",
      llmPromptTemplateVersion: "1.0.0",
      deepPathFetchFn: async () => new Response("llm down", { status: 503 }),
    });

    const result = await guard.check(
      GuardAction.custom("embedding_check", { embedding: [0.577, 0.577, 0.577] }),
      ctx,
    );
    expect(result.allowed).toBe(true);
    expect(result.details?.analysis).toBe("deep_path_error");
    expect(result.details?.fail_mode).toBe("allow");
  });

  it("allows legacy deep-path config without prompt template id/version", async () => {
    const guard = new SpiderSenseGuard({
      patterns: testPatterns,
      similarityThreshold: 0.5,
      ambiguityBand: 0.1,
      llmApiUrl: "https://api.openai.com/v1/chat/completions",
      llmApiKey: "llm-key",
      deepPathFetchFn: async () =>
        new Response(
          JSON.stringify({
            choices: [
              {
                message: {
                  content: JSON.stringify({
                    verdict: "deny",
                    reason: "legacy template path",
                  }),
                },
              },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    });

    const result = await guard.check(
      GuardAction.custom("embedding_check", { embedding: [0.577, 0.577, 0.577] }),
      ctx,
    );
    expect(result.allowed).toBe(false);
    expect(result.details?.analysis).toBe("deep_path");
  });

  it("rejects unknown deep-path prompt templates", () => {
    expect(
      () =>
        new SpiderSenseGuard({
          patterns: testPatterns,
          llmApiUrl: "https://api.openai.com/v1/chat/completions",
          llmApiKey: "llm-key",
          llmPromptTemplateId: "spider_sense.deep_path.unknown",
          llmPromptTemplateVersion: "9.9.9",
        }),
    ).toThrow(/unsupported llm prompt template/i);
  });

  it("validates pattern DB checksum for path-based loading", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "spider-sense-ts-"));
    const dbPath = path.join(dir, "patterns.json");
    const dbJson = JSON.stringify([
      {
        id: "p1",
        category: "prompt_injection",
        stage: "perception",
        label: "ignore previous",
        embedding: [1.0, 0.0, 0.0],
      },
    ]);
    await writeFile(dbPath, dbJson, "utf8");
    const checksum = createHash("sha256").update(dbJson).digest("hex");

    const guard = new SpiderSenseGuard({
      patternDbPath: dbPath,
      patternDbVersion: "test-v1",
      patternDbChecksum: checksum,
    });
    const result = await guard.check(
      GuardAction.custom("embedding_check", { embedding: [1.0, 0.0, 0.0] }),
      ctx,
    );
    expect(result.allowed).toBe(false);

    expect(
      () =>
        new SpiderSenseGuard({
          patternDbPath: dbPath,
          patternDbVersion: "test-v1",
          patternDbChecksum: "deadbeef",
        }),
    ).not.toThrow();
    await expect(
      new SpiderSenseGuard({
        patternDbPath: dbPath,
        patternDbVersion: "test-v1",
        patternDbChecksum: "deadbeef",
      }).check(GuardAction.custom("embedding_check", { embedding: [1.0, 0.0, 0.0] }), ctx),
    ).rejects.toThrow(/checksum mismatch/i);

    await rm(dir, { recursive: true, force: true });
  });

  it("serializes concurrent checks while pattern DB load is in-flight", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "spider-sense-ts-race-"));
    const dbPath = path.join(dir, "patterns.json");
    const dbJson = JSON.stringify([
      {
        id: "p1",
        category: "prompt_injection",
        stage: "perception",
        label: "ignore previous",
        embedding: [1.0, 0.0, 0.0],
      },
    ]);
    await writeFile(dbPath, dbJson, "utf8");
    const checksum = createHash("sha256").update(dbJson).digest("hex");

    const guard = new SpiderSenseGuard({
      patternDbPath: dbPath,
      patternDbVersion: "test-v1",
      patternDbChecksum: checksum,
    });
    const action = GuardAction.custom("embedding_check", { embedding: [1.0, 0.0, 0.0] });

    type LoaderHook = (config: unknown) => Promise<void>;
    const guarded = guard as unknown as { loadPatternDbFromPath: LoaderHook };
    const originalLoad = guarded.loadPatternDbFromPath.bind(guarded);
    let releaseLoad!: () => void;
    const loadGate = new Promise<void>((resolve) => {
      releaseLoad = resolve;
    });
    let signalStart!: () => void;
    const loadStarted = new Promise<void>((resolve) => {
      signalStart = resolve;
    });

    guarded.loadPatternDbFromPath = async (config: unknown) => {
      signalStart();
      await loadGate;
      await originalLoad(config);
    };

    const firstCheck = guard.check(action, ctx);
    await loadStarted;
    await Promise.resolve();

    let secondSettled = false;
    const secondCheck = guard.check(action, ctx).then((result) => {
      secondSettled = true;
      return result;
    });

    await Promise.resolve();
    expect(secondSettled).toBe(false);

    releaseLoad();
    const [firstResult, secondResult] = await Promise.all([firstCheck, secondCheck]);
    expect(firstResult.allowed).toBe(false);
    expect(secondResult.allowed).toBe(false);

    await rm(dir, { recursive: true, force: true });
  });

  it("retries pattern DB loading after a transient initialization failure", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "spider-sense-ts-retry-"));
    const dbPath = path.join(dir, "patterns.json");
    const dbJson = JSON.stringify([
      {
        id: "p1",
        category: "prompt_injection",
        stage: "perception",
        label: "ignore previous",
        embedding: [1.0, 0.0, 0.0],
      },
    ]);
    await writeFile(dbPath, dbJson, "utf8");
    const checksum = createHash("sha256").update(dbJson).digest("hex");

    const guard = new SpiderSenseGuard({
      patternDbPath: dbPath,
      patternDbVersion: "test-v1",
      patternDbChecksum: checksum,
    });
    const action = GuardAction.custom("embedding_check", { embedding: [1.0, 0.0, 0.0] });

    type LoaderHook = (config: unknown) => Promise<void>;
    const guarded = guard as unknown as { loadPatternDbFromPath: LoaderHook };
    const originalLoad = guarded.loadPatternDbFromPath.bind(guarded);
    let attempts = 0;
    guarded.loadPatternDbFromPath = async (config: unknown) => {
      attempts += 1;
      if (attempts === 1) {
        throw new Error("transient load failure");
      }
      await originalLoad(config);
    };

    await expect(guard.check(action, ctx)).rejects.toThrow(/transient load failure/i);
    const second = await guard.check(action, ctx);
    expect(second.allowed).toBe(false);
    expect(attempts).toBe(2);

    await rm(dir, { recursive: true, force: true });
  });

  it("emits metrics snapshots", async () => {
    const events: Array<Record<string, unknown>> = [];
    const guard = new SpiderSenseGuard({
      patterns: testPatterns,
      metricsHook: (event) => events.push(event as unknown as Record<string, unknown>),
    });
    await guard.check(GuardAction.custom("embedding_check", { embedding: [1.0, 0.0, 0.0] }), ctx);
    await guard.check(
      GuardAction.custom("embedding_check", { embedding: [0.577, 0.577, 0.577] }),
      ctx,
    );
    expect(events.length).toBe(2);
    expect(events[1].total_count).toBe(2);
    expect(events[1]).toHaveProperty("ambiguity_rate");
    expect(events[0]).toHaveProperty("db_source");
    expect(events[0]).toHaveProperty("provider_attempts");
  });
});
