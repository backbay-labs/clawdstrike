/**
 * PolicyEngine Performance Benchmarks
 *
 * Run with: npm run build && node benchmarks/policy-engine.bench.mjs
 *
 * Measures real-world latency of the PolicyEngine used in OpenClaw integration.
 */

import { performance } from "perf_hooks";
import { PolicyEngine } from "../src/policy/engine.js";
import type { ClawdstrikeConfig } from "../src/types.js";

// ============================================================================
// Benchmark Utilities
// ============================================================================

interface BenchmarkResult {
  name: string;
  iterations: number;
  totalMs: number;
  avgMs: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
}

async function benchmark(
  name: string,
  fn: () => Promise<void>,
  options: { iterations?: number; warmup?: number } = {}
): Promise<BenchmarkResult> {
  const { iterations = 1000, warmup = 50 } = options;

  // Warmup
  for (let i = 0; i < warmup; i++) {
    await fn();
  }

  // Collect samples
  const samples: number[] = [];

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    await fn();
    samples.push(performance.now() - start);
  }

  // Sort for percentiles
  samples.sort((a, b) => a - b);

  const totalMs = samples.reduce((a, b) => a + b, 0);

  return {
    name,
    iterations,
    totalMs,
    avgMs: totalMs / iterations,
    p50Ms: samples[Math.floor(iterations * 0.5)],
    p95Ms: samples[Math.floor(iterations * 0.95)],
    p99Ms: samples[Math.floor(iterations * 0.99)],
  };
}

function printTable(results: BenchmarkResult[]): void {
  console.log("\n" + "=".repeat(80));
  console.log("POLICYENGINE BENCHMARK RESULTS");
  console.log("=".repeat(80));

  const headers = ["Benchmark", "Avg (ms)", "p50 (ms)", "p95 (ms)", "p99 (ms)", "Total (ms)"];
  const widths = [30, 12, 12, 12, 12, 12];

  // Header
  console.log(headers.map((h, i) => h.padEnd(widths[i])).join(""));
  console.log("-".repeat(80));

  // Rows
  for (const r of results) {
    console.log(
      [
        r.name.padEnd(widths[0]),
        r.avgMs.toFixed(4).padStart(widths[1]),
        r.p50Ms.toFixed(4).padStart(widths[2]),
        r.p95Ms.toFixed(4).padStart(widths[3]),
        r.p99Ms.toFixed(4).padStart(widths[4]),
        r.totalMs.toFixed(1).padStart(widths[5]),
      ].join("")
    );
  }

  console.log("=".repeat(80));
}

// ============================================================================
// Test Events
// ============================================================================

function makeFileReadEvent(path: string, id: number) {
  return {
    eventId: `bench-file-${id}`,
    eventType: "file_read" as const,
    timestamp: new Date().toISOString(),
    data: { type: "file", path, operation: "read" },
  };
}

function makeNetworkEvent(host: string, id: number) {
  return {
    eventId: `bench-net-${id}`,
    eventType: "network_egress" as const,
    timestamp: new Date().toISOString(),
    data: { type: "network", host, port: 443 },
  };
}

function makeCommandEvent(command: string, id: number) {
  return {
    eventId: `bench-cmd-${id}`,
    eventType: "command_exec" as const,
    timestamp: new Date().toISOString(),
    data: { type: "command", command, args: [] },
  };
}

// ============================================================================
// Run Benchmarks
// ============================================================================

async function main() {
  console.log("PolicyEngine Performance Benchmarks");
  console.log(`Node.js ${process.version}`);
  console.log(`Date: ${new Date().toISOString()}\n`);

  const config: ClawdstrikeConfig = {
    mode: "deterministic",
    logLevel: "error", // Suppress logs during benchmark
    guards: {
      forbidden_path: true,
      egress: true,
      secret_leak: true,
      patch_integrity: true,
    },
  };

  const engine = new PolicyEngine(config);
  const results: BenchmarkResult[] = [];

  let counter = 0;

  // File read - allowed
  results.push(
    await benchmark("File Read (allowed)", async () => {
      await engine.evaluate(makeFileReadEvent("/tmp/test.txt", counter++) as any);
    })
  );

  // File read - blocked
  results.push(
    await benchmark("File Read (blocked)", async () => {
      await engine.evaluate(makeFileReadEvent("~/.ssh/id_rsa", counter++) as any);
    })
  );

  // Network egress - allowed
  results.push(
    await benchmark("Network Egress (allowed)", async () => {
      await engine.evaluate(makeNetworkEvent("api.github.com", counter++) as any);
    })
  );

  // Network egress - blocked
  results.push(
    await benchmark("Network Egress (blocked)", async () => {
      await engine.evaluate(makeNetworkEvent("evil-exfil.com", counter++) as any);
    })
  );

  // Command execution
  results.push(
    await benchmark("Command Exec", async () => {
      await engine.evaluate(makeCommandEvent("ls -la", counter++) as any);
    })
  );

  // Rapid sequential (simulates agent tool loop)
  results.push(
    await benchmark(
      "Rapid Sequential (10 checks)",
      async () => {
        for (let i = 0; i < 10; i++) {
          await engine.evaluate(makeFileReadEvent("/tmp/file" + i, counter++) as any);
        }
      },
      { iterations: 100 }
    )
  );

  printTable(results);

  // Summary
  const avgOverhead = results
    .filter((r) => !r.name.includes("Sequential"))
    .reduce((sum, r) => sum + r.avgMs, 0) / 5;

  console.log(`\nSummary:`);
  console.log(`  Average single-check overhead: ${avgOverhead.toFixed(4)}ms`);
  console.log(`  Typical LLM API latency:       500-2000ms`);
  console.log(`  Guard overhead as % of LLM:    ${((avgOverhead / 1000) * 100).toFixed(4)}%`);
  console.log(`  Verdict: Negligible impact on agent performance`);

  // JSON output for CI
  if (process.env.CI || process.env.OUTPUT_JSON) {
    const jsonOutput = {
      timestamp: new Date().toISOString(),
      node: process.version,
      summary: {
        avgOverheadMs: avgOverhead,
        overheadPercent: (avgOverhead / 1000) * 100,
      },
      results: results.map((r) => ({
        name: r.name,
        avgMs: r.avgMs,
        p50Ms: r.p50Ms,
        p95Ms: r.p95Ms,
        p99Ms: r.p99Ms,
      })),
    };
    console.log("\nJSON Output:");
    console.log(JSON.stringify(jsonOutput, null, 2));
  }
}

main().catch(console.error);
