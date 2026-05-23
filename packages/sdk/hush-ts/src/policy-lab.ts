import { ensureWasm, getWasmModule } from "./crypto/backend.js";
import type { HushWasmModule, WasmPolicyLabInstance } from "./types/wasm.js";

export interface SynthResult {
  policyYaml: string;
  risks: string[];
}

export interface SimulationSummary {
  total: number;
  allowed: number;
  warn: number;
  blocked: number;
}

export interface SimulationResultEntry {
  eventId: string;
  outcome: string;
  allowed: boolean;
  denied: boolean;
  warn: boolean;
  reasonCode: string;
  guard?: string;
  severity?: string;
  message?: string;
}

export interface SimulateResult {
  summary: SimulationSummary;
  results: SimulationResultEntry[];
}

/**
 * PolicyLab: unified observe -> hunt -> OCSF -> synth pipeline.
 * Backed by Rust compiled to WASM.
 * WASM is initialized lazily on first use.
 */
export class PolicyLab {
  private readonly inner: WasmPolicyLabInstance;

  private constructor(inner: WasmPolicyLabInstance) {
    this.inner = inner;
  }

  private static async getWasmModule(): Promise<HushWasmModule> {
    await ensureWasm();
    const wasm = getWasmModule();
    if (
      !wasm?.WasmPolicyLab ||
      !wasm?.policy_lab_synth ||
      !wasm?.policy_lab_to_ocsf ||
      !wasm?.policy_lab_to_timeline
    ) {
      throw new Error(
        "Installed @clawdstrike/wasm does not expose PolicyLab APIs. " +
          "Upgrade @clawdstrike/wasm to a version with PolicyLab support.",
      );
    }
    return wasm;
  }

  /**
   * Create a PolicyLab handle from policy YAML.
   */
  static async create(policyYaml: string): Promise<PolicyLab> {
    const wasm = await PolicyLab.getWasmModule();
    return new PolicyLab(new wasm.WasmPolicyLab(policyYaml));
  }

  /**
   * Simulate events against the loaded policy.
   *
   * Note: Simulation requires a native runtime (tokio) and is not available
   * in the WASM build. Use the Python or Go SDK for simulate support.
   *
   * @throws Error always — simulation is not supported in the WASM/TS SDK.
   */
  simulate(_eventsJsonl: string): SimulateResult {
    // Keep handle live for API shape parity with native SDKs.
    void this.inner;
    throw new Error(
      "PolicyLab.simulate() is not available in the WASM build. " +
        "Use the Python SDK, Go SDK, or Rust CLI for simulation.",
    );
  }

  /** Synthesize a candidate policy from observed events. */
  static async synth(eventsJsonl: string): Promise<SynthResult> {
    const wasm = await PolicyLab.getWasmModule();
    const json: string = wasm.policy_lab_synth(eventsJsonl);
    return JSON.parse(json) as SynthResult;
  }

  /** Convert PolicyEvent JSONL to OCSF JSONL. */
  static async toOcsf(eventsJsonl: string): Promise<string> {
    const wasm = await PolicyLab.getWasmModule();
    return wasm.policy_lab_to_ocsf(eventsJsonl);
  }

  /** Convert PolicyEvent JSONL to TimelineEvent JSONL. */
  static async toTimeline(eventsJsonl: string): Promise<string> {
    const wasm = await PolicyLab.getWasmModule();
    return wasm.policy_lab_to_timeline(eventsJsonl);
  }
}
