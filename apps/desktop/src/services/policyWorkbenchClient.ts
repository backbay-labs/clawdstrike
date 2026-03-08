import { type DaemonPolicyResponse, HushdClient, type PolicyEvalResponse } from "./hushdClient";
import {
  isTauri,
  type PolicyLoadResult,
  type PolicySaveResult,
  policyEvalEvent,
  policyLoad,
  policySave,
  policyValidate,
} from "./tauri";

export type PolicyLoadModel = PolicyLoadResult | DaemonPolicyResponse;
export interface PolicyValidationModel {
  valid: boolean;
  errors: Array<{ path: string; code: string; message: string }>;
  warnings: Array<{ path: string; code: string; message: string }>;
  normalized_version?: string;
}
export type PolicyEvalModel = PolicyEvalResponse;
export type PolicySaveModel = PolicySaveResult;

export class PolicyWorkbenchClientError extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "PolicyWorkbenchClientError";
  }
}

function toWorkbenchError(err: unknown): PolicyWorkbenchClientError {
  if (!(err instanceof Error)) {
    return new PolicyWorkbenchClientError("unknown_error", "Unknown policy workbench error");
  }

  const message = err.message || "Unknown policy workbench error";
  if (message.includes("policy_path_missing") || message.includes("No such file")) {
    return new PolicyWorkbenchClientError("policy_path_missing", message);
  }
  if (message.includes("policy_schema_unsupported")) {
    return new PolicyWorkbenchClientError("policy_schema_unsupported", message);
  }
  if (message.includes("Invalid policy YAML") || message.includes("policy_yaml_invalid")) {
    return new PolicyWorkbenchClientError("policy_yaml_invalid", message);
  }
  if (
    /policy_eval_invalid_event/i.test(message) ||
    /unsupported\s+event[_\s]?type/i.test(message)
  ) {
    return new PolicyWorkbenchClientError("policy_eval_invalid_event", message);
  }
  return new PolicyWorkbenchClientError("policy_request_failed", message);
}

export class PolicyWorkbenchClient {
  constructor(private daemonUrl: string) {}

  async loadPolicy(): Promise<PolicyLoadModel> {
    try {
      if (isTauri()) return await policyLoad();
      return await new HushdClient(this.daemonUrl).getPolicy();
    } catch (err) {
      throw toWorkbenchError(err);
    }
  }

  async validatePolicy(yaml: string): Promise<PolicyValidationModel> {
    try {
      if (isTauri()) return await policyValidate(yaml);
      const result = await new HushdClient(this.daemonUrl).validatePolicy(yaml);
      return {
        valid: result.valid,
        errors: result.errors.map((error) => ({
          path: error.path,
          code: error.code,
          message: error.message,
        })),
        warnings: result.warnings.map((warning) => ({
          path: warning.path,
          code: warning.code ?? "policy_warning",
          message: warning.message,
        })),
        normalized_version: result.normalized_version,
      };
    } catch (err) {
      throw toWorkbenchError(err);
    }
  }

  async evalPolicyEvent(event: Record<string, unknown>): Promise<PolicyEvalModel> {
    try {
      if (isTauri()) {
        return (await policyEvalEvent(event)) as unknown as PolicyEvalResponse;
      }
      return await new HushdClient(this.daemonUrl).eval(event);
    } catch (err) {
      throw toWorkbenchError(err);
    }
  }

  async savePolicy(yaml: string): Promise<PolicySaveModel> {
    try {
      if (isTauri()) return await policySave(yaml);
      return await new HushdClient(this.daemonUrl).updatePolicy(yaml);
    } catch (err) {
      throw toWorkbenchError(err);
    }
  }
}
