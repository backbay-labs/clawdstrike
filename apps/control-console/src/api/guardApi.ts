function getApiBase(): string {
  return localStorage.getItem("hushd_url") || "";
}

function getHeaders(): Record<string, string> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const apiBase = getApiBase();
  const apiKey = localStorage.getItem("hushd_api_key");
  if (apiBase && apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }
  return headers;
}

export interface GuardTestResult {
  decision: "allowed" | "blocked";
  guard: string;
  reasoning?: string;
  duration_ms?: number;
}

const GUARD_ACTION_TYPES: Record<string, string> = {
  ForbiddenPathGuard: "file",
  EgressAllowlistGuard: "network",
  SecretLeakGuard: "file_write",
  PatchIntegrityGuard: "patch",
  McpToolGuard: "mcp_tool",
  PromptInjectionGuard: "prompt",
  JailbreakGuard: "prompt",
};

export async function testGuard(
  guardName: string,
  input: Record<string, unknown>,
): Promise<GuardTestResult> {
  const actionType = GUARD_ACTION_TYPES[guardName] || "unknown";
  const res = await fetch(`${getApiBase()}/api/v1/check`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({
      ...input,
      action_type: actionType,
      target: input.target ?? input.path ?? input.domain ?? "",
      guard: guardName,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Guard test failed: ${res.status}`);
  }
  return res.json();
}
