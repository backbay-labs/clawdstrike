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

export interface ValidateResult {
  valid: boolean;
  errors?: string[];
}

export interface UpdatePolicyResult {
  success: boolean;
  policy_hash?: string;
}

export async function validatePolicy(yaml: string): Promise<ValidateResult> {
  const res = await fetch(`${getApiBase()}/api/v1/policy/validate`, {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ yaml }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Validation request failed: ${res.status}`);
  }
  return res.json();
}

export async function updatePolicy(yaml: string): Promise<UpdatePolicyResult> {
  const res = await fetch(`${getApiBase()}/api/v1/policy`, {
    method: "PUT",
    headers: getHeaders(),
    body: JSON.stringify({ yaml }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Policy update failed: ${res.status}`);
  }
  return res.json();
}
