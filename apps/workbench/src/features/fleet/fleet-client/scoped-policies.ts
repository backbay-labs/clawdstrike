import {
  controlHeaders,
  jsonFetch,
  preferredUrl,
  proxyUrl,
} from "./internal";
import type {
  FleetConnection,
  PolicyAssignment,
  PolicyAssignmentInput,
  ScopedPolicy,
  ScopedPolicyInput,
} from "./types";

export async function fetchScopedPolicies(
  conn: FleetConnection,
): Promise<ScopedPolicy[]> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return [];

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/scoped-policies`, kind),
      { headers: controlHeaders(conn) },
    );

    // Handle wrapped or bare array responses
    let list: unknown[];
    if (Array.isArray(res)) {
      list = res;
    } else if (res && typeof res === "object" && "scoped_policies" in res) {
      const wrapped = res as { scoped_policies: unknown };
      if (!Array.isArray(wrapped.scoped_policies)) {
        throw new Error("[fleet-client] fetchScopedPolicies: expected scoped_policies to be an array");
      }
      list = wrapped.scoped_policies;
    } else if (res && typeof res === "object" && "policies" in res) {
      const wrapped = res as { policies: unknown };
      if (!Array.isArray(wrapped.policies)) {
        throw new Error("[fleet-client] fetchScopedPolicies: expected policies to be an array");
      }
      list = wrapped.policies;
    } else {
      throw new Error("[fleet-client] fetchScopedPolicies: unexpected response shape");
    }

    return list.filter((p): p is ScopedPolicy => {
      if (!p || typeof p !== "object") return false;
      const obj = p as Record<string, unknown>;
      return typeof obj.id === "string" && typeof obj.scope_id === "string";
    });
  } catch (e) {
    console.warn("[fleet-client] fetchScopedPolicies failed:", e);
    return [];
  }
}

export async function createScopedPolicy(
  conn: FleetConnection,
  policy: ScopedPolicyInput,
): Promise<{ success: boolean; id?: string; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, error: "No API URL configured" };

  try {
    const res = await jsonFetch<{ id?: string; success?: boolean }>(
      proxyUrl(`${url}/api/v1/scoped-policies`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify(policy),
      },
    );
    return { success: true, id: res.id };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function fetchPolicyAssignments(
  conn: FleetConnection,
): Promise<PolicyAssignment[]> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return [];

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/policy-assignments`, kind),
      { headers: controlHeaders(conn) },
    );

    let list: unknown[];
    if (Array.isArray(res)) {
      list = res;
    } else if (res && typeof res === "object" && "assignments" in res) {
      const wrapped = res as { assignments: unknown };
      if (!Array.isArray(wrapped.assignments)) {
        throw new Error("[fleet-client] fetchPolicyAssignments: expected assignments to be an array");
      }
      list = wrapped.assignments;
    } else {
      throw new Error("[fleet-client] fetchPolicyAssignments: unexpected response shape");
    }

    return list.filter((a): a is PolicyAssignment => {
      if (!a || typeof a !== "object") return false;
      const obj = a as Record<string, unknown>;
      return typeof obj.id === "string" && typeof obj.scope_id === "string";
    });
  } catch (e) {
    console.warn("[fleet-client] fetchPolicyAssignments failed:", e);
    return [];
  }
}

export async function assignPolicyToScope(
  conn: FleetConnection,
  assignment: PolicyAssignmentInput,
): Promise<{ success: boolean; id?: string; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, error: "No API URL configured" };

  try {
    const res = await jsonFetch<{ id?: string; success?: boolean }>(
      proxyUrl(`${url}/api/v1/policy-assignments`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify(assignment),
      },
    );
    return { success: true, id: res.id };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
