import {
  controlHeaders,
  jsonFetch,
  preferredUrl,
  proxyUrl,
} from "./internal";
import type {
  FleetConnection,
  HierarchyNode,
  HierarchyNodeInput,
  HierarchyNodeUpdate,
  HierarchyTreeResponse,
} from "./types";

export async function fetchHierarchyNodes(
  conn: FleetConnection,
): Promise<HierarchyNode[]> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return [];

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/hierarchy/nodes`, kind),
      { headers: controlHeaders(conn) },
    );

    // Handle wrapped or bare array responses
    let list: unknown[];
    if (Array.isArray(res)) {
      list = res;
    } else if (res && typeof res === "object" && "nodes" in res) {
      const wrapped = res as { nodes: unknown };
      if (!Array.isArray(wrapped.nodes)) {
        throw new Error("[fleet-client] fetchHierarchyNodes: expected nodes to be an array");
      }
      list = wrapped.nodes;
    } else {
      throw new Error("[fleet-client] fetchHierarchyNodes: unexpected response shape");
    }

    return list.filter(isHierarchyNode);
  } catch (e) {
    console.warn("[fleet-client] fetchHierarchyNodes failed:", e);
    return [];
  }
}

export async function fetchHierarchyTree(
  conn: FleetConnection,
): Promise<HierarchyTreeResponse | null> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return null;

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/hierarchy/tree`, kind),
      { headers: controlHeaders(conn) },
    );

    if (!res || typeof res !== "object") {
      throw new Error("[fleet-client] fetchHierarchyTree: unexpected response shape");
    }

    const obj = res as Record<string, unknown>;
    const rootId = obj.root_id;
    if (
      (typeof rootId !== "string" && rootId !== null) ||
      !Array.isArray(obj.nodes)
    ) {
      throw new Error("[fleet-client] fetchHierarchyTree: expected { root_id, nodes }");
    }

    return {
      root_id: rootId,
      nodes: (obj.nodes as unknown[]).filter(isHierarchyNode),
    };
  } catch (e) {
    console.warn("[fleet-client] fetchHierarchyTree failed:", e);
    return null;
  }
}

export async function createHierarchyNode(
  conn: FleetConnection,
  node: HierarchyNodeInput,
): Promise<{ success: boolean; id?: string; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, error: "No API URL configured" };

  try {
    const res = await jsonFetch<{ id?: string; success?: boolean }>(
      proxyUrl(`${url}/api/v1/hierarchy/nodes`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify(node),
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

export async function updateHierarchyNode(
  conn: FleetConnection,
  id: string,
  updates: HierarchyNodeUpdate,
): Promise<{ success: boolean; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, error: "No API URL configured" };

  try {
    await jsonFetch<{ success?: boolean }>(
      proxyUrl(`${url}/api/v1/hierarchy/nodes/${encodeURIComponent(id)}`, kind),
      {
        method: "PUT",
        headers: controlHeaders(conn),
        body: JSON.stringify(updates),
      },
    );
    return { success: true };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * When reparent=true, children are moved to the deleted node's parent.
 * When reparent=false, all descendants are also deleted.
 */
export async function deleteHierarchyNode(
  conn: FleetConnection,
  id: string,
  reparent: boolean = false,
): Promise<{ success: boolean; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, error: "No API URL configured" };

  try {
    const endpoint = `${url}/api/v1/hierarchy/nodes/${encodeURIComponent(id)}?reparent=${reparent}`;
    await jsonFetch<{ success?: boolean }>(
      proxyUrl(endpoint, kind),
      {
        method: "DELETE",
        headers: controlHeaders(conn),
      },
    );
    return { success: true };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

function isHierarchyNode(value: unknown): value is HierarchyNode {
  if (!value || typeof value !== "object") return false;
  const obj = value as Record<string, unknown>;
  return typeof obj.id === "string" && typeof obj.name === "string" && typeof obj.node_type === "string";
}
