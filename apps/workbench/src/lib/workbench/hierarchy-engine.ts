// ---------------------------------------------------------------------------
// Hierarchy engine — CRUD operations and effective-policy merge logic
// ---------------------------------------------------------------------------

import type {
  OrgNode,
  OrgNodeType,
  PolicyHierarchy,
  EffectivePolicy,
  EffectivePolicySource,
  EffectivePolicyEntry,
} from "./hierarchy-types";
import type { SavedPolicy, GuardConfigMap, PolicySettings } from "./types";
import { GUARD_REGISTRY } from "./guard-registry";

// ---------------------------------------------------------------------------
// localStorage persistence key
// ---------------------------------------------------------------------------

const HIERARCHY_STORAGE_KEY = "clawdstrike_policy_hierarchy";

// ---------------------------------------------------------------------------
// ID generation
// ---------------------------------------------------------------------------

function uid(): string {
  return crypto.randomUUID();
}

// ---------------------------------------------------------------------------
// Default / demo hierarchy
// ---------------------------------------------------------------------------

export function createDefaultHierarchy(): PolicyHierarchy {
  // Org
  const orgId = uid();

  // Teams
  const engId = uid();
  const secId = uid();
  const csId = uid();

  // Endpoints
  const buildServer01 = uid();
  const buildServer02 = uid();
  const scannerHost = uid();
  const supportServer01 = uid();

  // Runtimes
  const plannerAgent = uid();
  const coderAgent = uid();
  const deployAgent = uid();
  const vulnScanner = uid();
  const penTestAgent = uid();
  const supportAgent01 = uid();
  const supportAgent02 = uid();

  const nodes: Record<string, OrgNode> = {
    [orgId]: {
      id: orgId,
      name: "Acme Corp",
      type: "org",
      parentId: null,
      children: [engId, secId, csId],
      metadata: {
        description: "Root organization",
        memberCount: 120,
        agentCount: 7,
      },
    },

    // --- Engineering team ---
    [engId]: {
      id: engId,
      name: "Engineering",
      type: "team",
      parentId: orgId,
      children: [buildServer01, buildServer02],
      metadata: {
        description: "Core engineering team",
        memberCount: 45,
        agentCount: 3,
      },
    },
    [buildServer01]: {
      id: buildServer01,
      name: "build-server-01",
      type: "endpoint",
      parentId: engId,
      children: [plannerAgent, coderAgent],
      metadata: {
        description: "Primary CI/CD build server",
      },
    },
    [plannerAgent]: {
      id: plannerAgent,
      name: "planner-agent",
      type: "runtime",
      parentId: buildServer01,
      children: [],
      metadata: { description: "Task planning and decomposition agent" },
    },
    [coderAgent]: {
      id: coderAgent,
      name: "coder-agent",
      type: "runtime",
      parentId: buildServer01,
      children: [],
      metadata: { description: "Autonomous coding agent" },
    },
    [buildServer02]: {
      id: buildServer02,
      name: "build-server-02",
      type: "endpoint",
      parentId: engId,
      children: [deployAgent],
      metadata: {
        description: "Secondary build server for deployments",
      },
    },
    [deployAgent]: {
      id: deployAgent,
      name: "deploy-agent",
      type: "runtime",
      parentId: buildServer02,
      children: [],
      metadata: { description: "Deployment pipeline agent" },
    },

    // --- Security team ---
    [secId]: {
      id: secId,
      name: "Security",
      type: "team",
      parentId: orgId,
      children: [scannerHost],
      metadata: {
        description: "Security operations team",
        memberCount: 15,
        agentCount: 2,
      },
    },
    [scannerHost]: {
      id: scannerHost,
      name: "scanner-host",
      type: "endpoint",
      parentId: secId,
      children: [vulnScanner, penTestAgent],
      metadata: {
        description: "Dedicated security scanning host",
      },
    },
    [vulnScanner]: {
      id: vulnScanner,
      name: "vuln-scanner",
      type: "runtime",
      parentId: scannerHost,
      children: [],
      metadata: { description: "Vulnerability scanner agent" },
    },
    [penTestAgent]: {
      id: penTestAgent,
      name: "pen-test-agent",
      type: "runtime",
      parentId: scannerHost,
      children: [],
      metadata: { description: "Automated penetration testing agent" },
    },

    // --- Customer Support team ---
    [csId]: {
      id: csId,
      name: "Customer Support",
      type: "team",
      parentId: orgId,
      children: [supportServer01],
      metadata: {
        description: "Customer-facing support team",
        memberCount: 30,
        agentCount: 2,
      },
    },
    [supportServer01]: {
      id: supportServer01,
      name: "support-server-01",
      type: "endpoint",
      parentId: csId,
      children: [supportAgent01, supportAgent02],
      metadata: {
        description: "Support automation server",
      },
    },
    [supportAgent01]: {
      id: supportAgent01,
      name: "support-agent-01",
      type: "runtime",
      parentId: supportServer01,
      children: [],
      metadata: { description: "Tier-1 support agent" },
    },
    [supportAgent02]: {
      id: supportAgent02,
      name: "support-agent-02",
      type: "runtime",
      parentId: supportServer01,
      children: [],
      metadata: { description: "Tier-2 support agent" },
    },
  };

  return { nodes, rootId: orgId };
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/**
 * Returns the ordered ancestry path from root to the given node (inclusive).
 */
export function getAncestryPath(
  hierarchy: PolicyHierarchy,
  nodeId: string,
): OrgNode[] {
  const path: OrgNode[] = [];
  const visited = new Set<string>();
  let current = hierarchy.nodes[nodeId];
  while (current) {
    if (visited.has(current.id)) {
      console.warn(
        `[hierarchy-engine] Cycle detected in ancestry path at node "${current.id}" ("${current.name}"). Breaking.`,
      );
      break;
    }
    visited.add(current.id);
    path.unshift(current);
    current = current.parentId ? hierarchy.nodes[current.parentId] : undefined!;
  }
  return path;
}

/**
 * Returns all descendant IDs (inclusive) of a node, depth-first.
 */
export function getDescendants(
  hierarchy: PolicyHierarchy,
  nodeId: string,
): string[] {
  const result: string[] = [];
  const visited = new Set<string>();
  const stack = [nodeId];
  while (stack.length > 0) {
    const id = stack.pop()!;
    if (visited.has(id)) {
      console.warn(
        `[hierarchy-engine] Cycle detected in descendants traversal at node "${id}". Skipping.`,
      );
      continue;
    }
    visited.add(id);
    result.push(id);
    const node = hierarchy.nodes[id];
    if (node) {
      // Push in reverse so we visit left-to-right
      for (let i = node.children.length - 1; i >= 0; i--) {
        stack.push(node.children[i]);
      }
    }
  }
  return result;
}

/**
 * Returns all leaf (runtime) node IDs under a given node.
 */
export function getLeafAgents(
  hierarchy: PolicyHierarchy,
  nodeId: string,
): string[] {
  return getDescendants(hierarchy, nodeId).filter(
    (id) => hierarchy.nodes[id]?.type === "runtime",
  );
}

// ---------------------------------------------------------------------------
// Effective policy computation
// ---------------------------------------------------------------------------

/**
 * Resolves the linked SavedPolicy for a node, if any.
 */
function resolvePolicy(
  node: OrgNode,
  savedPolicies: SavedPolicy[],
): SavedPolicy | undefined {
  if (!node.policyId) return undefined;
  return savedPolicies.find((p) => p.id === node.policyId);
}

/**
 * Deep-merge two guard config maps. Child values override parent at the
 * per-guard level (entire guard config replaced, not individual fields).
 */
function mergeGuardConfigs(
  parent: GuardConfigMap,
  child: GuardConfigMap,
): GuardConfigMap {
  const result: GuardConfigMap = { ...parent };
  for (const key of Object.keys(child) as (keyof GuardConfigMap)[]) {
    const childVal = child[key];
    if (childVal !== undefined && childVal !== null) {
      // Child fully replaces parent at the guard level — deep-clone to
      // prevent downstream mutation from corrupting the source policy.
      (result as Record<string, unknown>)[key] = structuredClone(childVal);
    }
  }
  return result;
}

/**
 * Shallow-merge two settings objects. Child values override parent.
 */
function mergeSettings(
  parent: PolicySettings,
  child: PolicySettings,
): PolicySettings {
  return { ...parent, ...child };
}

/**
 * Compute the effective (merged) policy for a node by walking from root
 * through the ancestry chain. Child overrides parent; nodes without a
 * linked policy are pass-through.
 */
export function computeEffectivePolicy(
  hierarchy: PolicyHierarchy,
  nodeId: string,
  savedPolicies: SavedPolicy[],
): EffectivePolicy {
  const path = getAncestryPath(hierarchy, nodeId);

  const source: EffectivePolicySource[] = path.map((n) => ({
    nodeId: n.id,
    nodeName: n.name,
    level: n.type,
  }));

  // Track which node introduced each guard/setting
  const guardOwner: Record<string, string> = {}; // guardId -> node name
  const settingOwner: Record<string, string> = {}; // setting key -> node name
  const guardOverridden: Record<string, boolean> = {};
  const settingOverridden: Record<string, boolean> = {};

  let mergedGuards: GuardConfigMap = {};
  let mergedSettings: PolicySettings = {};

  for (const node of path) {
    const saved = resolvePolicy(node, savedPolicies);
    if (!saved) continue;

    const policy = saved.policy;

    // Track guard provenance
    for (const gid of Object.keys(policy.guards) as (keyof GuardConfigMap)[]) {
      if (policy.guards[gid] !== undefined) {
        const wasSet = guardOwner[gid] !== undefined;
        guardOwner[gid] = node.name;
        if (wasSet) {
          guardOverridden[gid] = true;
        }
      }
    }

    // Track settings provenance
    for (const key of Object.keys(policy.settings) as (keyof PolicySettings)[]) {
      if (policy.settings[key] !== undefined) {
        const wasSet = settingOwner[key] !== undefined;
        settingOwner[key] = node.name;
        if (wasSet) {
          settingOverridden[key] = true;
        }
      }
    }

    mergedGuards = mergeGuardConfigs(mergedGuards, policy.guards);
    mergedSettings = mergeSettings(mergedSettings, policy.settings);
  }

  // Build guard entries
  const guards: Record<string, EffectivePolicyEntry> = {};
  for (const meta of GUARD_REGISTRY) {
    const cfg = mergedGuards[meta.id as keyof GuardConfigMap];
    if (cfg !== undefined) {
      guards[meta.id] = {
        value: cfg,
        inheritedFrom: guardOwner[meta.id] ?? "unknown",
        overridden: !!guardOverridden[meta.id],
      };
    }
  }

  // Build settings entries
  const settings: Record<string, EffectivePolicyEntry> = {};
  for (const key of Object.keys(mergedSettings) as (keyof PolicySettings)[]) {
    settings[key] = {
      value: mergedSettings[key],
      inheritedFrom: settingOwner[key] ?? "unknown",
      overridden: !!settingOverridden[key],
    };
  }

  return { source, guards, settings };
}

// ---------------------------------------------------------------------------
// Name validation
// ---------------------------------------------------------------------------

const MAX_NODE_NAME_LENGTH = 128;

/**
 * Sanitizes and validates a node name. Returns the cleaned name, or `null`
 * if the name is invalid (empty after trim, exceeds length limit).
 */
function sanitizeNodeName(raw: string): string | null {
  // Strip control characters (U+0000-U+001F except U+0020 space, U+007F-U+009F)
  // eslint-disable-next-line no-control-regex
  const stripped = raw.replace(/[\x00-\x1F\x7F-\x9F]/g, "");
  const trimmed = stripped.trim();

  if (trimmed.length === 0) {
    console.warn("[hierarchy-engine] Node name is empty after sanitization.");
    return null;
  }

  if (trimmed.length > MAX_NODE_NAME_LENGTH) {
    console.warn(
      `[hierarchy-engine] Node name exceeds ${MAX_NODE_NAME_LENGTH} characters (got ${trimmed.length}). Rejecting.`,
    );
    return null;
  }

  return trimmed;
}

// ---------------------------------------------------------------------------
// CRUD mutations (all pure — return a new hierarchy)
// ---------------------------------------------------------------------------

/** Valid parent type for each child node type. */
const VALID_PARENT_TYPE: Record<OrgNodeType, OrgNodeType | null> = {
  org: null, // org has no parent
  team: "org",
  endpoint: "team",
  runtime: "endpoint",
};

export function addNode(
  hierarchy: PolicyHierarchy,
  parentId: string,
  node: Omit<OrgNode, "id" | "children">,
): PolicyHierarchy {
  const parent = hierarchy.nodes[parentId];
  if (!parent) return hierarchy;

  // Validate node name
  const cleanName = sanitizeNodeName(node.name);
  if (cleanName === null) return hierarchy;

  // Validate parent-child type relationship
  const requiredParentType = VALID_PARENT_TYPE[node.type];
  if (requiredParentType !== parent.type) return hierarchy;

  const id = uid();
  const newNode: OrgNode = { ...node, id, name: cleanName, children: [] };

  return {
    ...hierarchy,
    nodes: {
      ...hierarchy.nodes,
      [id]: newNode,
      [parentId]: {
        ...parent,
        children: [...parent.children, id],
      },
    },
  };
}

export function removeNode(
  hierarchy: PolicyHierarchy,
  nodeId: string,
): PolicyHierarchy {
  const node = hierarchy.nodes[nodeId];
  if (!node || nodeId === hierarchy.rootId) return hierarchy;

  // Collect all descendants to remove
  const toRemove = new Set(getDescendants(hierarchy, nodeId));

  const newNodes: Record<string, OrgNode> = {};
  for (const [id, n] of Object.entries(hierarchy.nodes)) {
    if (toRemove.has(id)) continue;
    if (n.id === node.parentId) {
      // Remove from parent's children
      newNodes[id] = {
        ...n,
        children: n.children.filter((c) => c !== nodeId),
      };
    } else {
      newNodes[id] = n;
    }
  }

  return { ...hierarchy, nodes: newNodes };
}

export function moveNode(
  hierarchy: PolicyHierarchy,
  nodeId: string,
  newParentId: string,
): PolicyHierarchy {
  const node = hierarchy.nodes[nodeId];
  if (!node || nodeId === hierarchy.rootId) return hierarchy;
  if (node.parentId === newParentId) return hierarchy;

  // Prevent moving a node under its own descendant
  const descendants = new Set(getDescendants(hierarchy, nodeId));
  if (descendants.has(newParentId)) return hierarchy;

  const oldParent = node.parentId ? hierarchy.nodes[node.parentId] : undefined;
  const newParent = hierarchy.nodes[newParentId];
  if (!newParent) {
    console.warn(
      `[hierarchy-engine] moveNode: target parent "${newParentId}" does not exist. Move aborted.`,
    );
    return hierarchy;
  }

  // Validate parent-child type relationship
  const requiredParentType = VALID_PARENT_TYPE[node.type];
  if (requiredParentType !== newParent.type) return hierarchy;

  const newNodes = { ...hierarchy.nodes };

  // Remove from old parent
  if (oldParent) {
    newNodes[oldParent.id] = {
      ...oldParent,
      children: oldParent.children.filter((c) => c !== nodeId),
    };
  }

  // Add to new parent
  newNodes[newParentId] = {
    ...newParent,
    children: [...newParent.children, nodeId],
  };

  // Update node's parentId
  newNodes[nodeId] = { ...node, parentId: newParentId };

  return { ...hierarchy, nodes: newNodes };
}

export function assignPolicy(
  hierarchy: PolicyHierarchy,
  nodeId: string,
  policyId: string,
  policyName?: string,
): PolicyHierarchy {
  const node = hierarchy.nodes[nodeId];
  if (!node) return hierarchy;

  return {
    ...hierarchy,
    nodes: {
      ...hierarchy.nodes,
      [nodeId]: { ...node, policyId, policyName },
    },
  };
}

export function unassignPolicy(
  hierarchy: PolicyHierarchy,
  nodeId: string,
): PolicyHierarchy {
  const node = hierarchy.nodes[nodeId];
  if (!node) return hierarchy;

  const updated = { ...node };
  delete updated.policyId;
  delete updated.policyName;

  return {
    ...hierarchy,
    nodes: {
      ...hierarchy.nodes,
      [nodeId]: updated,
    },
  };
}

export function renameNode(
  hierarchy: PolicyHierarchy,
  nodeId: string,
  name: string,
): PolicyHierarchy {
  const node = hierarchy.nodes[nodeId];
  if (!node) return hierarchy;

  // Validate and sanitize the new name
  const cleanName = sanitizeNodeName(name);
  if (cleanName === null) return hierarchy;

  return {
    ...hierarchy,
    nodes: {
      ...hierarchy.nodes,
      [nodeId]: { ...node, name: cleanName },
    },
  };
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/**
 * Deduplicates `children` arrays across all nodes and migrates legacy
 * `type: "agent"` nodes to `type: "endpoint"`. Should be called after
 * loading from localStorage or after pulling from fleet data.
 */
export function normalizeHierarchy(
  hierarchy: PolicyHierarchy,
): PolicyHierarchy {
  const nodes: Record<string, OrgNode> = {};
  for (const [id, node] of Object.entries(hierarchy.nodes)) {
    const deduped = [...new Set(node.children)];
    // Migrate legacy "agent" type to "endpoint" for backward compat
    const type =
      (node.type as string) === "agent" ? ("endpoint" as OrgNodeType) : node.type;
    const needsUpdate =
      deduped.length !== node.children.length || type !== node.type;
    if (needsUpdate) {
      nodes[id] = { ...node, children: deduped, type };
    } else {
      nodes[id] = node;
    }
  }

  // Remove orphan nodes — collect all reachable IDs from rootId
  const reachable = new Set<string>();
  const stack = [hierarchy.rootId];
  while (stack.length > 0) {
    const id = stack.pop()!;
    if (reachable.has(id)) continue;
    reachable.add(id);
    const node = nodes[id];
    if (node) {
      for (const childId of node.children) {
        stack.push(childId);
      }
    }
  }

  const allIds = Object.keys(nodes);
  const orphanIds = allIds.filter((id) => !reachable.has(id));
  if (orphanIds.length > 0) {
    console.warn(
      `[hierarchy-engine] normalizeHierarchy: removing ${orphanIds.length} orphan node(s): ${orphanIds.join(", ")}`,
    );
    for (const orphanId of orphanIds) {
      delete nodes[orphanId];
    }
  }

  // Validate parent-child type constraints and remove violating nodes
  let removedViolators = true;
  while (removedViolators) {
    removedViolators = false;
    for (const [id, node] of Object.entries(nodes)) {
      if (id === hierarchy.rootId) continue;
      if (!node.parentId) continue;
      const parent = nodes[node.parentId];
      if (!parent) continue;

      const requiredParentType = VALID_PARENT_TYPE[node.type];
      if (requiredParentType !== parent.type) {
        console.warn(
          `[hierarchy-engine] normalizeHierarchy: node "${node.name}" (${node.type}) has invalid parent type "${parent.type}" (expected "${String(requiredParentType)}")` +
            `. Removing node and its descendants.`,
        );
        // Collect descendants of violating node to remove them all
        const toRemove = new Set<string>();
        const descStack = [id];
        while (descStack.length > 0) {
          const descId = descStack.pop()!;
          if (toRemove.has(descId)) continue;
          toRemove.add(descId);
          const descNode = nodes[descId];
          if (descNode) {
            for (const childId of descNode.children) {
              descStack.push(childId);
            }
          }
        }
        // Remove violating node from parent's children list
        nodes[node.parentId] = {
          ...parent,
          children: parent.children.filter((c) => c !== id),
        };
        // Remove all collected nodes
        for (const removeId of toRemove) {
          delete nodes[removeId];
        }
        removedViolators = true;
        break; // Restart scan since we mutated the map
      }
    }
  }

  return { ...hierarchy, nodes };
}

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

const VALID_NODE_TYPES = new Set<string>(["org", "team", "endpoint", "runtime"]);

/**
 * Validates the structural integrity of a parsed PolicyHierarchy object.
 * Returns the hierarchy if valid, or `null` if any check fails.
 * Logs `console.error` for every violation detected.
 */
export function validateHierarchyStructure(
  parsed: unknown,
): PolicyHierarchy | null {
  if (!parsed || typeof parsed !== "object") {
    console.error("[hierarchy-engine] validateHierarchyStructure: input is not an object.");
    return null;
  }

  const obj = parsed as Record<string, unknown>;

  // rootId must be a string
  if (typeof obj.rootId !== "string") {
    console.error("[hierarchy-engine] validateHierarchyStructure: rootId is not a string.");
    return null;
  }

  // nodes must be a non-null object
  if (!obj.nodes || typeof obj.nodes !== "object" || Array.isArray(obj.nodes)) {
    console.error("[hierarchy-engine] validateHierarchyStructure: nodes is not a non-null object.");
    return null;
  }

  const rootId = obj.rootId as string;
  const nodes = obj.nodes as Record<string, unknown>;

  // root node must exist
  if (!nodes[rootId]) {
    console.error(
      `[hierarchy-engine] validateHierarchyStructure: root node "${rootId}" not found in nodes.`,
    );
    return null;
  }

  // Validate every node
  for (const [key, raw] of Object.entries(nodes)) {
    if (!raw || typeof raw !== "object") {
      console.error(
        `[hierarchy-engine] validateHierarchyStructure: node "${key}" is not a valid object.`,
      );
      return null;
    }
    const node = raw as Record<string, unknown>;

    // id must be a string
    if (typeof node.id !== "string") {
      console.error(
        `[hierarchy-engine] validateHierarchyStructure: node "${key}" has non-string id.`,
      );
      return null;
    }

    // id must match the map key
    if (node.id !== key) {
      console.error(
        `[hierarchy-engine] validateHierarchyStructure: node map key "${key}" does not match node.id "${String(node.id)}".`,
      );
      return null;
    }

    // type must be a valid OrgNodeType
    if (typeof node.type !== "string" || !VALID_NODE_TYPES.has(node.type)) {
      console.error(
        `[hierarchy-engine] validateHierarchyStructure: node "${key}" has invalid type "${String(node.type)}".`,
      );
      return null;
    }

    // children must be an array of strings
    if (!Array.isArray(node.children)) {
      console.error(
        `[hierarchy-engine] validateHierarchyStructure: node "${key}" has non-array children.`,
      );
      return null;
    }
    for (const child of node.children) {
      if (typeof child !== "string") {
        console.error(
          `[hierarchy-engine] validateHierarchyStructure: node "${key}" has non-string child entry.`,
        );
        return null;
      }
      if (!nodes[child]) {
        console.error(
          `[hierarchy-engine] validateHierarchyStructure: node "${key}" references non-existent child "${child}".`,
        );
        return null;
      }
    }

    // parentId must be null or reference an existing node
    if (node.parentId !== null && node.parentId !== undefined) {
      if (typeof node.parentId !== "string") {
        console.error(
          `[hierarchy-engine] validateHierarchyStructure: node "${key}" has non-string parentId.`,
        );
        return null;
      }
      if (!nodes[node.parentId]) {
        console.error(
          `[hierarchy-engine] validateHierarchyStructure: node "${key}" references non-existent parent "${node.parentId}".`,
        );
        return null;
      }
    }
  }

  // Check for orphan nodes — every node must be reachable from rootId
  const reachable = new Set<string>();
  const stack = [rootId];
  while (stack.length > 0) {
    const id = stack.pop()!;
    if (reachable.has(id)) continue;
    reachable.add(id);
    const node = nodes[id] as Record<string, unknown> | undefined;
    if (node && Array.isArray(node.children)) {
      for (const child of node.children as string[]) {
        stack.push(child);
      }
    }
  }

  const allIds = Object.keys(nodes);
  const orphans = allIds.filter((id) => !reachable.has(id));
  if (orphans.length > 0) {
    console.error(
      `[hierarchy-engine] validateHierarchyStructure: ${orphans.length} orphan node(s) not reachable from root: ${orphans.join(", ")}`,
    );
    return null;
  }

  return parsed as PolicyHierarchy;
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

export function saveHierarchy(hierarchy: PolicyHierarchy): void {
  try {
    localStorage.setItem(HIERARCHY_STORAGE_KEY, JSON.stringify(hierarchy));
  } catch {
    // ignore quota errors
  }
}

export function loadHierarchy(): PolicyHierarchy | null {
  try {
    const raw = localStorage.getItem(HIERARCHY_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as unknown;

    // Migrate legacy "agent" type to "endpoint" before validation
    if (parsed && typeof parsed === "object" && (parsed as Record<string, unknown>).nodes) {
      const nodes = (parsed as Record<string, unknown>).nodes as Record<string, Record<string, unknown>>;
      for (const node of Object.values(nodes)) {
        if (node && typeof node === "object" && (node as Record<string, unknown>).type === "agent") {
          (node as Record<string, unknown>).type = "endpoint";
        }
      }
    }

    const validated = validateHierarchyStructure(parsed);
    if (!validated) {
      console.error("[hierarchy-engine] loadHierarchy: stored hierarchy failed validation, falling back to demo data.");
      return null;
    }
    return validated;
  } catch {
    return null;
  }
}

export function clearHierarchy(): void {
  try {
    localStorage.removeItem(HIERARCHY_STORAGE_KEY);
  } catch {
    // ignore
  }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

export interface HierarchyValidationIssue {
  nodeId: string;
  nodeName: string;
  message: string;
  severity: "error" | "warning";
}

/**
 * Validates all runtime (leaf) nodes and endpoints in the hierarchy,
 * checking effective policies and structural requirements.
 */
export function validateAllLeaves(
  hierarchy: PolicyHierarchy,
  savedPolicies: SavedPolicy[],
): HierarchyValidationIssue[] {
  const issues: HierarchyValidationIssue[] = [];

  // Validate endpoints: each must have at least one runtime child
  for (const node of Object.values(hierarchy.nodes)) {
    if (node.type !== "endpoint") continue;
    const runtimeChildren = node.children.filter(
      (cid) => hierarchy.nodes[cid]?.type === "runtime",
    );
    if (runtimeChildren.length === 0) {
      issues.push({
        nodeId: node.id,
        nodeName: node.name,
        message: "Endpoint has no runtime agents",
        severity: "warning",
      });
    }
  }

  // Validate runtimes (leaf nodes)
  const leaves = getLeafAgents(hierarchy, hierarchy.rootId);

  for (const leafId of leaves) {
    const node = hierarchy.nodes[leafId];
    if (!node) continue;

    const effective = computeEffectivePolicy(hierarchy, leafId, savedPolicies);

    // Check: at least one guard with a value
    const hasGuards = Object.keys(effective.guards).length > 0;
    if (!hasGuards) {
      // Walk ancestry to check if any node has a policy
      const anyPolicy = effective.source.some((s) => {
        const n = hierarchy.nodes[s.nodeId];
        return n?.policyId !== undefined;
      });

      if (!anyPolicy) {
        issues.push({
          nodeId: leafId,
          nodeName: node.name,
          message: "No policy assigned in the inheritance chain",
          severity: "error",
        });
      } else {
        issues.push({
          nodeId: leafId,
          nodeName: node.name,
          message: "Effective policy has no guards enabled",
          severity: "warning",
        });
      }
    }

    // Check: guards that are explicitly disabled — this is a deliberate
    // operator choice (e.g. disabling a guard for a specific runtime), so
    // flag as "warning" rather than "error".  True errors are reserved for
    // broken configurations like missing policies entirely.
    for (const [gid, entry] of Object.entries(effective.guards)) {
      const val = entry.value as Record<string, unknown> | undefined;
      if (val && val.enabled === false) {
        issues.push({
          nodeId: leafId,
          nodeName: node.name,
          message: `Guard "${gid}" is explicitly disabled`,
          severity: "warning",
        });
      }
    }
  }

  return issues;
}
