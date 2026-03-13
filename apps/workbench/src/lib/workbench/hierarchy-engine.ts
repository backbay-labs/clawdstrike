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
  const orgId = uid();
  const engId = uid();
  const secId = uid();
  const csId = uid();

  const agentCoder = uid();
  const agentReviewer = uid();
  const agentDeployer = uid();
  const agentScanner = uid();
  const agentMonitor = uid();
  const agentSupport1 = uid();
  const agentSupport2 = uid();

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
    [engId]: {
      id: engId,
      name: "Engineering",
      type: "team",
      parentId: orgId,
      children: [agentCoder, agentReviewer, agentDeployer],
      metadata: {
        description: "Core engineering team",
        memberCount: 45,
        agentCount: 3,
      },
    },
    [secId]: {
      id: secId,
      name: "Security",
      type: "team",
      parentId: orgId,
      children: [agentScanner, agentMonitor],
      metadata: {
        description: "Security operations team",
        memberCount: 15,
        agentCount: 2,
      },
    },
    [csId]: {
      id: csId,
      name: "Customer Support",
      type: "team",
      parentId: orgId,
      children: [agentSupport1, agentSupport2],
      metadata: {
        description: "Customer-facing support team",
        memberCount: 30,
        agentCount: 2,
      },
    },
    [agentCoder]: {
      id: agentCoder,
      name: "agent-coder-01",
      type: "agent",
      parentId: engId,
      children: [],
      metadata: { description: "Autonomous coding agent" },
    },
    [agentReviewer]: {
      id: agentReviewer,
      name: "agent-reviewer-01",
      type: "agent",
      parentId: engId,
      children: [],
      metadata: { description: "Code review agent" },
    },
    [agentDeployer]: {
      id: agentDeployer,
      name: "agent-deployer-01",
      type: "agent",
      parentId: engId,
      children: [],
      metadata: { description: "Deployment pipeline agent" },
    },
    [agentScanner]: {
      id: agentScanner,
      name: "agent-scanner-01",
      type: "agent",
      parentId: secId,
      children: [],
      metadata: { description: "Vulnerability scanner agent" },
    },
    [agentMonitor]: {
      id: agentMonitor,
      name: "agent-monitor-01",
      type: "agent",
      parentId: secId,
      children: [],
      metadata: { description: "Security monitoring agent" },
    },
    [agentSupport1]: {
      id: agentSupport1,
      name: "agent-support-01",
      type: "agent",
      parentId: csId,
      children: [],
      metadata: { description: "Tier-1 support agent" },
    },
    [agentSupport2]: {
      id: agentSupport2,
      name: "agent-support-02",
      type: "agent",
      parentId: csId,
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
  let current = hierarchy.nodes[nodeId];
  while (current) {
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
  const stack = [nodeId];
  while (stack.length > 0) {
    const id = stack.pop()!;
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
 * Returns all leaf enforcement node IDs under a given node.
 *
 * Endpoint nodes with no runtime children are also treated as leaves so a live
 * hierarchy still validates correctly before runtimes are attached.
 */
export function getLeafAgents(
  hierarchy: PolicyHierarchy,
  nodeId: string,
): string[] {
  return getDescendants(hierarchy, nodeId).filter(
    (id) => {
      const node = hierarchy.nodes[id];
      if (!node) return false;
      if (node.type === "agent" || node.type === "runtime") return true;
      return node.type === "endpoint" && node.children.length === 0;
    },
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
    if (childVal !== undefined) {
      // Child overrides at the guard level (shallow merge within the guard)
      (result as Record<string, unknown>)[key] = {
        ...((parent[key] as Record<string, unknown>) ?? {}),
        ...(childVal as Record<string, unknown>),
      };
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
// CRUD mutations (all pure — return a new hierarchy)
// ---------------------------------------------------------------------------

export function addNode(
  hierarchy: PolicyHierarchy,
  parentId: string,
  node: Omit<OrgNode, "id" | "children">,
): PolicyHierarchy {
  const parent = hierarchy.nodes[parentId];
  if (!parent) return hierarchy;

  const id = uid();
  const newNode: OrgNode = { ...node, id, children: [] };

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
  if (!newParent) return hierarchy;

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

  return {
    ...hierarchy,
    nodes: {
      ...hierarchy.nodes,
      [nodeId]: { ...node, name },
    },
  };
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
    const parsed = JSON.parse(raw) as PolicyHierarchy;
    if (!parsed.rootId || !parsed.nodes || !parsed.nodes[parsed.rootId]) {
      return null;
    }
    return parsed;
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
// Normalization
// ---------------------------------------------------------------------------

/**
 * Ensures a PolicyHierarchy has consistent parent↔child relationships.
 * Preserves the original explicit child ordering where possible, then
 * backfills any missing parent↔child links from parentId pointers so
 * loaded/pulled data is always structurally sound.
 */
export function normalizeHierarchy(hierarchy: PolicyHierarchy): PolicyHierarchy {
  const nodes = { ...hierarchy.nodes };

  // Reset children arrays
  for (const id of Object.keys(nodes)) {
    nodes[id] = { ...nodes[id], children: [] };
  }

  // Preserve explicit child ordering and recover missing parent links when
  // an existing children array is more authoritative than a missing parentId.
  for (const originalNode of Object.values(hierarchy.nodes)) {
    if (!nodes[originalNode.id]) {
      continue;
    }
    for (const childId of originalNode.children) {
      const child = nodes[childId];
      if (!child) {
        continue;
      }
      if (child.parentId == null || child.parentId === originalNode.id) {
        if (child.parentId !== originalNode.id) {
          nodes[childId] = { ...child, parentId: originalNode.id };
        }
        if (!nodes[originalNode.id].children.includes(childId)) {
          nodes[originalNode.id] = {
            ...nodes[originalNode.id],
            children: [...nodes[originalNode.id].children, childId],
          };
        }
      }
    }
  }

  // Rebuild any missing child links from parentId pointers without disturbing
  // the preserved explicit ordering above.
  for (const node of Object.values(nodes)) {
    if (node.parentId && nodes[node.parentId] && !nodes[node.parentId].children.includes(node.id)) {
      nodes[node.parentId] = {
        ...nodes[node.parentId],
        children: [...nodes[node.parentId].children, node.id],
      };
    }
  }

  return { nodes, rootId: hierarchy.rootId };
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
 * Validates all leaf enforcement nodes in the hierarchy, checking that their
 * effective policies have at least one guard enabled.
 */
export function validateAllLeaves(
  hierarchy: PolicyHierarchy,
  savedPolicies: SavedPolicy[],
): HierarchyValidationIssue[] {
  const issues: HierarchyValidationIssue[] = [];
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
          severity: "warning",
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

    // Check: enabled guards that are explicitly disabled
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
