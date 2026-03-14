/**
 * Org / Team / Endpoint / Runtime Policy Hierarchy Page
 *
 * Full-page visualization of policy inheritance across an organization tree.
 * Three-panel layout: tree (left), effective policy (center), merge preview (right).
 */

import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import {
  IconWorld,
  IconUsersGroup,
  IconRobot,
  IconServer,
  IconChevronRight,
  IconChevronDown,
  IconPlus,
  IconTrash,
  IconPencil,
  IconLink,
  IconLinkOff,
  IconRefresh,
  IconDownload,
  IconShieldCheck,
  IconAlertTriangle,
  IconCheck,
  IconX,
  IconArrowRight,
  IconLayersLinked,
  IconPlugConnected,
  IconCloudUpload,
  IconCloudDownload,
  IconLoader2,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import type { OrgNode, OrgNodeType, PolicyHierarchy, EffectivePolicy } from "@/lib/workbench/hierarchy-types";
import {
  createDefaultHierarchy,
  computeEffectivePolicy,
  addNode,
  removeNode,
  moveNode,
  assignPolicy,
  unassignPolicy,
  renameNode,
  saveHierarchy,
  loadHierarchy,
  clearHierarchy,
  getAncestryPath,
  getLeafAgents,
  getDescendants,
  validateAllLeaves,
  normalizeHierarchy,
  type HierarchyValidationIssue,
} from "@/lib/workbench/hierarchy-engine";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import {
  fetchScopedPolicies,
  fetchPolicyAssignments,
  fetchHierarchyTree,
  createHierarchyNode,
  updateHierarchyNode,
  deleteHierarchyNode,
} from "@/lib/workbench/fleet-client";
import type {
  HierarchyNode,
  HierarchyNodeInput,
  HierarchyTreeResponse,
} from "@/lib/workbench/fleet-client";


const NODE_TYPE_COLORS: Record<OrgNodeType, string> = {
  org: "#d4a84b",
  team: "#5b8def",
  agent: "#3dbf84",
  endpoint: "#6bc5a0",    // teal-green for machines
  runtime: "#3dbf84",     // bright green for AI agents
};

const NODE_TYPE_ICONS: Record<OrgNodeType, typeof IconWorld> = {
  org: IconWorld,
  team: IconUsersGroup,
  agent: IconRobot,
  endpoint: IconServer,    // server icon
  runtime: IconRobot,      // robot icon
};

const NODE_TYPE_LABELS: Record<OrgNodeType, string> = {
  org: "Organization",
  team: "Team",
  agent: "Agent",
  endpoint: "Endpoint",
  runtime: "Runtime Agent",
};


interface TreeNodeProps {
  node: OrgNode;
  hierarchy: PolicyHierarchy;
  selectedId: string | null;
  expandedIds: Set<string>;
  ancestryIds: Set<string>;
  depth: number;
  isSyncing: boolean;
  onSelect: (id: string) => void;
  onToggleExpand: (id: string) => void;
  onAddChild: (parentId: string, type: OrgNodeType) => void;
  onRemove: (id: string) => void;
  onRename: (id: string) => void;
  onDragStart: (id: string) => void;
  onDragOver: (id: string) => void;
  onDrop: (targetId: string) => void;
  dragOverId: string | null;
}

export async function resolvePendingHierarchyParentId(
  parentId: string | null,
  pendingCreateIds: ReadonlyMap<string, Promise<string | null>>,
): Promise<string | null> {
  if (!parentId) {
    return null;
  }

  const pendingParentId = pendingCreateIds.get(parentId);
  if (pendingParentId) {
    return await pendingParentId;
  }

  return parentId;
}

function TreeNode({
  node,
  hierarchy,
  selectedId,
  expandedIds,
  ancestryIds,
  depth,
  isSyncing,
  onSelect,
  onToggleExpand,
  onAddChild,
  onRemove,
  onRename,
  onDragStart,
  onDragOver,
  onDrop,
  dragOverId,
}: TreeNodeProps) {
  const childIds = [...new Set(node.children)];
  const isExpanded = expandedIds.has(node.id);
  const isSelected = selectedId === node.id;
  const isAncestor = ancestryIds.has(node.id);
  const hasChildren = childIds.length > 0;
  const Icon = NODE_TYPE_ICONS[node.type];
  const color = NODE_TYPE_COLORS[node.type];
  const isDragTarget = dragOverId === node.id;

  const [showActions, setShowActions] = useState(false);

  // Determine what child types can be added
  const canAddTeam = node.type === "org";
  const canAddAgent = node.type === "team";
  const canAddEndpoint = node.type === "team";
  const canAddRuntime = node.type === "endpoint";
  const canRemove = node.type !== "org"; // Can't remove root

  return (
    <div>
      {/* Node row */}
      <div
        className={cn(
          "group flex items-center gap-1.5 py-1.5 px-2 rounded-md cursor-pointer transition-all duration-100",
          "hover:bg-[#131721]/60",
          isSelected && "bg-[#131721] ring-1 ring-inset",
          isSelected && node.type === "org" && "ring-[#d4a84b]/30",
          isSelected && node.type === "team" && "ring-[#5b8def]/30",
          isSelected && node.type === "agent" && "ring-[#3dbf84]/30",
          isSelected && node.type === "endpoint" && "ring-[#6bc5a0]/30",
          isSelected && node.type === "runtime" && "ring-[#3dbf84]/30",
          isAncestor && !isSelected && "bg-[#131721]/30",
          isDragTarget && "ring-2 ring-[#d4a84b]/50 bg-[#d4a84b]/5",
        )}
        style={{ paddingLeft: `${depth * 20 + 8}px` }}
        onClick={() => onSelect(node.id)}
        onMouseEnter={() => setShowActions(true)}
        onMouseLeave={() => setShowActions(false)}
        draggable={node.type !== "org" && !isSyncing}
        onDragStart={(e) => {
          if (isSyncing) return;
          e.stopPropagation();
          onDragStart(node.id);
        }}
        onDragOver={(e) => {
          if (isSyncing) return;
          e.preventDefault();
          e.stopPropagation();
          onDragOver(node.id);
        }}
        onDrop={(e) => {
          if (isSyncing) return;
          e.preventDefault();
          e.stopPropagation();
          onDrop(node.id);
        }}
      >
        {/* Expand/collapse toggle */}
        {hasChildren ? (
          <button
            className="shrink-0 p-0.5 rounded hover:bg-[#2d3240]/50 text-[#6f7f9a]"
            onClick={(e) => {
              e.stopPropagation();
              onToggleExpand(node.id);
            }}
          >
            {isExpanded ? (
              <IconChevronDown size={12} stroke={1.5} />
            ) : (
              <IconChevronRight size={12} stroke={1.5} />
            )}
          </button>
        ) : (
          <span className="w-5 shrink-0" />
        )}

        {/* Type icon */}
        <Icon
          size={14}
          stroke={1.5}
          style={{ color }}
          className="shrink-0"
        />

        {/* Name */}
        <span
          className={cn(
            "text-[11.5px] font-medium truncate",
            isSelected ? "text-[#ece7dc]" : "text-[#ece7dc]/80",
          )}
        >
          {node.name}
        </span>

        {/* Policy badge */}
        {node.policyName && (
          <span className="ml-auto shrink-0 inline-flex items-center gap-1 px-1.5 py-0 text-[8px] font-mono bg-[#d4a84b]/10 text-[#d4a84b]/80 border border-[#d4a84b]/20 rounded">
            <IconLink size={8} stroke={1.5} />
            {node.policyName}
          </span>
        )}

        {/* Metadata count */}
        {node.metadata?.agentCount !== undefined &&
          node.type !== "runtime" &&
          node.type !== "agent" &&
          !node.policyName && (
          <span className="ml-auto shrink-0 text-[9px] font-mono text-[#6f7f9a]/60">
            {node.metadata.agentCount} leaf{node.metadata.agentCount !== 1 ? "s" : ""}
          </span>
        )}

        {/* Hover action buttons */}
        {showActions && !isSyncing && (
          <div className="flex items-center gap-0.5 ml-1 shrink-0">
            {canAddTeam && (
              <button
                className="p-0.5 rounded hover:bg-[#5b8def]/20 text-[#5b8def]/60 hover:text-[#5b8def]"
                title="Add team"
                onClick={(e) => {
                  e.stopPropagation();
                  onAddChild(node.id, "team");
                }}
              >
                <IconPlus size={11} stroke={2} />
              </button>
            )}
            {canAddEndpoint && (
              <button
                className="p-0.5 rounded hover:bg-[#6bc5a0]/20 text-[#6bc5a0]/60 hover:text-[#6bc5a0]"
                title="Add Endpoint"
                onClick={(e) => {
                  e.stopPropagation();
                  onAddChild(node.id, "endpoint");
                }}
              >
                <IconPlus size={11} stroke={2} />
              </button>
            )}
            {canAddAgent && (
              <button
                className="p-0.5 rounded hover:bg-[#3dbf84]/20 text-[#3dbf84]/60 hover:text-[#3dbf84]"
                title="Add Agent"
                onClick={(e) => {
                  e.stopPropagation();
                  onAddChild(node.id, "agent");
                }}
              >
                <IconPlus size={11} stroke={2} />
              </button>
            )}
            {canAddRuntime && (
              <button
                className="p-0.5 rounded hover:bg-[#3dbf84]/20 text-[#3dbf84]/60 hover:text-[#3dbf84]"
                title="Add Runtime"
                onClick={(e) => {
                  e.stopPropagation();
                  onAddChild(node.id, "runtime");
                }}
              >
                <IconPlus size={11} stroke={2} />
              </button>
            )}
            <button
              className="p-0.5 rounded hover:bg-[#6f7f9a]/20 text-[#6f7f9a]/60 hover:text-[#6f7f9a]"
              title="Rename"
              onClick={(e) => {
                e.stopPropagation();
                onRename(node.id);
              }}
            >
              <IconPencil size={11} stroke={1.5} />
            </button>
            {canRemove && (
              <button
                className="p-0.5 rounded hover:bg-[#c45c5c]/20 text-[#c45c5c]/60 hover:text-[#c45c5c]"
                title="Remove"
                onClick={(e) => {
                  e.stopPropagation();
                  onRemove(node.id);
                }}
              >
                <IconTrash size={11} stroke={1.5} />
              </button>
            )}
          </div>
        )}
      </div>

      {/* Children (with connector lines) */}
      {isExpanded && hasChildren && (
        <div className="relative">
          {/* Vertical connector line */}
          <div
            className="absolute top-0 bottom-0 border-l border-[#2d3240]/60"
            style={{ left: `${depth * 20 + 18}px` }}
          />
          {childIds.map((childId) => {
            const child = hierarchy.nodes[childId];
            if (!child) return null;
            return (
              <TreeNode
                key={childId}
                node={child}
                hierarchy={hierarchy}
                selectedId={selectedId}
                expandedIds={expandedIds}
                ancestryIds={ancestryIds}
                depth={depth + 1}
                isSyncing={isSyncing}
                onSelect={onSelect}
                onToggleExpand={onToggleExpand}
                onAddChild={onAddChild}
                onRemove={onRemove}
                onRename={onRename}
                onDragStart={onDragStart}
                onDragOver={onDragOver}
                onDrop={onDrop}
                dragOverId={dragOverId}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}


interface GuardProvenanceCardProps {
  guardId: string;
  guardName: string;
  entry: { value: unknown; inheritedFrom: string; overridden: boolean };
  selectedNodeName: string;
}

function GuardProvenanceCard({
  guardId,
  guardName,
  entry,
  selectedNodeName,
}: GuardProvenanceCardProps) {
  const val = entry.value as Record<string, unknown> | undefined;
  const isEnabled = val ? val.enabled !== false : false;
  const isFromSelf = entry.inheritedFrom === selectedNodeName;
  const meta = GUARD_REGISTRY.find((g) => g.id === guardId);

  // Determine provenance style
  let provenanceColor = "#6f7f9a"; // inherited
  let provenanceLabel = `Inherited from ${entry.inheritedFrom}`;
  let provenanceBg = "bg-[#6f7f9a]/10 border-[#6f7f9a]/20";

  if (entry.overridden) {
    provenanceColor = "#d4a84b";
    provenanceLabel = `Overridden at ${entry.inheritedFrom}`;
    provenanceBg = "bg-[#d4a84b]/10 border-[#d4a84b]/20";
  }

  if (isFromSelf && !entry.overridden) {
    provenanceColor = "#3dbf84";
    provenanceLabel = `Added at ${entry.inheritedFrom}`;
    provenanceBg = "bg-[#3dbf84]/10 border-[#3dbf84]/20";
  }

  return (
    <div className="flex items-start gap-3 p-2.5 rounded-md bg-[#131721]/50 border border-[#2d3240]/50">
      <div className="shrink-0 mt-0.5">
        <div
          className="w-2 h-2 rounded-full"
          style={{ backgroundColor: isEnabled ? provenanceColor : "#6f7f9a40" }}
        />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span
            className={cn(
              "text-[11px] font-medium",
              isEnabled ? "text-[#ece7dc]" : "text-[#6f7f9a]/60 line-through",
            )}
          >
            {guardName}
          </span>
          <span className="text-[8px] font-mono text-[#6f7f9a]/50">
            {guardId}
          </span>
        </div>
        <div className="mt-1 flex items-center gap-1.5">
          <span
            className={cn(
              "inline-flex items-center px-1.5 py-0 text-[8px] font-mono border rounded",
              provenanceBg,
            )}
            style={{ color: provenanceColor }}
          >
            {provenanceLabel}
          </span>
        </div>
        {/* Show key config values */}
        {val && isEnabled && (
          <div className="mt-1.5 flex flex-wrap gap-1">
            {Object.entries(val)
              .filter(([k]) => k !== "enabled")
              .slice(0, 3)
              .map(([k, v]) => (
                <span
                  key={k}
                  className="inline-flex items-center px-1 py-0 text-[8px] font-mono text-[#6f7f9a]/70 bg-[#2d3240]/30 rounded"
                >
                  {k}:{" "}
                  {Array.isArray(v)
                    ? `[${v.length}]`
                    : typeof v === "object" && v !== null
                      ? "{...}"
                      : String(v)}
                </span>
              ))}
          </div>
        )}
        {meta?.description && (
          <p className="mt-1 text-[9px] text-[#6f7f9a]/50 leading-relaxed line-clamp-1">
            {meta.description}
          </p>
        )}
      </div>
    </div>
  );
}


interface EffectivePolicyPanelProps {
  hierarchy: PolicyHierarchy;
  selectedId: string;
  effective: EffectivePolicy;
}

function EffectivePolicyPanel({
  hierarchy,
  selectedId,
  effective,
}: EffectivePolicyPanelProps) {
  const node = hierarchy.nodes[selectedId];
  if (!node) return null;

  const guardEntries = Object.entries(effective.guards);
  const settingEntries = Object.entries(effective.settings);
  const hasContent = guardEntries.length > 0 || settingEntries.length > 0;

  return (
    <div className="flex flex-col h-full">
      {/* Header with ancestry chain */}
      <div className="shrink-0 p-4 border-b border-[#2d3240]/50">
        <div className="flex items-center gap-2 mb-2">
          <IconLayersLinked size={14} stroke={1.5} className="text-[#6f7f9a]" />
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
            Effective Policy
          </span>
        </div>

        {/* Ancestry chain visualization */}
        <div className="flex items-center gap-1 flex-wrap">
          {effective.source.map((s, idx) => {
            const color = NODE_TYPE_COLORS[s.level];
            const hasPolicy = hierarchy.nodes[s.nodeId]?.policyId !== undefined;
            return (
              <span key={s.nodeId} className="flex items-center gap-1">
                {idx > 0 && (
                  <IconArrowRight size={8} stroke={1.5} className="text-[#6f7f9a]/40" />
                )}
                <span
                  className={cn(
                    "inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono border rounded",
                    hasPolicy
                      ? "border-opacity-30 bg-opacity-10"
                      : "border-[#2d3240]/30 bg-[#2d3240]/10 text-[#6f7f9a]/50",
                  )}
                  style={
                    hasPolicy
                      ? {
                          color,
                          borderColor: `${color}30`,
                          backgroundColor: `${color}10`,
                        }
                      : undefined
                  }
                >
                  {s.nodeName}
                  {hasPolicy && (
                    <IconLink size={7} stroke={1.5} className="ml-1 opacity-60" />
                  )}
                </span>
              </span>
            );
          })}
        </div>
      </div>

      {/* Guard cards */}
      <div className="flex-1 overflow-y-auto p-4">
        {hasContent ? (
          <div className="flex flex-col gap-4">
            {/* Guards */}
            {guardEntries.length > 0 && (
              <div>
                <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]/60 mb-2 block">
                  Guards ({guardEntries.length})
                </span>
                <div className="flex flex-col gap-1.5">
                  {guardEntries.map(([gid, entry]) => {
                    const meta = GUARD_REGISTRY.find((g) => g.id === gid);
                    return (
                      <GuardProvenanceCard
                        key={gid}
                        guardId={gid}
                        guardName={meta?.name ?? gid}
                        entry={entry}
                        selectedNodeName={node.name}
                      />
                    );
                  })}
                </div>
              </div>
            )}

            {/* Settings */}
            {settingEntries.length > 0 && (
              <div>
                <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]/60 mb-2 block">
                  Settings ({settingEntries.length})
                </span>
                <div className="flex flex-col gap-1.5">
                  {settingEntries.map(([key, entry]) => {
                    const isFromSelf = entry.inheritedFrom === node.name;
                    let provenanceColor = "#6f7f9a";
                    let provenanceBg = "bg-[#6f7f9a]/10 border-[#6f7f9a]/20";
                    if (entry.overridden) {
                      provenanceColor = "#d4a84b";
                      provenanceBg = "bg-[#d4a84b]/10 border-[#d4a84b]/20";
                    } else if (isFromSelf) {
                      provenanceColor = "#3dbf84";
                      provenanceBg = "bg-[#3dbf84]/10 border-[#3dbf84]/20";
                    }

                    return (
                      <div
                        key={key}
                        className="flex items-center gap-3 p-2 rounded-md bg-[#131721]/50 border border-[#2d3240]/50"
                      >
                        <span className="text-[10px] font-mono text-[#ece7dc]/80 min-w-[140px]">
                          {key}
                        </span>
                        <span className="text-[10px] font-mono text-[#d4a84b]">
                          {String(entry.value)}
                        </span>
                        <span
                          className={cn(
                            "ml-auto inline-flex items-center px-1.5 py-0 text-[8px] font-mono border rounded",
                            provenanceBg,
                          )}
                          style={{ color: provenanceColor }}
                        >
                          {entry.overridden
                            ? `overridden at ${entry.inheritedFrom}`
                            : isFromSelf
                              ? `set at ${entry.inheritedFrom}`
                              : `from ${entry.inheritedFrom}`}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-full text-center">
            <IconShieldCheck size={28} stroke={1} className="text-[#6f7f9a]/30 mb-3" />
            <p className="text-[11px] text-[#6f7f9a]/60 mb-1">
              No policy assigned in the inheritance chain
            </p>
            <p className="text-[9px] text-[#6f7f9a]/40">
              Assign a saved policy to this node or any ancestor to see the effective policy.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}


interface MergePreviewPanelProps {
  hierarchy: PolicyHierarchy;
  selectedId: string;
  savedPolicies: { id: string; policy: { name: string } }[];
}

function MergePreviewPanel({
  hierarchy,
  selectedId,
  savedPolicies,
}: MergePreviewPanelProps) {
  const node = hierarchy.nodes[selectedId];
  if (!node) return null;

  const leafTargets = getLeafAgents(hierarchy, selectedId);
  const directChildren = node.children.length;

  return (
    <div className="flex flex-col h-full">
      <div className="shrink-0 p-4 border-b border-[#2d3240]/50">
        <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
          Impact Preview
        </span>
      </div>

      <div className="flex-1 overflow-y-auto p-4">
        {/* Node info */}
        <div className="mb-4 p-3 rounded-md bg-[#131721]/50 border border-[#2d3240]/50">
          <div className="flex items-center gap-2 mb-2">
            {(() => {
              const NodeIcon = NODE_TYPE_ICONS[node.type];
              return (
                <NodeIcon
                  size={14}
                  stroke={1.5}
                  style={{ color: NODE_TYPE_COLORS[node.type] }}
                />
              );
            })()}
            <span className="text-[11px] font-medium text-[#ece7dc]">
              {node.name}
            </span>
            <span
              className="text-[8px] font-mono px-1.5 py-0 rounded border"
              style={{
                color: NODE_TYPE_COLORS[node.type],
                borderColor: `${NODE_TYPE_COLORS[node.type]}30`,
                backgroundColor: `${NODE_TYPE_COLORS[node.type]}10`,
              }}
            >
              {NODE_TYPE_LABELS[node.type]}
            </span>
          </div>

          {node.metadata?.description && (
            <p className="text-[9px] text-[#6f7f9a]/60 mb-2">
              {node.metadata.description}
            </p>
          )}

          <div className="flex gap-3 text-[9px] font-mono text-[#6f7f9a]/70">
            <span>{directChildren} direct children</span>
            <span>{leafTargets.length} leaf node{leafTargets.length !== 1 ? "s" : ""}</span>
          </div>
        </div>

        {/* Policy changes at this level affect these leaf nodes */}
        {leafTargets.length > 0 && (
          <div className="mb-4">
            <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]/60 mb-2 block">
              Affected Leaves
            </span>
            <div className="flex flex-col gap-1">
              {leafTargets.map((leafId) => {
                const leaf = hierarchy.nodes[leafId];
                if (!leaf) return null;
                const LeafIcon = NODE_TYPE_ICONS[leaf.type];
                return (
                  <div
                    key={leafId}
                    className="flex items-center gap-2 p-1.5 rounded bg-[#131721]/30"
                  >
                    <LeafIcon
                      size={11}
                      stroke={1.5}
                      style={{ color: `${NODE_TYPE_COLORS[leaf.type]}99` }}
                    />
                    <span className="text-[10px] font-mono text-[#ece7dc]/70">
                      {leaf.name}
                    </span>
                    {leaf.policyId && (
                      <span className="ml-auto text-[8px] font-mono text-[#d4a84b]/60">
                        has own policy
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Assign policy section */}
        <div>
          <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]/60 mb-2 block">
            Linked Policy
          </span>
          {node.policyId ? (
            <div className="flex items-center gap-2 p-2 rounded bg-[#d4a84b]/5 border border-[#d4a84b]/20">
              <IconLink size={11} stroke={1.5} className="text-[#d4a84b]" />
              <span className="text-[10px] font-medium text-[#d4a84b]">
                {node.policyName ?? "Unknown Policy"}
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-2 p-2 rounded bg-[#2d3240]/20 border border-[#2d3240]/30">
              <IconLinkOff size={11} stroke={1.5} className="text-[#6f7f9a]/40" />
              <span className="text-[10px] text-[#6f7f9a]/50">
                No policy assigned
              </span>
            </div>
          )}

          {savedPolicies.length > 0 && (
            <div className="mt-2 text-[9px] text-[#6f7f9a]/50">
              {savedPolicies.length} saved polic{savedPolicies.length === 1 ? "y" : "ies"} available
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


interface ValidationModalProps {
  issues: HierarchyValidationIssue[];
  onClose: () => void;
  onSelectNode: (nodeId: string) => void;
}

function ValidationModal({ issues, onClose, onSelectNode }: ValidationModalProps) {
  const errors = issues.filter((i) => i.severity === "error");
  const warnings = issues.filter((i) => i.severity === "warning");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="w-[480px] max-h-[60vh] bg-[#0b0d13] border border-[#2d3240] rounded-lg overflow-hidden flex flex-col">
        <div className="flex items-center justify-between p-4 border-b border-[#2d3240]">
          <div className="flex items-center gap-2">
            <IconShieldCheck size={16} stroke={1.5} className="text-[#d4a84b]" />
            <span className="text-[12px] font-medium text-[#ece7dc]">
              Hierarchy Validation
            </span>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-[#2d3240] text-[#6f7f9a] hover:text-[#ece7dc]"
          >
            <IconX size={14} stroke={1.5} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4">
          {issues.length === 0 ? (
            <div className="flex flex-col items-center py-8">
              <IconCheck size={24} stroke={1.5} className="text-[#3dbf84] mb-2" />
              <span className="text-[11px] text-[#3dbf84]">
                All leaf nodes have valid effective policies
              </span>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              {errors.length > 0 && (
                <span className="text-[9px] font-mono uppercase text-[#c45c5c]/70">
                  {errors.length} error{errors.length !== 1 ? "s" : ""}
                </span>
              )}
              {warnings.length > 0 && (
                <span className="text-[9px] font-mono uppercase text-[#d4a84b]/70">
                  {warnings.length} warning{warnings.length !== 1 ? "s" : ""}
                </span>
              )}
              {issues.map((issue, idx) => (
                <button
                  key={`${issue.nodeId}-${issue.severity}-${idx}`}
                  className="flex items-start gap-2 p-2.5 rounded bg-[#131721]/50 border border-[#2d3240]/50 text-left hover:bg-[#131721] transition-colors"
                  onClick={() => {
                    onSelectNode(issue.nodeId);
                    onClose();
                  }}
                >
                  <IconAlertTriangle
                    size={12}
                    stroke={1.5}
                    className={cn(
                      "shrink-0 mt-0.5",
                      issue.severity === "error" ? "text-[#c45c5c]" : "text-[#d4a84b]",
                    )}
                  />
                  <div>
                    <span className="text-[10px] font-medium text-[#ece7dc]">
                      {issue.nodeName}
                    </span>
                    <p className="text-[9px] text-[#6f7f9a]/70 mt-0.5">
                      {issue.message}
                    </p>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


interface PolicyAssignDialogProps {
  node: OrgNode;
  savedPolicies: { id: string; policy: { name: string } }[];
  onAssign: (policyId: string, policyName: string) => void;
  onUnassign: () => void;
  onClose: () => void;
}

function PolicyAssignDialog({
  node,
  savedPolicies,
  onAssign,
  onUnassign,
  onClose,
}: PolicyAssignDialogProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="w-[380px] max-h-[50vh] bg-[#0b0d13] border border-[#2d3240] rounded-lg overflow-hidden flex flex-col">
        <div className="flex items-center justify-between p-4 border-b border-[#2d3240]">
          <div className="flex items-center gap-2">
            <IconLink size={14} stroke={1.5} className="text-[#d4a84b]" />
            <span className="text-[11px] font-medium text-[#ece7dc]">
              Assign Policy to {node.name}
            </span>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-[#2d3240] text-[#6f7f9a] hover:text-[#ece7dc]"
          >
            <IconX size={14} stroke={1.5} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-3">
          {savedPolicies.length === 0 ? (
            <div className="py-6 text-center">
              <p className="text-[10px] text-[#6f7f9a]/60">
                No saved policies available.
              </p>
              <p className="text-[9px] text-[#6f7f9a]/40 mt-1">
                Save a policy from the Editor to assign it here.
              </p>
            </div>
          ) : (
            <div className="flex flex-col gap-1">
              {savedPolicies.map((sp) => {
                const isActive = node.policyId === sp.id;
                return (
                  <button
                    key={sp.id}
                    className={cn(
                      "flex items-center gap-2 p-2 rounded text-left transition-colors",
                      isActive
                        ? "bg-[#d4a84b]/10 border border-[#d4a84b]/30"
                        : "hover:bg-[#131721] border border-transparent",
                    )}
                    onClick={() => {
                      if (isActive) {
                        onUnassign();
                      } else {
                        onAssign(sp.id, sp.policy.name);
                      }
                    }}
                  >
                    {isActive ? (
                      <IconCheck size={12} stroke={2} className="text-[#d4a84b] shrink-0" />
                    ) : (
                      <div className="w-3 shrink-0" />
                    )}
                    <span
                      className={cn(
                        "text-[10px] font-medium",
                        isActive ? "text-[#d4a84b]" : "text-[#ece7dc]/80",
                      )}
                    >
                      {sp.policy.name}
                    </span>
                    <span className="ml-auto text-[8px] font-mono text-[#6f7f9a]/40">
                      {sp.id.slice(0, 8)}
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {node.type === "runtime" && (
          <div className="shrink-0 px-3 py-2 border-t border-[#2d3240]/50">
            <p className="text-[9px] text-[#6f7f9a]/60 leading-relaxed">
              This policy will be applied as an override layer on top of the endpoint's inherited policy.
            </p>
          </div>
        )}

        {node.policyId && (
          <div className="shrink-0 p-3 border-t border-[#2d3240]">
            <button
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-medium text-[#c45c5c] hover:bg-[#c45c5c]/10 transition-colors"
              onClick={onUnassign}
            >
              <IconLinkOff size={12} stroke={1.5} />
              Remove assignment
            </button>
          </div>
        )}
      </div>
    </div>
  );
}


interface RenameDialogProps {
  node: OrgNode;
  onRename: (name: string) => void;
  onClose: () => void;
}

type HierarchySyncResult = {
  success: boolean;
  error?: string;
  id?: string;
};

function RenameDialog({ node, onRename, onClose }: RenameDialogProps) {
  const [name, setName] = useState(node.name);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.select();
  }, []);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="w-[320px] bg-[#0b0d13] border border-[#2d3240] rounded-lg overflow-hidden">
        <div className="p-4 border-b border-[#2d3240]">
          <span className="text-[11px] font-medium text-[#ece7dc]">
            Rename {NODE_TYPE_LABELS[node.type]}
          </span>
        </div>
        <form
          className="p-4 flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (name.trim()) {
              onRename(name.trim());
            }
          }}
        >
          <input
            ref={inputRef}
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full px-3 py-2 text-[11px] font-mono bg-[#131721] border border-[#2d3240] rounded text-[#ece7dc] placeholder-[#6f7f9a]/40 focus:outline-none focus:border-[#d4a84b]/50"
            placeholder="Enter name..."
            autoFocus
          />
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 text-[10px] font-medium text-[#6f7f9a] hover:text-[#ece7dc] rounded hover:bg-[#2d3240]/50 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!name.trim()}
              className="px-3 py-1.5 text-[10px] font-medium text-[#0b0d13] bg-[#d4a84b] rounded hover:bg-[#d4a84b]/80 transition-colors disabled:opacity-40"
            >
              Rename
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}


export function HierarchyPage() {
  const { state } = useWorkbench();
  const savedPolicies = state.savedPolicies;
  const { connection, getAuthenticatedConnection } = useFleetConnection();
  const fleetConnected = connection.connected;


  const [hierarchy, setHierarchy] = useState<PolicyHierarchy>(() => {
    const loaded = loadHierarchy();
    return loaded ? normalizeHierarchy(loaded) : createDefaultHierarchy();
  });

  // Version counter to prevent stale optimistic rollbacks on concurrent mutations
  const [, setHierarchyVersion] = useState(0);
  const hierarchyVersionRef = useRef(0);
  const hierarchyRef = useRef(hierarchy);

  const [selectedId, setSelectedId] = useState<string | null>(hierarchy.rootId);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(() => {
    // Expand root and all team nodes by default
    const ids = new Set<string>();
    ids.add(hierarchy.rootId);
    for (const node of Object.values(hierarchy.nodes)) {
      if (node.type === "org" || node.type === "team" || node.type === "endpoint") {
        ids.add(node.id);
      }
    }
    return ids;
  });

  // Dialog states
  const [renameTarget, setRenameTarget] = useState<string | null>(null);
  const [assignTarget, setAssignTarget] = useState<string | null>(null);
  const [validationIssues, setValidationIssues] = useState<HierarchyValidationIssue[] | null>(null);

  // Drag state
  const [dragSourceId, setDragSourceId] = useState<string | null>(null);
  const [dragOverId, setDragOverId] = useState<string | null>(null);

  useEffect(() => {
    hierarchyRef.current = hierarchy;
  }, [hierarchy]);

  const applyHierarchyChange = useCallback((next: PolicyHierarchy) => {
    const nextVersion = hierarchyVersionRef.current + 1;
    hierarchyRef.current = next;
    hierarchyVersionRef.current = nextVersion;
    setHierarchy(next);
    setHierarchyVersion(nextVersion);
  }, []);


  const [isLiveMode, setIsLiveMode] = useState(false);
  const [hasPulledFleetHierarchy, setHasPulledFleetHierarchy] = useState(false);
  const [syncStatus, setSyncStatus] = useState<{
    type: "idle" | "pushing" | "pulling" | "success" | "error";
    message?: string;
  }>({ type: "idle" });
  const syncStatusTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const syncInProgressRef = useRef(false);
  const pendingCreateIdsRef = useRef(new Map<string, Promise<string | null>>());

  /** Show a transient sync status message that auto-clears after a delay. */
  const showSyncStatus = useCallback(
    (type: "success" | "error", message: string) => {
      if (syncStatusTimerRef.current) clearTimeout(syncStatusTimerRef.current);
      setSyncStatus({ type, message });
      syncStatusTimerRef.current = setTimeout(() => {
        setSyncStatus({ type: "idle" });
        syncStatusTimerRef.current = null;
      }, 4000);
    },
    [],
  );

  const clearPendingCreateIds = useCallback(() => {
    pendingCreateIdsRef.current.clear();
  }, []);

  // Clear sync status timer on unmount
  useEffect(() => {
    return () => {
      if (syncStatusTimerRef.current) clearTimeout(syncStatusTimerRef.current);
      clearPendingCreateIds();
    };
  }, [clearPendingCreateIds]);

  // Turn off live mode if fleet disconnects
  useEffect(() => {
    if (!fleetConnected && isLiveMode) {
      setIsLiveMode(false);
      setHasPulledFleetHierarchy(false);
      showSyncStatus("error", "Fleet disconnected — switched to DEMO mode");
    }
  }, [fleetConnected, isLiveMode, showSyncStatus]);

  // Persist on change
  useEffect(() => {
    saveHierarchy(hierarchy);
  }, [hierarchy]);


  const selectedNode = selectedId ? hierarchy.nodes[selectedId] : null;

  const ancestryIds = useMemo(() => {
    if (!selectedId) return new Set<string>();
    const path = getAncestryPath(hierarchy, selectedId);
    return new Set(path.map((n) => n.id));
  }, [hierarchy, selectedId]);

  const effective = useMemo(() => {
    if (!selectedId) return null;
    return computeEffectivePolicy(hierarchy, selectedId, savedPolicies);
  }, [hierarchy, selectedId, savedPolicies]);


  const handleSelect = useCallback((id: string) => {
    setSelectedId(id);
  }, []);

  const handleToggleExpand = useCallback((id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  /**
   * Fire-and-forget sync helper: runs a backend call without blocking
   * the local UI. On failure, rolls back to the previous hierarchy state.
   */
  const syncToBackend = useCallback(
    (
      label: string,
      fn: () => Promise<HierarchySyncResult>,
      prevHierarchy: PolicyHierarchy,
    ) => {
      if (!isLiveMode || !fleetConnected) return;
      const capturedVersion = hierarchyVersionRef.current;
      return fn().then((result): HierarchySyncResult => {
        if (!result.success) {
          console.warn(`[hierarchy-sync] ${label} failed:`, result.error);
          const reverted = hierarchyVersionRef.current === capturedVersion;
          if (reverted) {
            applyHierarchyChange(prevHierarchy);
          }
          showSyncStatus(
            "error",
            reverted
              ? `Sync: ${label} failed — reverted`
              : `Sync: ${label} failed — newer local changes were kept`,
          );
        }
        return result;
      }).catch((err): HierarchySyncResult => {
        console.warn(`[hierarchy-sync] ${label} error:`, err);
        const reverted = hierarchyVersionRef.current === capturedVersion;
        if (reverted) {
          applyHierarchyChange(prevHierarchy);
        }
        showSyncStatus(
          "error",
          reverted
            ? `Sync: ${label} error — reverted`
            : `Sync: ${label} error — newer local changes were kept`,
        );
        return { success: false, error: String(err) };
      });
    },
    [isLiveMode, fleetConnected, applyHierarchyChange, showSyncStatus],
  );

  /**
   * Remap a node's ID in the hierarchy after the server assigns a different ID.
   * Updates: the nodes map key, node.id, parent's children array, and children's parentId.
   */
  const remapNodeId = useCallback(
    (h: PolicyHierarchy, oldId: string, newId: string): PolicyHierarchy => {
      if (oldId === newId || !h.nodes[oldId]) return h;
      const nodes = { ...h.nodes };
      const node = { ...nodes[oldId], id: newId };
      delete nodes[oldId];
      nodes[newId] = node;

      // Update parent's children array
      if (node.parentId && nodes[node.parentId]) {
        const parent = { ...nodes[node.parentId] };
        parent.children = parent.children.map((cid) => (cid === oldId ? newId : cid));
        nodes[node.parentId] = parent;
      }

      // Update children's parentId
      for (const childId of node.children) {
        if (nodes[childId]) {
          nodes[childId] = { ...nodes[childId], parentId: newId };
        }
      }

      return {
        ...h,
        nodes,
        rootId: h.rootId === oldId ? newId : h.rootId,
      };
    },
    [],
  );

  const handleAddChild = useCallback(
    (parentId: string, type: OrgNodeType) => {
      const defaultNames: Record<OrgNodeType, string> = {
        org: "New Org",
        team: "New Team",
        agent: `agent-new-${String(Date.now()).slice(-4)}`,
        endpoint: `endpoint-${String(Date.now()).slice(-4)}`,
        runtime: `runtime-${String(Date.now()).slice(-4)}`,
      };

      const prevHierarchy = hierarchy;
      const updated = addNode(hierarchy, parentId, {
        name: defaultNames[type],
        type,
        parentId,
        metadata: {
          description: "",
        },
      });

      applyHierarchyChange(updated);

      // Expand parent
      setExpandedIds((prev) => {
        const next = new Set(prev);
        next.add(parentId);
        return next;
      });

      // Find the new node and select it
      const parent = updated.nodes[parentId];
      if (parent) {
        const newId = parent.children[parent.children.length - 1];
        setSelectedId(newId);
        // Trigger rename immediately
        setRenameTarget(newId);

        // LIVE mode: create node on backend and remap local ID to server ID
        const newNode = updated.nodes[newId];
        if (newNode) {
          const localId = newId;
          let resolveCreatedId!: (value: string | null) => void;
          const pendingCreatedId = new Promise<string | null>((resolve) => {
            resolveCreatedId = resolve;
          });
          pendingCreateIdsRef.current.set(localId, pendingCreatedId);

          const resultPromise = syncToBackend(
            "create node",
            async (): Promise<HierarchySyncResult> => {
              const parentId = await resolvePendingHierarchyParentId(
                newNode.parentId,
                pendingCreateIdsRef.current,
              );
              if (newNode.parentId && !parentId) {
                const parentName = updated.nodes[newNode.parentId]?.name ?? newNode.parentId;
                return {
                  success: false,
                  error: `Parent node "${parentName}" is missing a fleet id`,
                };
              }

              return createHierarchyNode(getAuthenticatedConnection(), {
                name: newNode.name,
                node_type: newNode.type,
                external_id: newNode.externalId ?? null,
                parent_id: parentId,
                metadata: newNode.metadata,
              });
            },
            prevHierarchy,
          );
          if (!resultPromise) {
            resolveCreatedId(null);
            pendingCreateIdsRef.current.delete(localId);
          } else {
            resultPromise
              .then((result) => {
                resolveCreatedId(result.success && result.id ? result.id : null);
                if (result.success && result.id && result.id !== localId) {
                  const serverId = result.id;
                  const remapped = remapNodeId(hierarchyRef.current, localId, serverId);
                  applyHierarchyChange(remapped);
                  setSelectedId((prev) => (prev === localId ? serverId : prev));
                  setRenameTarget((prev) => (prev === localId ? serverId : prev));
                  setExpandedIds((prev) => {
                    if (!prev.has(localId)) {
                      return prev;
                    }
                    const next = new Set(prev);
                    next.delete(localId);
                    next.add(serverId);
                    return next;
                  });
                }
              })
              .catch(() => {
                resolveCreatedId(null);
              })
              .finally(() => {
                pendingCreateIdsRef.current.delete(localId);
              });
          }
        }
      }
    },
    [hierarchy, syncToBackend, connection, remapNodeId, applyHierarchyChange],
  );

  const handleRemove = useCallback(
    (id: string) => {
      const node = hierarchy.nodes[id];
      if (!node) return;

      // getDescendants is inclusive of the node itself, so subtract 1 for descendants-only count
      const descendantCount = getDescendants(hierarchy, id).length - 1;

      const message = descendantCount > 0
        ? `Delete node "${node.name}" and all ${descendantCount} descendant(s)? This cannot be undone.`
        : `Delete node "${node.name}"? This cannot be undone.`;

      if (!window.confirm(message)) return;

      const prevHierarchy = hierarchy;
      const updated = removeNode(hierarchy, id);
      applyHierarchyChange(updated);
      if (selectedId === id) {
        setSelectedId(node.parentId);
      }

      // LIVE mode: delete node on backend (no reparent — descendants removed locally)
      syncToBackend("delete node", () =>
        deleteHierarchyNode(getAuthenticatedConnection(), id, false),
        prevHierarchy,
      );
    },
    [hierarchy, selectedId, syncToBackend, connection, applyHierarchyChange],
  );

  const handleRename = useCallback((id: string) => {
    setRenameTarget(id);
  }, []);

  const handleDoRename = useCallback(
    (name: string) => {
      if (renameTarget) {
        const prevHierarchy = hierarchyRef.current;
        const updated = renameNode(prevHierarchy, renameTarget, name);
        applyHierarchyChange(updated);
        setRenameTarget(null);

        // LIVE mode: update name on backend
        syncToBackend("rename node", () =>
          updateHierarchyNode(getAuthenticatedConnection(), renameTarget, { name }),
          prevHierarchy,
        );
      }
    },
    [renameTarget, syncToBackend, connection, applyHierarchyChange],
  );

  const handleAssign = useCallback(
    (policyId: string, policyName: string) => {
      if (assignTarget) {
        const prevHierarchy = hierarchyRef.current;
        const updated = assignPolicy(
          prevHierarchy,
          assignTarget,
          policyId,
          policyName,
        );
        applyHierarchyChange(updated);
        setAssignTarget(null);

        // LIVE mode: update policy assignment on backend
        syncToBackend("assign policy", () =>
          updateHierarchyNode(getAuthenticatedConnection(), assignTarget, {
            policy_id: policyId,
            policy_name: policyName,
          }),
          prevHierarchy,
        );
      }
    },
    [assignTarget, syncToBackend, connection, applyHierarchyChange],
  );

  const handleUnassign = useCallback(() => {
    if (assignTarget) {
      const prevHierarchy = hierarchyRef.current;
      const updated = unassignPolicy(prevHierarchy, assignTarget);
      applyHierarchyChange(updated);
      setAssignTarget(null);

      // LIVE mode: clear policy assignment on backend
      syncToBackend("unassign policy", () =>
        updateHierarchyNode(getAuthenticatedConnection(), assignTarget, {
          policy_id: null,
          policy_name: null,
        }),
        prevHierarchy,
      );
    }
  }, [assignTarget, syncToBackend, connection, applyHierarchyChange]);

  const handleDragStart = useCallback((id: string) => {
    setDragSourceId(id);
  }, []);

  const handleDragOver = useCallback((id: string) => {
    setDragOverId(id);
  }, []);

  const handleDrop = useCallback(
    (targetId: string) => {
      if (dragSourceId && dragSourceId !== targetId) {
        const currentHierarchy = hierarchyRef.current;
        const sourceNode = currentHierarchy.nodes[dragSourceId];
        const targetNode = currentHierarchy.nodes[targetId];
        if (sourceNode && targetNode) {
          // Preserve legacy agent leaf moves while enforcing the new endpoint/runtime hierarchy.
          const canDrop =
            (sourceNode.type === "runtime" && targetNode.type === "endpoint") ||
            (sourceNode.type === "agent" && targetNode.type === "team") ||
            (sourceNode.type === "endpoint" && targetNode.type === "team") ||
            (sourceNode.type === "team" && targetNode.type === "org");
          if (canDrop) {
            const prevHierarchy = currentHierarchy;
            const updated = moveNode(currentHierarchy, dragSourceId, targetId);
            applyHierarchyChange(updated);

            // LIVE mode: update parent_id on backend
            const movedId = dragSourceId;
            syncToBackend("move node", async (): Promise<HierarchySyncResult> => {
              const [resolvedMovedId, resolvedTargetId] = await Promise.all([
                resolvePendingHierarchyParentId(movedId, pendingCreateIdsRef.current),
                resolvePendingHierarchyParentId(targetId, pendingCreateIdsRef.current),
              ]);
              if (!resolvedMovedId) {
                return {
                  success: false,
                  error: `Node "${sourceNode.name}" is missing a fleet id`,
                };
              }
              if (!resolvedTargetId) {
                return {
                  success: false,
                  error: `Parent node "${targetNode.name}" is missing a fleet id`,
                };
              }
              return updateHierarchyNode(getAuthenticatedConnection(), resolvedMovedId, {
                parent_id: resolvedTargetId,
              });
            },
              prevHierarchy,
            );
          }
        }
      }
      setDragSourceId(null);
      setDragOverId(null);
    },
    [dragSourceId, syncToBackend, connection, applyHierarchyChange],
  );

  const handleResetToDemo = useCallback(() => {
    if (!window.confirm("Reset hierarchy to demo data? All current changes will be lost.")) return;
    clearPendingCreateIds();
    clearHierarchy();
    const demo = createDefaultHierarchy();
    applyHierarchyChange(demo);
    setHasPulledFleetHierarchy(false);
    setSelectedId(demo.rootId);
    setExpandedIds(() => {
      const ids = new Set<string>();
      for (const node of Object.values(demo.nodes)) {
        if (node.type === "org" || node.type === "team" || node.type === "endpoint") {
          ids.add(node.id);
        }
      }
      return ids;
    });
  }, [applyHierarchyChange, clearPendingCreateIds]);

  const handleExport = useCallback(() => {
    const json = JSON.stringify(hierarchy, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "policy-hierarchy.json";
    a.click();
    URL.revokeObjectURL(url);
  }, [hierarchy]);

  const handleValidateAll = useCallback(() => {
    const issues = validateAllLeaves(hierarchy, savedPolicies);
    setValidationIssues(issues);
  }, [hierarchy, savedPolicies]);


  const handleToggleLiveMode = useCallback(() => {
    if (!fleetConnected) return;
    setHasPulledFleetHierarchy(false);
    setIsLiveMode((prev) => !prev);
  }, [fleetConnected]);

  /**
   * Push local hierarchy to the fleet via the hierarchy CRUD API.
   * Walks the tree breadth-first (parents first) so that parent nodes exist
   * on the backend before their children are created.
   */
  const handlePushToFleet = useCallback(async () => {
    if (!fleetConnected) return;
    if (syncInProgressRef.current) {
      console.warn("[hierarchy-sync] push skipped: another sync operation is in progress");
      showSyncStatus("error", "Another sync operation is already in progress");
      return;
    }

    const hierarchySnapshot = hierarchyRef.current;

    // Issue #5: Validate before push and require confirmation for any leaf warnings/errors
    const issues = validateAllLeaves(hierarchySnapshot, savedPolicies);
    if (issues.length > 0) {
      const errorCount = issues.filter((i) => i.severity === "error").length;
      const warningCount = issues.length - errorCount;
      const message =
        errorCount > 0 && warningCount > 0
          ? `There are ${issues.length} validation issue(s) in the hierarchy (${errorCount} error(s), ${warningCount} warning(s)). Push anyway?`
          : `There are ${issues.length} validation ${errorCount > 0 ? "error" : "warning"}(s) in the hierarchy. Push anyway?`;
      const proceed = window.confirm(
        message,
      );
      if (!proceed) return;
    }

    syncInProgressRef.current = true;
    setSyncStatus({ type: "pushing", message: "Uploading hierarchy..." });

    try {
      // BFS traversal: create parents before children.
      // Build an idMap (localId -> serverId) so that child nodes reference
      // their parent's server-assigned ID rather than the local UUID.
      const queue: string[] = [hierarchySnapshot.rootId];
      const idMap = new Map<string, string>(); // localId -> serverId
      let successCount = 0;
      let errorCount = 0;

      let firstMissingParentIdNodeName: string | null = null;
      let missingParentIdNodeCount = 0;
      let missingParentSkippedNodeCount = 0;

      while (queue.length > 0) {
        const nodeId = queue.shift()!;
        const node = hierarchySnapshot.nodes[nodeId];
        if (!node) continue;

        // Resolve parent_id: if the parent was already created, use its
        // server-assigned ID. For the root node (parentId === null) this
        // is a no-op.
        const resolvedParentId = node.parentId
          ? idMap.get(node.parentId) ?? node.parentId
          : null;

        const input: HierarchyNodeInput = {
          name: node.name,
          node_type: node.type,
          external_id: node.externalId ?? null,
          parent_id: resolvedParentId,
          policy_id: node.policyId ?? null,
          policy_name: node.policyName ?? null,
          metadata: node.metadata,
        };

        const result = await createHierarchyNode(getAuthenticatedConnection(), input);
        if (!result.success) {
          console.warn(
            `[hierarchy-sync] push failed for node "${node.name}":`,
            result.error,
          );
          errorCount++;
          // Skip children — parent failed so they would reference an invalid ID
          continue;
        }

        successCount++;

        if (result.id) {
          idMap.set(nodeId, result.id);
        } else if (node.children.length > 0) {
          firstMissingParentIdNodeName ??= node.name;
          missingParentIdNodeCount++;
          missingParentSkippedNodeCount += Math.max(
            0,
            getDescendants(hierarchySnapshot, node.id).length - 1,
          );
          console.warn(
            `[hierarchy-sync] push incomplete for node "${node.name}": backend created the node without returning an id, so its descendants cannot be uploaded`,
          );
          continue;
        }

        // Enqueue children
        for (const childId of node.children) {
          queue.push(childId);
        }
      }

      const remappedHierarchy = Array.from(idMap.entries()).reduce(
        (currentHierarchy, [localId, serverId]) =>
          remapNodeId(currentHierarchy, localId, serverId),
        hierarchyRef.current,
      );

      if (remappedHierarchy !== hierarchyRef.current) {
        applyHierarchyChange(remappedHierarchy);
        setSelectedId((prev) => (prev ? idMap.get(prev) ?? prev : prev));
        setRenameTarget((prev) => (prev ? idMap.get(prev) ?? prev : prev));
        setExpandedIds((prev) => {
          let changed = false;
          const next = new Set<string>();
          for (const id of prev) {
            const mappedId = idMap.get(id) ?? id;
            if (mappedId !== id) {
              changed = true;
            }
            next.add(mappedId);
          }
          return changed ? next : prev;
        });
      }

      if (missingParentIdNodeCount > 0) {
        showSyncStatus(
          "error",
          missingParentIdNodeCount === 1
            ? `Push incomplete: "${firstMissingParentIdNodeName}" was created without an id, so ${missingParentSkippedNodeCount} descendant node${missingParentSkippedNodeCount === 1 ? "" : "s"} could not be uploaded`
            : `Push incomplete: ${missingParentIdNodeCount} nodes were created without ids, so ${missingParentSkippedNodeCount} descendant nodes could not be uploaded`,
        );
      } else if (errorCount === 0) {
        showSyncStatus("success", `Pushed ${successCount} nodes to fleet`);
      } else {
        showSyncStatus(
          "error",
          `Pushed ${successCount} nodes, ${errorCount} failed`,
        );
      }
    } catch (err) {
      showSyncStatus(
        "error",
        `Push failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    } finally {
      syncInProgressRef.current = false;
    }
  }, [fleetConnected, connection, showSyncStatus, savedPolicies, remapNodeId, applyHierarchyChange]);

  /**
   * Map a backend node_type string to the frontend OrgNodeType.
   * The backend supports "project" which the frontend does not yet have,
   * so we map it to "team" as the closest equivalent.
   */
  const mapNodeType = useCallback((backendType: string): OrgNodeType => {
    if (
      backendType === "org" ||
      backendType === "team" ||
      backendType === "agent" ||
      backendType === "endpoint" ||
      backendType === "runtime"
    ) {
      return backendType;
    }
    return "team"; // "project" and unknown
  }, []);

  /**
   * Recursively flatten a hierarchy tree node (with nested children) into
   * the local OrgNode flat map format.
   */
  const flattenTreeNode = useCallback(
    (
      hNode: HierarchyNode,
      parentId: string | null,
      nodesOut: Record<string, OrgNode>,
    ) => {
      const nodeType = mapNodeType(hNode.node_type);
      const nestedChildren = (hNode.children ?? []).filter(
        (child): child is HierarchyNode => typeof child === "object" && child !== null,
      );
      const childIds = [...new Set(nestedChildren.map((child) => child.id))];

      nodesOut[hNode.id] = {
        id: hNode.id,
        name: hNode.name,
        type: nodeType,
        parentId,
        externalId: hNode.external_id ?? undefined,
        policyId: hNode.policy_id ?? undefined,
        policyName: hNode.policy_name ?? undefined,
        children: childIds,
        metadata: (hNode.metadata as OrgNode["metadata"]) ?? {},
      };

      for (const child of nestedChildren) {
        flattenTreeNode(child, hNode.id, nodesOut);
      }
    },
    [mapNodeType],
  );

  /**
   * Pull hierarchy from the fleet via the hierarchy tree endpoint.
   * Falls back to the older scoped-policies endpoint only when the tree
   * endpoint is unavailable. An empty tree is a valid live response.
   */
  const handlePullFromFleet = useCallback(async () => {
    if (!fleetConnected) return;
    if (syncInProgressRef.current) {
      console.warn("[hierarchy-sync] pull skipped: another sync operation is in progress");
      showSyncStatus("error", "Another sync operation is already in progress");
      return;
    }
    if (!window.confirm("Replace local hierarchy with fleet data? Unsaved local changes will be lost.")) return;
    syncInProgressRef.current = true;
    setSyncStatus({ type: "pulling", message: "Downloading hierarchy..." });

    try {
      // Try the new hierarchy tree endpoint first
      const tree: HierarchyTreeResponse | null = await fetchHierarchyTree(getAuthenticatedConnection());

      if (tree) {
        if (tree.nodes.length === 0) {
          setHasPulledFleetHierarchy(false);
          showSyncStatus("success", "Fleet hierarchy is empty — keeping local draft");
          return;
        }

        // Flatten the tree response into local OrgNode format.
        // The tree endpoint returns nodes with nested children arrays.
        const nodes: Record<string, OrgNode> = {};

        // Find the root node in the array
        const rootNode = tree.nodes.find((n) => n.id === tree.root_id);
        const rootHasNestedChildren = Array.isArray(rootNode?.children)
          && rootNode.children.some((child) => typeof child === "object" && child !== null);

        if (rootNode && rootHasNestedChildren) {
          // If the root has nested children, flatten recursively
          flattenTreeNode(rootNode, null, nodes);
        } else {
          // Fallback: the tree response may be a flat list with child ids.
          for (const hNode of tree.nodes) {
            const nodeType = mapNodeType(hNode.node_type);
            nodes[hNode.id] = {
              id: hNode.id,
              name: hNode.name,
              type: nodeType,
              parentId: hNode.parent_id ?? null,
              externalId: hNode.external_id ?? undefined,
              policyId: hNode.policy_id ?? undefined,
              policyName: hNode.policy_name ?? undefined,
              children: [],
              metadata: (hNode.metadata as OrgNode["metadata"]) ?? {},
            };
          }

          // Reconstruct children from parent pointers
          for (const node of Object.values(nodes)) {
            if (
              node.parentId &&
              nodes[node.parentId] &&
              !nodes[node.parentId].children.includes(node.id)
            ) {
              nodes[node.parentId].children.push(node.id);
            }
          }
        }

        const rootId = tree.root_id;
        if (!rootId) {
          setHasPulledFleetHierarchy(false);
          showSyncStatus("error", "Fleet hierarchy did not include a root node");
          return;
        }
        if (!nodes[rootId]) {
          setHasPulledFleetHierarchy(false);
          showSyncStatus("error", "Could not find root node in fleet hierarchy");
          return;
        }

        const newHierarchy: PolicyHierarchy = normalizeHierarchy({ nodes, rootId });
        clearPendingCreateIds();
        applyHierarchyChange(newHierarchy);
        setSelectedId(rootId);

        // Expand all org and team nodes
        setExpandedIds(() => {
          const ids = new Set<string>();
          for (const node of Object.values(newHierarchy.nodes)) {
            if (node.type === "org" || node.type === "team" || node.type === "endpoint") {
              ids.add(node.id);
            }
          }
          return ids;
        });
        setHasPulledFleetHierarchy(true);

        showSyncStatus(
          "success",
          `Pulled ${Object.keys(nodes).length} nodes from fleet`,
        );
        return;
      }

      // Fallback: try older scoped-policies endpoint for backward compatibility
      console.warn("[hierarchy-sync] hierarchy/tree unavailable, falling back to scoped-policies");
      const [scopedPolicies, assignments] = await Promise.all([
        fetchScopedPolicies(getAuthenticatedConnection()),
        fetchPolicyAssignments(getAuthenticatedConnection()),
      ]);

      if (assignments.length === 0 && scopedPolicies.length === 0) {
        setHasPulledFleetHierarchy(false);
        showSyncStatus("error", "No hierarchy data found on fleet");
        return;
      }

      // Use assignments if available, fall back to scoped policies
      const source: Array<{
        scope_id: string;
        scope_name: string;
        scope_type: string;
        external_id?: string | null;
        policy_id?: string;
        policy_name?: string;
        parent_scope_id?: string | null;
        children?: string[];
      }> = assignments.length > 0 ? assignments : scopedPolicies;

      // Build the node map from remote data
      const nodes: Record<string, OrgNode> = {};
      let rootId: string | null = null;

      for (const item of source) {
        const nodeType = mapNodeType(item.scope_type);
        nodes[item.scope_id] = {
          id: item.scope_id,
          name: item.scope_name,
          type: nodeType,
          parentId: item.parent_scope_id ?? null,
          externalId: item.external_id ?? undefined,
          policyId: item.policy_id,
          policyName: item.policy_name,
          children: item.children ?? [],
          metadata: {},
        };

        if (nodeType === "org" && !item.parent_scope_id) {
          rootId = item.scope_id;
        }
      }

      // Older scoped-policies payloads may only encode the tree through children arrays.
      // Recover missing parent links before normalization so those nodes stay connected.
      for (const node of Object.values(nodes)) {
        for (const childId of node.children) {
          const child = nodes[childId];
          if (child && child.parentId == null) {
            child.parentId = node.id;
          }
        }
      }

      // If children were not provided, reconstruct from parent pointers
      const anyHasChildren = Object.values(nodes).some(
        (n) => n.children.length > 0,
      );
      if (!anyHasChildren) {
        for (const node of Object.values(nodes)) {
          if (
            node.parentId &&
            nodes[node.parentId] &&
            !nodes[node.parentId].children.includes(node.id)
          ) {
            nodes[node.parentId].children.push(node.id);
          }
        }
      }

      // Find root if we haven't yet
      if (!rootId) {
        const orgNode = Object.values(nodes).find(
          (n) => n.type === "org" && !n.parentId,
        );
        rootId = orgNode?.id ?? Object.values(nodes).find((n) => !n.parentId)?.id ?? null;
      }

      if (!rootId || !nodes[rootId]) {
        setHasPulledFleetHierarchy(false);
        showSyncStatus("error", "Could not determine root node from fleet data");
        return;
      }

      const newHierarchy: PolicyHierarchy = normalizeHierarchy({ nodes, rootId });
      clearPendingCreateIds();
      applyHierarchyChange(newHierarchy);
      setSelectedId(rootId);

      setExpandedIds(() => {
        const ids = new Set<string>();
        for (const node of Object.values(newHierarchy.nodes)) {
          if (node.type === "org" || node.type === "team" || node.type === "endpoint") {
            ids.add(node.id);
          }
        }
        return ids;
      });
      setHasPulledFleetHierarchy(true);

      showSyncStatus(
        "success",
        `Pulled ${Object.keys(nodes).length} nodes from fleet (legacy)`,
      );
    } catch (err) {
      showSyncStatus(
        "error",
        `Pull failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    } finally {
      syncInProgressRef.current = false;
    }
  }, [
    fleetConnected,
    connection,
    showSyncStatus,
    flattenTreeNode,
    mapNodeType,
    clearPendingCreateIds,
    applyHierarchyChange,
  ]);


  const isSyncing = syncStatus.type === "pushing" || syncStatus.type === "pulling";
  const rootNode = hierarchy.nodes[hierarchy.rootId];

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="shrink-0 flex items-center gap-2 px-4 py-2.5 border-b border-[#2d3240]/50 bg-[#0b0d13]/80">
        <span className="text-[11px] font-medium text-[#ece7dc] mr-2">
          Org Hierarchy
        </span>

        {/* LIVE / DEMO toggle */}
        <button
          onClick={handleToggleLiveMode}
          disabled={!fleetConnected}
          className={cn(
            "flex items-center gap-1.5 px-2 py-1 rounded text-[9px] font-semibold uppercase tracking-wider transition-colors",
            isLiveMode
              ? "bg-[#3dbf84]/15 text-[#3dbf84] hover:bg-[#3dbf84]/25"
              : "bg-[#6f7f9a]/10 text-[#6f7f9a]/60 hover:bg-[#6f7f9a]/20",
            !fleetConnected && "opacity-40 cursor-not-allowed",
          )}
          title={
            fleetConnected
              ? isLiveMode
                ? "Switch to DEMO mode (local-only)"
                : "Switch to LIVE mode (fleet sync enabled)"
              : "Connect to fleet to enable LIVE mode"
          }
        >
          {isLiveMode ? "LIVE" : "DEMO"}
        </button>

        {!fleetConnected && (
          <span className="flex items-center gap-1 text-[9px] text-[#6f7f9a]/40">
            <IconPlugConnected size={10} stroke={1.5} />
            Disconnected
          </span>
        )}

        {isLiveMode && (
          <span
            className={cn(
              "text-[9px] font-medium px-2 py-0.5 rounded",
              hasPulledFleetHierarchy
                ? "text-[#3dbf84] bg-[#3dbf84]/10"
                : "text-[#d4a84b] bg-[#d4a84b]/10",
            )}
            title={
              hasPulledFleetHierarchy
                ? "Currently rendering the last hierarchy snapshot fetched from fleet"
                : "Currently rendering the local draft; pull from fleet to replace it"
            }
          >
            {hasPulledFleetHierarchy ? "Fleet Snapshot" : "Local Draft"}
          </span>
        )}

        {/* Fleet sync buttons — only visible in LIVE mode */}
        {isLiveMode && fleetConnected && (
          <>
            <div className="w-px h-4 bg-[#2d3240]/50" />
            <button
              onClick={handlePushToFleet}
              disabled={syncStatus.type === "pushing" || syncStatus.type === "pulling"}
              className={cn(
                "flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[10px] font-medium transition-colors",
                syncStatus.type === "pushing"
                  ? "text-[#d4a84b] bg-[#d4a84b]/10"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/50",
                (syncStatus.type === "pushing" || syncStatus.type === "pulling") && "opacity-60 cursor-not-allowed",
              )}
              title="Upload local hierarchy as scoped policies to fleet"
            >
              {syncStatus.type === "pushing" ? (
                <IconLoader2 size={13} stroke={1.5} className="animate-spin" />
              ) : (
                <IconCloudUpload size={13} stroke={1.5} />
              )}
              Push to Fleet
            </button>

            <button
              onClick={handlePullFromFleet}
              disabled={syncStatus.type === "pushing" || syncStatus.type === "pulling"}
              className={cn(
                "flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[10px] font-medium transition-colors",
                syncStatus.type === "pulling"
                  ? "text-[#d4a84b] bg-[#d4a84b]/10"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/50",
                (syncStatus.type === "pushing" || syncStatus.type === "pulling") && "opacity-60 cursor-not-allowed",
              )}
              title="Download scoped policies from fleet into local hierarchy"
            >
              {syncStatus.type === "pulling" ? (
                <IconLoader2 size={13} stroke={1.5} className="animate-spin" />
              ) : (
                <IconCloudDownload size={13} stroke={1.5} />
              )}
              Pull from Fleet
            </button>
          </>
        )}

        {/* Sync status message */}
        {syncStatus.type !== "idle" && syncStatus.message && (
          <span
            className={cn(
              "text-[9px] font-medium px-2 py-0.5 rounded transition-opacity",
              syncStatus.type === "success" && "text-[#3dbf84] bg-[#3dbf84]/10",
              syncStatus.type === "error" && "text-[#c45c5c] bg-[#c45c5c]/10",
              (syncStatus.type === "pushing" || syncStatus.type === "pulling") &&
                "text-[#d4a84b] bg-[#d4a84b]/10",
            )}
          >
            {syncStatus.message}
          </span>
        )}

        <div className="flex-1" />

        <button
          onClick={handleValidateAll}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[10px] font-medium text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/50 transition-colors"
        >
          <IconShieldCheck size={13} stroke={1.5} />
          Validate All
        </button>

        <button
          onClick={handleExport}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[10px] font-medium text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/50 transition-colors"
        >
          <IconDownload size={13} stroke={1.5} />
          Export
        </button>

        <button
          onClick={handleResetToDemo}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[10px] font-medium text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/50 transition-colors"
        >
          <IconRefresh size={13} stroke={1.5} />
          Reset to Demo
        </button>
      </div>

      {/* Three-panel layout */}
      <div className="flex-1 flex min-h-0">
        {/* Left: Tree View */}
        <div className="w-[280px] shrink-0 border-r border-[#2d3240]/50 flex flex-col">
          <div className="shrink-0 px-3 py-2 border-b border-[#2d3240]/30">
            <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]/60">
              Organization Tree
            </span>
          </div>
          <div className="flex-1 overflow-y-auto py-1.5">
            {rootNode && (
              <TreeNode
                node={rootNode}
                hierarchy={hierarchy}
                selectedId={selectedId}
                expandedIds={expandedIds}
                ancestryIds={ancestryIds}
                depth={0}
                isSyncing={isSyncing}
                onSelect={handleSelect}
                onToggleExpand={handleToggleExpand}
                onAddChild={handleAddChild}
                onRemove={handleRemove}
                onRename={handleRename}
                onDragStart={handleDragStart}
                onDragOver={handleDragOver}
                onDrop={handleDrop}
                dragOverId={dragOverId}
              />
            )}
          </div>

          {/* Quick assign button at bottom of tree */}
          {selectedNode && (
            <div className="shrink-0 p-2 border-t border-[#2d3240]/30">
              <button
                onClick={() => setAssignTarget(selectedId)}
                className={cn(
                  "flex items-center gap-1.5 w-full px-2.5 py-2 rounded text-[10px] font-medium transition-colors",
                  selectedNode.policyId
                    ? "text-[#d4a84b] bg-[#d4a84b]/10 hover:bg-[#d4a84b]/15"
                    : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/50",
                )}
              >
                <IconLink size={12} stroke={1.5} />
                {selectedNode.policyId ? "Change Policy" : "Assign Policy"}
              </button>
            </div>
          )}
        </div>

        {/* Center: Effective Policy View */}
        <div className="flex-1 min-w-0 border-r border-[#2d3240]/50">
          {selectedId && effective ? (
            <EffectivePolicyPanel
              hierarchy={hierarchy}
              selectedId={selectedId}
              effective={effective}
            />
          ) : (
            <div className="flex items-center justify-center h-full">
              <p className="text-[11px] text-[#6f7f9a]/50">
                Select a node to view its effective policy
              </p>
            </div>
          )}
        </div>

        {/* Right: Merge Preview / Impact */}
        <div className="w-[260px] shrink-0">
          {selectedId && selectedNode ? (
            <MergePreviewPanel
              hierarchy={hierarchy}
              selectedId={selectedId}
              savedPolicies={savedPolicies}
            />
          ) : (
            <div className="flex items-center justify-center h-full">
              <p className="text-[10px] text-[#6f7f9a]/40">
                Select a node for details
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Dialogs */}
      {renameTarget && hierarchy.nodes[renameTarget] && (
        <RenameDialog
          node={hierarchy.nodes[renameTarget]}
          onRename={handleDoRename}
          onClose={() => setRenameTarget(null)}
        />
      )}

      {assignTarget && hierarchy.nodes[assignTarget] && (
        <PolicyAssignDialog
          node={hierarchy.nodes[assignTarget]}
          savedPolicies={savedPolicies}
          onAssign={handleAssign}
          onUnassign={handleUnassign}
          onClose={() => setAssignTarget(null)}
        />
      )}

      {validationIssues !== null && (
        <ValidationModal
          issues={validationIssues}
          onClose={() => setValidationIssues(null)}
          onSelectNode={(id) => {
            setSelectedId(id);
            // Expand ancestry
            const path = getAncestryPath(hierarchy, id);
            setExpandedIds((prev) => {
              const next = new Set(prev);
              for (const n of path) {
                next.add(n.id);
              }
              return next;
            });
          }}
        />
      )}
    </div>
  );
}
