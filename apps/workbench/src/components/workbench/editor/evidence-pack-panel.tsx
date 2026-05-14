/**
 * Evidence Pack Panel — right sidebar panel showing evidence packs
 * linked to the active detection document.
 *
 * Follows the same visual patterns as VersionHistoryPanel:
 * - bg-[#0b0d13] with border-l
 * - 10px font-mono headers with tabler icons
 * - ScrollArea body
 * - Collapsible card items
 */

import { useState, useCallback, useRef, useMemo } from "react";
import {
  IconPackage,
  IconPlus,
  IconTrash,
  IconDownload,
  IconUpload,
  IconChevronDown,
  IconChevronRight,
  IconShieldCheck,
  IconAlertTriangle,
  IconLock,
  IconX,
  IconArrowsExchange,
} from "@tabler/icons-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useEvidencePacks, type ImportResult } from "@/lib/workbench/detection-workflow/use-evidence-packs";
import type { FileType } from "@/lib/workbench/file-type-registry";
import type {
  EvidencePack,
  EvidenceDatasetKind,
  EvidenceItem,
  RedactionState,
} from "@/lib/workbench/detection-workflow/shared-types";

// ---- Constants ----

const DATASET_LABELS: Record<EvidenceDatasetKind, string> = {
  positive: "Positive",
  negative: "Negative",
  regression: "Regression",
  false_positive: "False Positive",
};

const DATASET_COLORS: Record<EvidenceDatasetKind, string> = {
  positive: "#3dbf84",
  negative: "#c45c5c",
  regression: "#d4a84b",
  false_positive: "#7c6ecf",
};

const DATASET_ORDER: EvidenceDatasetKind[] = [
  "positive",
  "negative",
  "regression",
  "false_positive",
];

const REDACTION_BADGES: Record<RedactionState, { label: string; color: string }> = {
  clean: { label: "Clean", color: "#3dbf84" },
  redacted: { label: "Redacted", color: "#d4a84b" },
  contains_sensitive_fields: { label: "Sensitive", color: "#c45c5c" },
};

// ---- Helpers ----

function relativeTime(iso: string): string {
  const now = Date.now();
  const then = new Date(iso).getTime();
  const diff = now - then;

  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months}mo ago`;
  return `${Math.floor(months / 12)}y ago`;
}

function totalItemCount(pack: EvidencePack): number {
  return Object.values(pack.datasets).reduce((sum, items) => sum + items.length, 0);
}

function itemCountsByKind(pack: EvidencePack): Record<EvidenceDatasetKind, number> {
  return {
    positive: pack.datasets.positive.length,
    negative: pack.datasets.negative.length,
    regression: pack.datasets.regression.length,
    false_positive: pack.datasets.false_positive.length,
  };
}

// ---- Props ----

interface EvidencePackPanelProps {
  documentId: string | undefined;
  fileType: FileType | undefined;
}

// ---- Component ----

export function EvidencePackPanel({ documentId, fileType }: EvidencePackPanelProps) {
  const {
    packs,
    loading,
    selectedPackId,
    selectPack,
    createPack,
    deletePack,
    addItem,
    removeItem,
    reclassifyItem,
    importPack,
    exportPack,
  } = useEvidencePacks(documentId, fileType);

  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [importResult, setImportResult] = useState<ImportResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleCreatePack = useCallback(async () => {
    await createPack();
  }, [createPack]);

  const handleDeletePack = useCallback(
    async (packId: string) => {
      await deletePack(packId);
      setDeleteConfirmId(null);
    },
    [deletePack],
  );

  const handleImportClick = useCallback(() => {
    fileInputRef.current?.click();
  }, []);

  const handleFileChange = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file) return;
      const result = await importPack(file);
      setImportResult(result);
      // Clear input so the same file can be re-selected
      e.target.value = "";
      // Auto-dismiss after 5 seconds
      setTimeout(() => setImportResult(null), 5000);
    },
    [importPack],
  );

  const handleExport = useCallback(
    async (packId: string) => {
      await exportPack(packId);
    },
    [exportPack],
  );

  if (!documentId) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-4 text-center">
        <IconPackage size={24} stroke={1.5} className="text-[#6f7f9a]/50 mb-2" />
        <p className="text-xs text-[#6f7f9a]">Open a detection document to view evidence packs</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full bg-[#0b0d13] border-l border-[#2d3240]">
      {/* Header */}
      <div className="shrink-0 px-3 py-2.5 border-b border-[#2d3240]">
        <div className="flex items-center gap-1.5 mb-2">
          <IconPackage size={13} stroke={1.5} className="text-[#d4a84b]" />
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
            Evidence Packs
          </span>
          {packs.length > 0 && (
            <span className="ml-auto text-[9px] font-mono text-[#6f7f9a]/60">
              {packs.length}
            </span>
          )}
        </div>

        {/* Action buttons */}
        <div className="flex gap-1">
          <Button
            variant="ghost"
            size="xs"
            onClick={handleCreatePack}
            className="flex-1 text-[9px] font-mono bg-[#d4a84b]/10 text-[#d4a84b] hover:bg-[#d4a84b]/20 border border-[#d4a84b]/20"
          >
            <IconPlus size={10} stroke={2} />
            New Pack
          </Button>
          <button
            type="button"
            onClick={handleImportClick}
            className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[8px] font-mono rounded border border-[#2d3240] text-[#6f7f9a] hover:text-[#ece7dc] hover:border-[#6f7f9a]/50 transition-colors"
            title="Import evidence pack from JSON"
          >
            <IconUpload size={9} stroke={1.5} />
            Import
          </button>
        </div>
        <input
          ref={fileInputRef}
          type="file"
          accept=".json,application/json"
          onChange={handleFileChange}
          className="hidden"
          data-testid="import-file-input"
        />
      </div>

      {/* Import result notification */}
      {importResult && (
        <div
          className={cn(
            "shrink-0 mx-3 mt-2 px-2 py-1.5 rounded text-[9px] font-mono border",
            importResult.failed.length > 0
              ? "bg-[#d4a84b]/10 text-[#d4a84b] border-[#d4a84b]/20"
              : "bg-[#3dbf84]/10 text-[#3dbf84] border-[#3dbf84]/20",
          )}
        >
          <div className="flex items-center justify-between">
            <span>
              Imported {importResult.imported} item{importResult.imported !== 1 ? "s" : ""}
              {importResult.failed.length > 0 &&
                ` (${importResult.failed.length} failed)`}
            </span>
            <button
              type="button"
              onClick={() => setImportResult(null)}
              className="text-current opacity-60 hover:opacity-100"
            >
              <IconX size={9} stroke={2} />
            </button>
          </div>
          {importResult.failed.length > 0 && (
            <div className="mt-1 space-y-0.5">
              {importResult.failed.slice(0, 3).map((f, i) => (
                <p key={i} className="text-[8px] opacity-70 truncate">
                  {f.reason}
                </p>
              ))}
              {importResult.failed.length > 3 && (
                <p className="text-[8px] opacity-50">
                  ...and {importResult.failed.length - 3} more
                </p>
              )}
            </div>
          )}
        </div>
      )}

      {/* Pack list */}
      <ScrollArea className="flex-1">
        <div className="p-3">
          {/* Loading state */}
          {loading && (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => (
                <div
                  key={i}
                  className="h-14 rounded bg-[#131721] animate-pulse border border-[#2d3240]/50"
                />
              ))}
            </div>
          )}

          {/* Empty state */}
          {!loading && packs.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 text-[#6f7f9a] text-xs font-mono gap-2">
              <IconPackage size={24} stroke={1} className="opacity-40" />
              <span>No evidence packs yet</span>
              <span className="text-[9px] text-[#6f7f9a]/50">
                Create one to start collecting test evidence
              </span>
            </div>
          )}

          {/* Pack cards */}
          {!loading && (
            <div className="flex flex-col gap-1">
              {packs.map((pack) => {
                const isSelected = selectedPackId === pack.id;
                const counts = itemCountsByKind(pack);
                const total = totalItemCount(pack);
                const redactionBadge = REDACTION_BADGES[pack.redactionState];

                return (
                  <div key={pack.id}>
                    {/* Pack card header */}
                    <button
                      type="button"
                      onClick={() => selectPack(isSelected ? null : pack.id)}
                      className={cn(
                        "w-full text-left rounded-md px-2 py-1.5 transition-colors",
                        isSelected
                          ? "bg-[#131721] border border-[#2d3240]"
                          : "hover:bg-[#131721]/60",
                      )}
                    >
                      <div className="flex items-center gap-1.5">
                        {isSelected ? (
                          <IconChevronDown size={10} stroke={1.5} className="text-[#6f7f9a] shrink-0" />
                        ) : (
                          <IconChevronRight size={10} stroke={1.5} className="text-[#6f7f9a] shrink-0" />
                        )}
                        <span className="text-[10px] font-mono font-bold text-[#ece7dc] truncate">
                          {pack.title}
                        </span>
                        <span className="ml-auto text-[9px] font-mono text-[#6f7f9a]/60 shrink-0">
                          {relativeTime(pack.createdAt)}
                        </span>
                      </div>

                      {/* Dataset counts inline */}
                      <div className="flex items-center gap-2 mt-1 ml-4">
                        {DATASET_ORDER.map((kind) =>
                          counts[kind] > 0 ? (
                            <span
                              key={kind}
                              className="text-[8px] font-mono flex items-center gap-0.5"
                              style={{ color: DATASET_COLORS[kind] }}
                            >
                              <span
                                className="w-1 h-1 rounded-full"
                                style={{ backgroundColor: DATASET_COLORS[kind] }}
                              />
                              {counts[kind]} {DATASET_LABELS[kind].toLowerCase()}
                            </span>
                          ) : null,
                        )}
                        {total === 0 && (
                          <span className="text-[8px] font-mono text-[#6f7f9a]/40">
                            empty
                          </span>
                        )}
                      </div>

                      {/* Redaction badge */}
                      <div className="flex items-center gap-1.5 mt-1 ml-4">
                        <span
                          className="inline-flex items-center gap-0.5 text-[8px] font-mono px-1 py-0 rounded-full border"
                          style={{
                            color: redactionBadge.color,
                            backgroundColor: `${redactionBadge.color}10`,
                            borderColor: `${redactionBadge.color}33`,
                          }}
                        >
                          {pack.redactionState === "redacted" ? (
                            <IconLock size={7} stroke={1.5} />
                          ) : pack.redactionState === "contains_sensitive_fields" ? (
                            <IconAlertTriangle size={7} stroke={1.5} />
                          ) : (
                            <IconShieldCheck size={7} stroke={1.5} />
                          )}
                          {redactionBadge.label}
                        </span>
                      </div>
                    </button>

                    {/* Expanded pack detail */}
                    {isSelected && (
                      <div className="px-2 pb-2 mt-1">
                        {/* Actions */}
                        <div className="flex flex-wrap gap-1 mb-2">
                          <button
                            type="button"
                            onClick={() => handleExport(pack.id)}
                            className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[8px] font-mono rounded border border-[#2d3240] text-[#6f7f9a] hover:text-[#ece7dc] hover:border-[#6f7f9a]/50 transition-colors"
                          >
                            <IconDownload size={9} stroke={1.5} />
                            Export JSON
                          </button>
                          {deleteConfirmId === pack.id ? (
                            <div className="flex items-center gap-1">
                              <span className="text-[8px] font-mono text-[#c45c5c]">
                                Delete?
                              </span>
                              <button
                                type="button"
                                onClick={() => handleDeletePack(pack.id)}
                                className="px-1.5 py-0.5 text-[8px] font-mono rounded border border-[#c45c5c]/30 text-[#c45c5c] hover:bg-[#c45c5c]/10 transition-colors"
                                data-testid="confirm-delete"
                              >
                                Confirm
                              </button>
                              <button
                                type="button"
                                onClick={() => setDeleteConfirmId(null)}
                                className="px-1.5 py-0.5 text-[8px] font-mono text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
                              >
                                Cancel
                              </button>
                            </div>
                          ) : (
                            <button
                              type="button"
                              onClick={() => setDeleteConfirmId(pack.id)}
                              className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[8px] font-mono rounded border border-[#2d3240] text-[#6f7f9a] hover:text-[#c45c5c] hover:border-[#c45c5c]/30 transition-colors"
                            >
                              <IconTrash size={9} stroke={1.5} />
                              Delete
                            </button>
                          )}
                        </div>

                        {/* Notes */}
                        {pack.notes && (
                          <p className="text-[9px] font-mono text-[#6f7f9a]/70 mb-2 italic">
                            {pack.notes}
                          </p>
                        )}

                        {/* Items grouped by dataset kind */}
                        <AddEvidenceItemComposer
                          packId={pack.id}
                          fileType={pack.fileType}
                          onAddItem={addItem}
                        />

                        {DATASET_ORDER.map((kind) => {
                          const items = pack.datasets[kind];
                          if (items.length === 0) return null;

                          return (
                            <DatasetSection
                              key={kind}
                              kind={kind}
                              items={items}
                              packId={pack.id}
                              onRemoveItem={removeItem}
                              onReclassifyItem={reclassifyItem}
                            />
                          );
                        })}

                        {total === 0 && (
                          <p className="text-[9px] font-mono text-[#6f7f9a]/40 text-center py-2">
                            No evidence items in this pack
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}

const POLICY_ACTION_OPTIONS = [
  "file_access",
  "file_write",
  "network_egress",
  "shell_command",
  "mcp_tool_call",
  "patch_apply",
  "user_input",
] as const;

function defaultItemKind(fileType: FileType): EvidenceItem["kind"] {
  if (fileType === "yara_rule") return "bytes";
  if (fileType === "ocsf_event") return "ocsf_event";
  if (fileType === "clawdstrike_policy") return "policy_scenario";
  return "structured_event";
}

function AddEvidenceItemComposer({
  packId,
  fileType,
  onAddItem,
}: {
  packId: string;
  fileType: FileType;
  onAddItem: (
    packId: string,
    dataset: EvidenceDatasetKind,
    item: EvidenceItem,
  ) => Promise<void>;
}) {
  const [expanded, setExpanded] = useState(false);
  const [dataset, setDataset] = useState<EvidenceDatasetKind>("regression");
  const [itemKind, setItemKind] = useState<EvidenceItem["kind"]>(() => defaultItemKind(fileType));
  const [payloadText, setPayloadText] = useState("{}");
  const [bytesEncoding, setBytesEncoding] = useState<"base64" | "hex" | "utf8">("utf8");
  const [expectedMatch, setExpectedMatch] = useState<"match" | "no_match">("match");
  const [expectedValidity, setExpectedValidity] = useState<"valid" | "invalid">("valid");
  const [scenarioVerdict, setScenarioVerdict] = useState<"allow" | "warn" | "deny">("deny");
  const [scenarioActionType, setScenarioActionType] = useState<(typeof POLICY_ACTION_OPTIONS)[number]>("shell_command");
  const [scenarioName, setScenarioName] = useState("Captured Scenario");
  const [scenarioTarget, setScenarioTarget] = useState("");
  const [sourceRef, setSourceRef] = useState("");
  const [error, setError] = useState<string | null>(null);

  const handleAdd = useCallback(async () => {
    try {
      let item: EvidenceItem;
      if (itemKind === "structured_event") {
        item = {
          id: crypto.randomUUID(),
          kind: "structured_event",
          format: "json",
          payload: JSON.parse(payloadText) as Record<string, unknown>,
          expected: expectedMatch,
          sourceEventId: sourceRef || undefined,
        };
      } else if (itemKind === "bytes") {
        item = {
          id: crypto.randomUUID(),
          kind: "bytes",
          encoding: bytesEncoding,
          payload: payloadText,
          expected: expectedMatch,
          sourceArtifactPath: sourceRef || undefined,
        };
      } else if (itemKind === "ocsf_event") {
        item = {
          id: crypto.randomUUID(),
          kind: "ocsf_event",
          payload: JSON.parse(payloadText) as Record<string, unknown>,
          expected: expectedValidity,
          sourceEventId: sourceRef || undefined,
        };
      } else {
        item = {
          id: crypto.randomUUID(),
          kind: "policy_scenario",
          scenario: {
            id: crypto.randomUUID(),
            name: scenarioName.trim() || "Captured Scenario",
            description: "Manually captured evidence scenario",
            category: dataset === "negative" || dataset === "false_positive" ? "benign" : "attack",
            actionType: scenarioActionType,
            payload: {
              target: scenarioTarget,
              content: payloadText.trim().length > 0 ? payloadText : undefined,
            },
            expectedVerdict: scenarioVerdict,
          },
          expected: scenarioVerdict,
        };
      }

      await onAddItem(packId, dataset, item);
      setError(null);
      setExpanded(false);
      setPayloadText(itemKind === "bytes" ? "" : "{}");
      setScenarioTarget("");
      setSourceRef("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Failed to add evidence item");
    }
  }, [
    bytesEncoding,
    dataset,
    expectedMatch,
    expectedValidity,
    itemKind,
    onAddItem,
    packId,
    payloadText,
    scenarioActionType,
    scenarioName,
    scenarioTarget,
    scenarioVerdict,
    sourceRef,
  ]);

  return (
    <div className="mb-3 rounded-md border border-[#2d3240]/70 bg-[#0f131c] p-2">
      <button
        type="button"
        onClick={() => setExpanded((value) => !value)}
        className="flex w-full items-center gap-1.5 text-left"
      >
        {expanded ? (
          <IconChevronDown size={10} stroke={1.5} className="text-[#6f7f9a]" />
        ) : (
          <IconChevronRight size={10} stroke={1.5} className="text-[#6f7f9a]" />
        )}
        <IconPlus size={10} stroke={1.8} className="text-[#d4a84b]" />
        <span className="text-[9px] font-mono uppercase tracking-wider text-[#d4a84b]">
          Add Evidence Item
        </span>
      </button>

      {expanded && (
        <div className="mt-2 space-y-2">
          <div className="grid grid-cols-2 gap-2">
            <label className="text-[8px] font-mono text-[#6f7f9a]">
              Dataset
              <select
                value={dataset}
                onChange={(event) => setDataset(event.target.value as EvidenceDatasetKind)}
                className="mt-1 h-7 w-full rounded border border-[#2d3240] bg-[#05060a] px-2 text-[9px] text-[#ece7dc]"
              >
                {DATASET_ORDER.map((kind) => (
                  <option key={kind} value={kind}>
                    {DATASET_LABELS[kind]}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-[8px] font-mono text-[#6f7f9a]">
              Kind
              <select
                value={itemKind}
                onChange={(event) => setItemKind(event.target.value as EvidenceItem["kind"])}
                className="mt-1 h-7 w-full rounded border border-[#2d3240] bg-[#05060a] px-2 text-[9px] text-[#ece7dc]"
              >
                <option value="structured_event">Structured Event</option>
                <option value="bytes">Byte Sample</option>
                <option value="ocsf_event">OCSF Event</option>
                <option value="policy_scenario">Policy Scenario</option>
              </select>
            </label>
          </div>

          {(itemKind === "structured_event" || itemKind === "bytes" || itemKind === "ocsf_event") && (
            <label className="block text-[8px] font-mono text-[#6f7f9a]">
              Source Reference
              <input
                value={sourceRef}
                onChange={(event) => setSourceRef(event.target.value)}
                placeholder="event id or artifact path"
                className="mt-1 h-7 w-full rounded border border-[#2d3240] bg-[#05060a] px-2 text-[9px] text-[#ece7dc]"
              />
            </label>
          )}

          {itemKind === "bytes" && (
            <label className="block text-[8px] font-mono text-[#6f7f9a]">
              Encoding
              <select
                value={bytesEncoding}
                onChange={(event) => setBytesEncoding(event.target.value as "base64" | "hex" | "utf8")}
                className="mt-1 h-7 w-full rounded border border-[#2d3240] bg-[#05060a] px-2 text-[9px] text-[#ece7dc]"
              >
                <option value="utf8">UTF-8</option>
                <option value="hex">Hex</option>
                <option value="base64">Base64</option>
              </select>
            </label>
          )}

          {itemKind === "policy_scenario" ? (
            <div className="space-y-2">
              <label className="block text-[8px] font-mono text-[#6f7f9a]">
                Scenario Name
                <input
                  value={scenarioName}
                  onChange={(event) => setScenarioName(event.target.value)}
                  className="mt-1 h-7 w-full rounded border border-[#2d3240] bg-[#05060a] px-2 text-[9px] text-[#ece7dc]"
                />
              </label>
              <div className="grid grid-cols-2 gap-2">
                <label className="text-[8px] font-mono text-[#6f7f9a]">
                  Action
                  <select
                    value={scenarioActionType}
                    onChange={(event) =>
                      setScenarioActionType(event.target.value as (typeof POLICY_ACTION_OPTIONS)[number])
                    }
                    className="mt-1 h-7 w-full rounded border border-[#2d3240] bg-[#05060a] px-2 text-[9px] text-[#ece7dc]"
                  >
                    {POLICY_ACTION_OPTIONS.map((option) => (
                      <option key={option} value={option}>
                        {option}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="text-[8px] font-mono text-[#6f7f9a]">
                  Expect
                  <select
                    value={scenarioVerdict}
                    onChange={(event) => setScenarioVerdict(event.target.value as "allow" | "warn" | "deny")}
                    className="mt-1 h-7 w-full rounded border border-[#2d3240] bg-[#05060a] px-2 text-[9px] text-[#ece7dc]"
                  >
                    <option value="deny">deny</option>
                    <option value="warn">warn</option>
                    <option value="allow">allow</option>
                  </select>
                </label>
              </div>
              <label className="block text-[8px] font-mono text-[#6f7f9a]">
                Target
                <input
                  value={scenarioTarget}
                  onChange={(event) => setScenarioTarget(event.target.value)}
                  className="mt-1 h-7 w-full rounded border border-[#2d3240] bg-[#05060a] px-2 text-[9px] text-[#ece7dc]"
                />
              </label>
            </div>
          ) : (
            <label className="block text-[8px] font-mono text-[#6f7f9a]">
              Expected
              <select
                value={itemKind === "ocsf_event" ? expectedValidity : expectedMatch}
                onChange={(event) => {
                  if (itemKind === "ocsf_event") {
                    setExpectedValidity(event.target.value as "valid" | "invalid");
                  } else {
                    setExpectedMatch(event.target.value as "match" | "no_match");
                  }
                }}
                className="mt-1 h-7 w-full rounded border border-[#2d3240] bg-[#05060a] px-2 text-[9px] text-[#ece7dc]"
              >
                {itemKind === "ocsf_event" ? (
                  <>
                    <option value="valid">valid</option>
                    <option value="invalid">invalid</option>
                  </>
                ) : (
                  <>
                    <option value="match">match</option>
                    <option value="no_match">no match</option>
                  </>
                )}
              </select>
            </label>
          )}

          <label className="block text-[8px] font-mono text-[#6f7f9a]">
            {itemKind === "bytes"
              ? "Byte Content"
              : itemKind === "policy_scenario"
                ? "Optional Content"
                : "JSON Payload"}
            <textarea
              value={payloadText}
              onChange={(event) => setPayloadText(event.target.value)}
              rows={itemKind === "policy_scenario" ? 3 : 5}
              className="mt-1 w-full rounded border border-[#2d3240] bg-[#05060a] px-2 py-1.5 text-[9px] font-mono text-[#ece7dc]"
            />
          </label>

          {error && <p className="text-[8px] font-mono text-[#c45c5c]">{error}</p>}

          <div className="flex justify-end">
            <button
              type="button"
              onClick={() => void handleAdd()}
              className="inline-flex items-center gap-1 rounded border border-[#d4a84b]/25 bg-[#d4a84b]/10 px-2 py-1 text-[8px] font-mono text-[#d4a84b] hover:bg-[#d4a84b]/15"
            >
              <IconPlus size={9} stroke={1.8} />
              Add Item
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ---- DatasetSection ----

function DatasetSection({
  kind,
  items,
  packId,
  onRemoveItem,
  onReclassifyItem,
}: {
  kind: EvidenceDatasetKind;
  items: EvidenceItem[];
  packId: string;
  onRemoveItem: (packId: string, itemId: string) => Promise<void>;
  onReclassifyItem: (
    packId: string,
    itemId: string,
    from: EvidenceDatasetKind,
    to: EvidenceDatasetKind,
  ) => Promise<void>;
}) {
  const [expanded, setExpanded] = useState(true);

  return (
    <div className="mb-2">
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-1 w-full text-left py-0.5"
      >
        {expanded ? (
          <IconChevronDown size={9} stroke={1.5} className="text-[#6f7f9a]" />
        ) : (
          <IconChevronRight size={9} stroke={1.5} className="text-[#6f7f9a]" />
        )}
        <span
          className="w-1.5 h-1.5 rounded-full"
          style={{ backgroundColor: DATASET_COLORS[kind] }}
        />
        <span
          className="text-[9px] font-mono font-bold uppercase tracking-wider"
          style={{ color: DATASET_COLORS[kind] }}
        >
          {DATASET_LABELS[kind]}
        </span>
        <span className="text-[8px] font-mono text-[#6f7f9a]/50 ml-auto">
          {items.length}
        </span>
      </button>

      {expanded && (
        <div className="ml-3 mt-0.5 space-y-0.5">
          {items.map((item) => (
            <EvidenceItemRow
              key={item.id}
              item={item}
              currentKind={kind}
              packId={packId}
              onRemove={onRemoveItem}
              onReclassify={onReclassifyItem}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ---- EvidenceItemRow ----

function EvidenceItemRow({
  item,
  currentKind,
  packId,
  onRemove,
  onReclassify,
}: {
  item: EvidenceItem;
  currentKind: EvidenceDatasetKind;
  packId: string;
  onRemove: (packId: string, itemId: string) => Promise<void>;
  onReclassify: (
    packId: string,
    itemId: string,
    from: EvidenceDatasetKind,
    to: EvidenceDatasetKind,
  ) => Promise<void>;
}) {
  const [showReclassify, setShowReclassify] = useState(false);

  const itemLabel = useMemo(() => {
    switch (item.kind) {
      case "structured_event":
        return `structured: ${item.sourceEventId ?? item.id.slice(0, 8)}`;
      case "bytes":
        return `bytes: ${item.sourceArtifactPath ?? item.id.slice(0, 8)}`;
      case "ocsf_event":
        return `ocsf: ${item.sourceEventId ?? item.id.slice(0, 8)}`;
      case "policy_scenario":
        return `scenario: ${item.scenario.name}`;
    }
  }, [item]);

  const expectedLabel = useMemo(() => {
    if ("expected" in item) {
      return item.expected;
    }
    return "";
  }, [item]);

  return (
    <div className="flex items-center gap-1 group py-0.5 px-1 rounded hover:bg-[#2d3240]/20 transition-colors">
      <span className="text-[8px] font-mono text-[#ece7dc]/60 truncate flex-1">
        {itemLabel}
      </span>
      {expectedLabel && (
        <span className="text-[7px] font-mono text-[#6f7f9a]/40 shrink-0">
          {expectedLabel}
        </span>
      )}

      {/* Reclassify dropdown */}
      {showReclassify ? (
        <div className="flex items-center gap-0.5">
          {DATASET_ORDER.filter((k) => k !== currentKind).map((targetKind) => (
            <button
              key={targetKind}
              type="button"
              onClick={() => {
                void onReclassify(packId, item.id, currentKind, targetKind);
                setShowReclassify(false);
              }}
              className="px-1 py-0 text-[7px] font-mono rounded border border-[#2d3240] hover:border-[#6f7f9a]/50 transition-colors"
              style={{ color: DATASET_COLORS[targetKind] }}
              title={`Move to ${DATASET_LABELS[targetKind]}`}
            >
              {DATASET_LABELS[targetKind].slice(0, 3)}
            </button>
          ))}
          <button
            type="button"
            onClick={() => setShowReclassify(false)}
            className="text-[#6f7f9a] hover:text-[#ece7dc]"
          >
            <IconX size={7} stroke={2} />
          </button>
        </div>
      ) : (
        <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
          <button
            type="button"
            onClick={() => setShowReclassify(true)}
            className="text-[#6f7f9a] hover:text-[#d4a84b] transition-colors"
            title="Reclassify"
          >
            <IconArrowsExchange size={9} stroke={1.5} />
          </button>
          <button
            type="button"
            onClick={() => void onRemove(packId, item.id)}
            className="text-[#6f7f9a] hover:text-[#c45c5c] transition-colors"
            title="Remove"
          >
            <IconX size={9} stroke={1.5} />
          </button>
        </div>
      )}
    </div>
  );
}
