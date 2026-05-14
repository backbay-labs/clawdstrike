/**
 * Publish Panel — format-aware publication surface for all detection types.
 *
 * Shows gate status indicators, target selectors, publication history,
 * and export/deploy actions. Non-policy formats cannot invoke fleet deploy
 * directly — they must go through the publication pipeline.
 */

import { useState, useCallback, useMemo } from "react";
import {
  IconRocket,
  IconDownload,
  IconCheck,
  IconX,
  IconLoader2,
  IconCircle,
  IconChevronDown,
  IconChevronRight,
  IconFileExport,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useToast } from "@/components/ui/toast";
import { emitAuditEvent } from "@/lib/workbench/local-audit";
import { FILE_TYPE_REGISTRY, type FileType } from "@/lib/workbench/file-type-registry";
import type { PublicationManifest, PublishTarget, LabRun } from "@/lib/workbench/detection-workflow/shared-types";
import {
  usePublication,
  getAvailableTargets,
  type PublishGateStatus,
} from "@/lib/workbench/detection-workflow/use-publication";
import { getPublicationStore } from "@/lib/workbench/detection-workflow/publication-store";
import { useFleetConnection } from "@/features/fleet/use-fleet-connection";
import { deployPolicy } from "@/features/fleet/fleet-client";

// ---- Target Labels ----

const TARGET_LABELS: Record<PublishTarget, string> = {
  native_policy: "Native Policy (YAML)",
  fleet_deploy: "Fleet Deploy",
  spl: "Splunk SPL",
  kql: "KQL (Kusto)",
  esql: "ES|QL",
  json_export: "JSON Export",
};

// ---- Props ----

export interface PublishPanelProps {
  documentId: string | undefined;
  fileType: FileType | undefined;
  source: string;
  validationValid: boolean;
  lastLabRun: LabRun | null | undefined;
}

// ---- Component ----

export function PublishPanel({
  documentId,
  fileType,
  source,
  validationValid,
  lastLabRun,
}: PublishPanelProps) {
  const { toast } = useToast();
  const { connection, getAuthenticatedConnection: getAuthedConn } = useFleetConnection();

  const {
    manifests,
    loading,
    publish,
    canPublish,
    publishGateStatus,
    refreshManifests,
  } = usePublication(documentId, fileType, {
    validationValid,
    currentSource: source,
    lastLabRun: lastLabRun ?? undefined,
  });

  const [selectedTarget, setSelectedTarget] = useState<PublishTarget | null>(null);
  const [isPublishing, setIsPublishing] = useState(false);
  const [expandedManifestId, setExpandedManifestId] = useState<string | null>(null);
  const [skipLabGate, setSkipLabGate] = useState(false);

  const availableTargets = useMemo(
    () => (fileType ? getAvailableTargets(fileType) : []),
    [fileType],
  );

  // Auto-select first target
  const effectiveTarget = selectedTarget ?? availableTargets[0] ?? null;

  // ---- Publish Handler ----

  const handlePublish = useCallback(async () => {
    if (!effectiveTarget) return;

    setIsPublishing(true);
    try {
      const result = await publish({
        source,
        targetFormat: effectiveTarget,
        skipLabGate,
      });

      if (result.success && result.manifest) {
        if (effectiveTarget === "fleet_deploy" && connection.connected) {
          try {
            const deploySource = result.outputContent ?? source;
            const deployResult = await deployPolicy(getAuthedConn(), deploySource);
            const updatedManifest: PublicationManifest = {
              ...result.manifest,
              deployResponse: {
                success: deployResult.success,
                hash: deployResult.hash,
                destination: "fleet",
              },
            };
            const store = getPublicationStore();
            await store.init();
            await store.saveManifest(updatedManifest);
            await refreshManifests();
            if (deployResult.success) {
              toast({
                type: "success",
                title: "Published and deployed",
                description: `Hash: ${deployResult.hash?.slice(0, 12) ?? "n/a"}`,
              });
              emitAuditEvent({
                eventType: "publication.fleet_deploy.success",
                source: "deploy",
                summary: `Published and deployed to fleet`,
                details: {
                  manifestId: updatedManifest.id,
                  hash: deployResult.hash,
                },
              });
            } else {
              toast({
                type: "error",
                title: "Published but deploy failed",
                description: deployResult.error ?? "Unknown error",
                duration: 5000,
              });
            }
          } catch (err) {
            toast({
              type: "error",
              title: "Published but deploy failed",
              description: err instanceof Error ? err.message : "Deploy request failed",
              duration: 5000,
            });
          }
        } else if (effectiveTarget !== "fleet_deploy") {
          // Non-deploy targets: trigger download
          downloadOutput(result.manifest, result.outputContent ?? source);
          toast({
            type: "success",
            title: "Published",
            description: `${TARGET_LABELS[effectiveTarget]} exported`,
          });
        } else {
          toast({
            type: "success",
            title: "Publication manifest created",
            description: "Connect to fleet to deploy",
          });
        }

        emitAuditEvent({
          eventType: "publication.success",
          source: "editor",
          summary: `Published ${fileType ?? "unknown"} as ${effectiveTarget}`,
          details: {
            manifestId: result.manifest.id,
            sourceHash: result.manifest.sourceHash,
            outputHash: result.manifest.outputHash,
          },
        });
      } else {
        toast({
          type: "error",
          title: "Publication failed",
          description: result.error ?? "Unknown error",
          duration: 5000,
        });
      }
    } finally {
      setIsPublishing(false);
    }
  }, [connection, effectiveTarget, getAuthedConn, publish, refreshManifests, source, skipLabGate, toast]);

  // ---- Download Helper ----

  function downloadOutput(manifest: PublicationManifest, content: string) {
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;

    const ext =
      manifest.target === "json_export"
        ? ".json"
        : manifest.target === "spl"
          ? ".spl"
          : manifest.target === "kql"
            ? ".kql"
            : manifest.target === "esql"
              ? ".esql"
              : ".yaml";

    a.download = `${manifest.documentId.slice(0, 8)}_${manifest.target}${ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  const handleDownloadManifestOutput = useCallback(
    async (manifest: PublicationManifest) => {
      const store = getPublicationStore();
      await store.init();
      const outputContent = await store.getOutputContent(manifest.id);
      if (!outputContent) {
        toast({
          type: "error",
          title: "Artifact unavailable",
          description: "No stored publication artifact was found for this manifest.",
        });
        return;
      }
      downloadOutput(manifest, outputContent);
    },
    [toast],
  );

  // ---- Non-publishable state ----

  if (!documentId || !fileType) {
    return (
      <div className="flex flex-col gap-3 p-4 h-full">
        <h3 className="text-[10px] font-semibold uppercase tracking-wider text-[#6f7f9a]">
          Publish
        </h3>
        <p className="text-[10px] text-[#6f7f9a]">
          Open a detection document to publish.
        </p>
      </div>
    );
  }

  if (!canPublish) {
    return (
      <div className="flex flex-col gap-3 p-4 h-full">
        <h3 className="text-[10px] font-semibold uppercase tracking-wider text-[#6f7f9a]">
          Publish
        </h3>
        <p className="text-[10px] text-[#6f7f9a]">
          No publish adapter registered for {FILE_TYPE_REGISTRY[fileType]?.label ?? fileType}.
        </p>
      </div>
    );
  }

  const isFleetTarget = effectiveTarget === "fleet_deploy";
  const publishBlocked = isPublishing || !effectiveTarget || (!publishGateStatus.gateOpen && !skipLabGate);

  return (
    <div className="flex flex-col gap-3 p-4 h-full overflow-y-auto">
      {/* ---- Header ---- */}
      <div className="flex items-center justify-between">
        <h3 className="text-[10px] font-semibold uppercase tracking-wider text-[#6f7f9a]">
          Publish
        </h3>
        <span className="text-[10px] text-[#6f7f9a]">
          {FILE_TYPE_REGISTRY[fileType]?.shortLabel ?? fileType}
        </span>
      </div>

      {/* ---- Gate Status ---- */}
      <GateStatusSection status={publishGateStatus} />

      {/* ---- Target Selector ---- */}
      <div className="flex flex-col gap-1.5">
        <label className="text-[10px] font-medium text-[#6f7f9a] uppercase tracking-wider">
          Target Format
        </label>
        <select
          value={effectiveTarget ?? ""}
          onChange={(e) => setSelectedTarget(e.target.value as PublishTarget)}
          className="h-7 px-2 rounded-md border border-[#2d3240] bg-[#131721] text-[10px] text-[#ece7dc] focus:outline-none focus:border-[#d4a84b]/50"
        >
          {availableTargets.map((target) => (
            <option key={target} value={target}>
              {TARGET_LABELS[target]}
            </option>
          ))}
        </select>
      </div>

      {/* ---- Skip lab gate toggle ---- */}
      {publishGateStatus.labRunPassed === false && (
        <label className="flex items-center gap-2 text-[10px] text-[#d4a84b] cursor-pointer">
          <input
            type="checkbox"
            checked={skipLabGate}
            onChange={(e) => setSkipLabGate(e.target.checked)}
            className="rounded border-[#2d3240] bg-[#131721]"
          />
          Override: skip lab run gate
        </label>
      )}

      {/* ---- Publish Button ---- */}
      <button
        onClick={handlePublish}
        disabled={publishBlocked}
        className={cn(
          "flex items-center justify-center gap-1.5 h-8 rounded-lg text-[11px] font-medium transition-colors",
          publishBlocked
            ? "bg-[#131721] text-[#6f7f9a] border border-[#2d3240] opacity-50 cursor-not-allowed"
            : isFleetTarget
              ? "bg-[#d4a84b] text-[#05060a] hover:bg-[#e8c36a]"
              : "bg-[#3dbf84] text-[#05060a] hover:bg-[#4dd99a]",
        )}
      >
        {isPublishing ? (
          <>
            <IconLoader2 size={13} stroke={2} className="animate-spin" />
            Publishing...
          </>
        ) : isFleetTarget ? (
          <>
            <IconRocket size={13} stroke={2} />
            Publish & Deploy
          </>
        ) : (
          <>
            <IconFileExport size={13} stroke={2} />
            Publish & Export
          </>
        )}
      </button>

      {/* ---- Publication History ---- */}
      <PublicationHistory
        manifests={manifests}
        loading={loading}
        expandedManifestId={expandedManifestId}
        onDownloadManifest={handleDownloadManifestOutput}
        onToggleManifest={(id) =>
          setExpandedManifestId((prev) => (prev === id ? null : id))
        }
      />
    </div>
  );
}

// ---- Gate Status Section ----

function GateStatusSection({ status }: { status: PublishGateStatus }) {
  return (
    <div className="flex flex-col gap-1.5">
      <p className="text-[10px] font-medium text-[#6f7f9a] uppercase tracking-wider">
        Publish Gates
      </p>
      <div className="flex flex-col gap-1 px-3 py-2 rounded-md bg-[#131721] border border-[#2d3240]/60">
        <GateIndicator
          label="Validation"
          passed={status.validationPassed}
        />
        <GateIndicator
          label="Lab Run"
          passed={status.labRunPassed}
        />
        <GateIndicator
          label="Source Changed"
          passed={status.sourceHashChanged ? null : true}
          infoLabel={status.sourceHashChanged ? "Modified" : "Unchanged"}
        />
      </div>
      {status.reasons.length > 0 && (
        <div className="text-[9px] text-[#c45c5c] px-1">
          {status.reasons.map((r, i) => (
            <p key={i}>{r}</p>
          ))}
        </div>
      )}
    </div>
  );
}

function GateIndicator({
  label,
  passed,
  infoLabel,
}: {
  label: string;
  passed: boolean | null;
  infoLabel?: string;
}) {
  return (
    <div className="flex items-center gap-2 text-[10px]">
      {passed === true ? (
        <IconCheck size={10} stroke={2} className="text-[#3dbf84]" />
      ) : passed === false ? (
        <IconX size={10} stroke={2} className="text-[#c45c5c]" />
      ) : (
        <IconCircle size={10} stroke={1.5} className="text-[#6f7f9a]" />
      )}
      <span
        className={cn(
          passed === true
            ? "text-[#3dbf84]"
            : passed === false
              ? "text-[#c45c5c]"
              : "text-[#6f7f9a]",
        )}
      >
        {label}
      </span>
      {infoLabel && (
        <span className="ml-auto text-[9px] text-[#6f7f9a]">{infoLabel}</span>
      )}
    </div>
  );
}

// ---- Publication History ----

function PublicationHistory({
  manifests,
  loading,
  expandedManifestId,
  onDownloadManifest,
  onToggleManifest,
}: {
  manifests: PublicationManifest[];
  loading: boolean;
  expandedManifestId: string | null;
  onDownloadManifest: (manifest: PublicationManifest) => void | Promise<void>;
  onToggleManifest: (id: string) => void;
}) {
  if (loading) {
    return (
      <div className="flex flex-col gap-2 mt-2">
        <p className="text-[10px] font-medium text-[#6f7f9a] uppercase tracking-wider">
          Publication History
        </p>
        <div className="animate-pulse h-16 bg-[#131721] rounded-md" />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-1.5 mt-2">
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-medium text-[#6f7f9a] uppercase tracking-wider">
          Publication History
        </p>
        <span className="text-[9px] text-[#6f7f9a]">{manifests.length}</span>
      </div>

      {manifests.length === 0 ? (
        <p className="text-[10px] text-[#6f7f9a] italic px-1">No publications yet</p>
      ) : (
        <div className="flex flex-col gap-1 max-h-[300px] overflow-y-auto">
          {manifests.map((manifest) => (
            <ManifestEntry
              key={manifest.id}
              manifest={manifest}
              expanded={expandedManifestId === manifest.id}
              onDownload={() => onDownloadManifest(manifest)}
              onToggle={() => onToggleManifest(manifest.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function ManifestEntry({
  manifest,
  expanded,
  onDownload,
  onToggle,
}: {
  manifest: PublicationManifest;
  expanded: boolean;
  onDownload: () => void;
  onToggle: () => void;
}) {
  const date = new Date(manifest.createdAt);
  const timeStr = date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

  return (
    <div className="rounded-md border border-[#2d3240]/60 bg-[#131721] overflow-hidden">
      <button
        onClick={onToggle}
        className="flex items-center gap-2 w-full px-3 py-2 text-left hover:bg-[#2d3240]/30 transition-colors"
      >
        {expanded ? (
          <IconChevronDown size={10} stroke={1.5} className="text-[#6f7f9a] shrink-0" />
        ) : (
          <IconChevronRight size={10} stroke={1.5} className="text-[#6f7f9a] shrink-0" />
        )}
        <span className="text-[10px] text-[#ece7dc] truncate flex-1">
          {TARGET_LABELS[manifest.target]}
        </span>
        <span className="text-[9px] text-[#6f7f9a] shrink-0">{timeStr}</span>
      </button>

      {expanded && (
        <div className="px-3 pb-2 flex flex-col gap-1 border-t border-[#2d3240]/40">
          <div className="flex justify-end pt-2">
            <button
              type="button"
              onClick={onDownload}
              className="inline-flex items-center gap-1 rounded-md border border-[#2d3240] px-2 py-1 text-[9px] font-mono text-[#6f7f9a] hover:text-[#ece7dc] hover:border-[#d4a84b]/30 transition-colors"
            >
              <IconDownload size={10} stroke={1.5} />
              Download Output
            </button>
          </div>
          <ManifestDetailRow label="ID" value={manifest.id.slice(0, 12) + "..."} />
          <ManifestDetailRow label="Source Hash" value={manifest.sourceHash.slice(0, 16) + "..."} mono />
          <ManifestDetailRow label="Output Hash" value={manifest.outputHash.slice(0, 16) + "..."} mono />
          <ManifestDetailRow
            label="Converter"
            value={`${manifest.converter.id} v${manifest.converter.version}`}
          />
          <ManifestDetailRow
            label="Validation"
            value={
              manifest.validationSnapshot.valid
                ? `Valid (${manifest.validationSnapshot.diagnosticCount} diagnostics)`
                : "Invalid"
            }
            highlight={!manifest.validationSnapshot.valid ? "error" : undefined}
          />
          {manifest.runSnapshot && (
            <ManifestDetailRow
              label="Lab Run"
              value={manifest.runSnapshot.passed ? "Passed" : "Failed"}
              highlight={!manifest.runSnapshot.passed ? "error" : "success"}
            />
          )}
          {manifest.signer && (
            <ManifestDetailRow
              label="Signer"
              value={`${manifest.signer.keyType}: ${manifest.signer.publicKey.slice(0, 12)}...`}
              mono
            />
          )}
          {manifest.receiptId && (
            <ManifestDetailRow label="Receipt" value={manifest.receiptId.slice(0, 12) + "..."} mono />
          )}
          {manifest.deployResponse && (
            <ManifestDetailRow
              label="Deploy"
              value={
                manifest.deployResponse.success
                  ? `Success${manifest.deployResponse.hash ? ` (${manifest.deployResponse.hash.slice(0, 8)}...)` : ""}`
                  : "Failed"
              }
              highlight={manifest.deployResponse.success ? "success" : "error"}
            />
          )}
        </div>
      )}
    </div>
  );
}

function ManifestDetailRow({
  label,
  value,
  mono,
  highlight,
}: {
  label: string;
  value: string;
  mono?: boolean;
  highlight?: "success" | "error";
}) {
  return (
    <div className="flex items-center justify-between gap-2 text-[9px] pt-1">
      <span className="text-[#6f7f9a] shrink-0">{label}</span>
      <span
        className={cn(
          "truncate text-right",
          mono && "font-mono",
          highlight === "success" && "text-[#3dbf84]",
          highlight === "error" && "text-[#c45c5c]",
          !highlight && "text-[#ece7dc]",
        )}
      >
        {value}
      </span>
    </div>
  );
}
