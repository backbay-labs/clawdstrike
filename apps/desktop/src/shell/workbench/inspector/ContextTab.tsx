/**
 * ContextTab - Metadata inspector panel for the currently selected entity.
 *
 * Reads selection state via useSelection() and renders a card-based layout
 * with header, metadata key-value pairs, tags, and related entity links.
 */
import { useCallback } from "react";
import { useSelection, useWorkbenchDispatch } from "@/shell/workbench/WorkbenchStateProvider";
import type { SelectionEntityType, SelectionState } from "@/shell/workbench/workbenchState";

// ── Badge Colors ────────────────────────────────────────────────────

const ENTITY_TYPE_COLORS: Record<NonNullable<SelectionEntityType>, string> = {
  file: "#4ade80",
  receipt: "#c8a84e",
  policy: "#818cf8",
  agent: "#f472b6",
  session: "#38bdf8",
  guard: "#fb923c",
};

// ── Metadata Field Definitions ──────────────────────────────────────

interface MetadataFieldDef {
  key: string;
  label: string;
}

const ENTITY_FIELDS: Record<NonNullable<SelectionEntityType>, MetadataFieldDef[]> = {
  file: [
    { key: "filePath", label: "Path" },
    { key: "fileSize", label: "Size" },
    { key: "language", label: "Language" },
    { key: "lastModified", label: "Modified" },
    { key: "workspaceRoot", label: "Workspace" },
  ],
  receipt: [
    { key: "receiptId", label: "Receipt ID" },
    { key: "verdict", label: "Verdict" },
    { key: "timestamp", label: "Timestamp" },
    { key: "guardCount", label: "Guards" },
    { key: "policyName", label: "Policy" },
  ],
  policy: [
    { key: "policyName", label: "Policy" },
    { key: "schemaVersion", label: "Schema" },
    { key: "guardCount", label: "Guards" },
    { key: "inheritanceChain", label: "Extends" },
  ],
  agent: [
    { key: "agentId", label: "Agent ID" },
    { key: "identity", label: "Identity" },
    { key: "delegationTokens", label: "Delegations" },
    { key: "activeSessions", label: "Sessions" },
  ],
  session: [
    { key: "sessionId", label: "Session ID" },
    { key: "createdAt", label: "Created" },
    { key: "lastActive", label: "Last Active" },
    { key: "status", label: "Status" },
  ],
  guard: [
    { key: "guardName", label: "Guard" },
    { key: "guardType", label: "Type" },
    { key: "lastResult", label: "Last Result" },
  ],
};

// ── Shared Styles ───────────────────────────────────────────────────

const styles = {
  muted: "var(--color-text-muted, #6b7280)",
  primary: "var(--color-text-primary, #e0e0e6)",
  border: "1px solid var(--color-border-subtle, #1a1d2e)",
} as const;

// ── Sub-Components ──────────────────────────────────────────────────

function EmptyState() {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        height: "100%",
        gap: 8,
        color: styles.muted,
        fontFamily: "monospace",
        fontSize: 11,
        padding: 16,
        textAlign: "center",
      }}
    >
      <span style={{ fontSize: 24, opacity: 0.4 }}>{"\u{1F50D}"}</span>
      Select an item to view details
    </div>
  );
}

function EntityTypeBadge({ entityType }: { entityType: NonNullable<SelectionEntityType> }) {
  const color = ENTITY_TYPE_COLORS[entityType];
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 6px",
        borderRadius: 3,
        background: `${color}22`,
        color,
        fontSize: 9,
        fontWeight: 600,
        fontFamily: "monospace",
        textTransform: "uppercase",
        letterSpacing: "0.08em",
        lineHeight: "14px",
        flexShrink: 0,
      }}
    >
      {entityType}
    </span>
  );
}

function HeaderSection({
  entityType,
  entityId,
}: {
  entityType: NonNullable<SelectionEntityType>;
  entityId: string;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "10px 12px",
        borderBottom: styles.border,
      }}
    >
      <EntityTypeBadge entityType={entityType} />
      <span
        style={{
          fontFamily: "monospace",
          fontSize: 11,
          fontWeight: 600,
          color: styles.primary,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          minWidth: 0,
        }}
        title={entityId}
      >
        {entityId}
      </span>
    </div>
  );
}

function VerdictValue({ value }: { value: string }) {
  const isAllow = value.toLowerCase() === "allow";
  const color = isAllow ? "#4ade80" : "#f87171";
  return (
    <span
      style={{
        color,
        fontWeight: 600,
        textTransform: "uppercase",
        fontSize: 10,
        letterSpacing: "0.04em",
      }}
    >
      {value}
    </span>
  );
}

function MetadataRow({ label, value }: { label: string; value: unknown }) {
  const displayValue = value == null ? "\u2014" : String(value);

  return (
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "baseline",
        gap: 8,
        padding: "3px 0",
      }}
    >
      <span
        style={{
          fontFamily: "monospace",
          fontSize: 10,
          color: styles.muted,
          textTransform: "uppercase",
          letterSpacing: "0.04em",
          flexShrink: 0,
        }}
      >
        {label}
      </span>
      <span
        style={{
          fontFamily: "monospace",
          fontSize: 11,
          color: styles.primary,
          textAlign: "right",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          minWidth: 0,
        }}
        title={displayValue}
      >
        {displayValue}
      </span>
    </div>
  );
}

function MetadataSection({
  entityType,
  metadata,
}: {
  entityType: NonNullable<SelectionEntityType>;
  metadata: Record<string, unknown> | undefined;
}) {
  const fields = ENTITY_FIELDS[entityType];
  if (!fields || fields.length === 0) return null;

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 2,
        padding: "8px 12px",
        borderBottom: styles.border,
      }}
    >
      <span
        style={{
          fontFamily: "monospace",
          fontSize: 9,
          color: styles.muted,
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          marginBottom: 4,
        }}
      >
        Metadata
      </span>
      {fields.map((field) => {
        const rawValue = metadata?.[field.key];

        // Special rendering for verdict fields
        if (field.key === "verdict" && rawValue != null && typeof rawValue === "string") {
          return (
            <div
              key={field.key}
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "baseline",
                gap: 8,
                padding: "3px 0",
              }}
            >
              <span
                style={{
                  fontFamily: "monospace",
                  fontSize: 10,
                  color: styles.muted,
                  textTransform: "uppercase",
                  letterSpacing: "0.04em",
                  flexShrink: 0,
                }}
              >
                {field.label}
              </span>
              <VerdictValue value={rawValue} />
            </div>
          );
        }

        // Arrays render as comma-separated
        const value = Array.isArray(rawValue) ? rawValue.join(" \u2192 ") : rawValue;
        return <MetadataRow key={field.key} label={field.label} value={value} />;
      })}
    </div>
  );
}

function TagsSection({ tags }: { tags: unknown[] }) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 6,
        padding: "8px 12px",
        borderBottom: styles.border,
      }}
    >
      <span
        style={{
          fontFamily: "monospace",
          fontSize: 9,
          color: styles.muted,
          textTransform: "uppercase",
          letterSpacing: "0.06em",
        }}
      >
        Tags
      </span>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
        {tags.map((tag, i) => (
          <span
            key={i}
            style={{
              display: "inline-block",
              padding: "2px 6px",
              borderRadius: 3,
              background: "rgba(255,255,255,0.06)",
              color: styles.primary,
              fontFamily: "monospace",
              fontSize: 10,
              lineHeight: "14px",
            }}
          >
            {String(tag)}
          </span>
        ))}
      </div>
    </div>
  );
}

interface RelatedEntity {
  entityType: NonNullable<SelectionEntityType>;
  entityId: string;
  label?: string;
}

function RelatedEntitiesSection({
  entities,
  onSelect,
}: {
  entities: RelatedEntity[];
  onSelect: (selection: SelectionState) => void;
}) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 6,
        padding: "8px 12px",
      }}
    >
      <span
        style={{
          fontFamily: "monospace",
          fontSize: 9,
          color: styles.muted,
          textTransform: "uppercase",
          letterSpacing: "0.06em",
        }}
      >
        Related
      </span>
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {entities.map((entity, i) => {
          const color = ENTITY_TYPE_COLORS[entity.entityType];
          return (
            <button
              key={i}
              onClick={() =>
                onSelect({
                  entityType: entity.entityType,
                  entityId: entity.entityId,
                })
              }
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                padding: "4px 6px",
                borderRadius: 3,
                border: "none",
                background: "rgba(255,255,255,0.03)",
                cursor: "pointer",
                textAlign: "left",
                width: "100%",
              }}
            >
              <span
                style={{
                  display: "inline-block",
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  background: color,
                  flexShrink: 0,
                }}
              />
              <span
                style={{
                  fontFamily: "monospace",
                  fontSize: 10,
                  color: styles.primary,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  minWidth: 0,
                }}
              >
                {entity.label ?? entity.entityId}
              </span>
              <span
                style={{
                  fontFamily: "monospace",
                  fontSize: 9,
                  color: styles.muted,
                  textTransform: "uppercase",
                  letterSpacing: "0.04em",
                  flexShrink: 0,
                  marginLeft: "auto",
                }}
              >
                {entity.entityType}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ── Main Component ──────────────────────────────────────────────────

export function ContextTab() {
  const selection = useSelection();
  const dispatch = useWorkbenchDispatch();

  const handleSelectRelated = useCallback(
    (newSelection: SelectionState) => {
      dispatch({ type: "SET_SELECTION", payload: newSelection });
    },
    [dispatch],
  );

  if (!selection.entityType || !selection.entityId) {
    return <EmptyState />;
  }

  const { entityType, entityId, metadata } = selection;

  const tags =
    metadata?.tags != null && Array.isArray(metadata.tags) && metadata.tags.length > 0
      ? metadata.tags
      : null;

  const relatedEntities =
    metadata?.relatedEntities != null && Array.isArray(metadata.relatedEntities) && metadata.relatedEntities.length > 0
      ? (metadata.relatedEntities as RelatedEntity[])
      : null;

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 0,
        height: "100%",
        fontFamily: "monospace",
        fontSize: 11,
        color: styles.primary,
        overflowY: "auto",
      }}
    >
      <HeaderSection entityType={entityType} entityId={entityId} />
      <MetadataSection entityType={entityType} metadata={metadata} />
      {tags && <TagsSection tags={tags} />}
      {relatedEntities && (
        <RelatedEntitiesSection
          entities={relatedEntities}
          onSelect={handleSelectRelated}
        />
      )}
    </div>
  );
}
