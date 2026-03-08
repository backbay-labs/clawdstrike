/**
 * CompanionTab - AI-powered contextual suggestions panel (experimental).
 *
 * Reads selection state via useSelection() and renders structured suggestion
 * sections based on the selected entity type. Uses no real AI backend --
 * this is a UX pattern placeholder that demonstrates the companion surface.
 */
import { useSelection } from "@/shell/workbench/WorkbenchStateProvider";
import type { SelectionEntityType } from "@/shell/workbench/workbenchState";

// ── Entity Type Colors (same as ContextTab) ─────────────────────────

const ENTITY_TYPE_COLORS: Record<NonNullable<SelectionEntityType>, string> = {
  file: "#4ade80",
  receipt: "#c8a84e",
  policy: "#818cf8",
  agent: "#f472b6",
  session: "#38bdf8",
  guard: "#fb923c",
};

// ── Shared Styles ───────────────────────────────────────────────────

const styles = {
  muted: "var(--color-text-muted, #6b7280)",
  primary: "var(--color-text-primary, #e0e0e6)",
  border: "1px solid var(--color-border-subtle, #1a1d2e)",
  gold: "var(--color-origin-gold, #c8a84e)",
} as const;

// ── Documentation Descriptions ──────────────────────────────────────

const DOCUMENTATION_HINTS: Record<NonNullable<SelectionEntityType>, string> = {
  file: "Related documentation for this file type",
  receipt: "Receipt format documentation, verification guides",
  policy: "Policy authoring guide, guard configuration reference",
  agent: "Agent identity management, delegation protocol",
  session: "Session lifecycle, connection management",
  guard: "Guard implementation guide, custom guard API",
};

// ── Mock Similar Items ──────────────────────────────────────────────

interface SimilarItem {
  entityType: NonNullable<SelectionEntityType>;
  name: string;
  similarity: number;
}

const MOCK_SIMILAR_ITEMS: Record<NonNullable<SelectionEntityType>, SimilarItem[]> = {
  file: [
    { entityType: "file", name: "config.yaml", similarity: 0.94 },
    { entityType: "file", name: "schema.json", similarity: 0.87 },
    { entityType: "policy", name: "default.yaml", similarity: 0.81 },
  ],
  receipt: [
    { entityType: "receipt", name: "receipt_a3f9c1", similarity: 0.92 },
    { entityType: "receipt", name: "receipt_d7e244", similarity: 0.88 },
  ],
  policy: [
    { entityType: "policy", name: "strict.yaml", similarity: 0.95 },
    { entityType: "policy", name: "ai-agent.yaml", similarity: 0.89 },
    { entityType: "guard", name: "ForbiddenPathGuard", similarity: 0.82 },
  ],
  agent: [
    { entityType: "agent", name: "agent_primary", similarity: 0.91 },
    { entityType: "agent", name: "agent_delegate_01", similarity: 0.84 },
  ],
  session: [
    { entityType: "session", name: "sess_f8a21b", similarity: 0.93 },
    { entityType: "session", name: "sess_c4d907", similarity: 0.86 },
    { entityType: "agent", name: "agent_primary", similarity: 0.80 },
  ],
  guard: [
    { entityType: "guard", name: "ShellCommandGuard", similarity: 0.93 },
    { entityType: "guard", name: "EgressAllowlistGuard", similarity: 0.87 },
  ],
};

// ── Recommendation Definitions ──────────────────────────────────────

const RECOMMENDATIONS: Record<NonNullable<SelectionEntityType>, string[]> = {
  file: ["Consider adding to watchlist", "Run security scan"],
  receipt: ["Export receipt chain", "Verify Merkle proof"],
  policy: ["Test in sandbox", "Check inheritance chain"],
  agent: ["Review delegation tokens", "Audit session history"],
  session: ["Check for idle sessions", "Review recent receipts"],
  guard: ["Run guard benchmark", "Check false positive rate"],
};

// ── Sub-Components ──────────────────────────────────────────────────

function BetaHeader() {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 6,
        padding: "10px 12px",
        borderBottom: styles.border,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span
          style={{
            display: "inline-block",
            padding: "2px 6px",
            borderRadius: 3,
            background: "rgba(200,168,78,0.15)",
            color: styles.gold,
            fontSize: 9,
            fontWeight: 600,
            fontFamily: "monospace",
            textTransform: "uppercase",
            letterSpacing: "0.08em",
            lineHeight: "14px",
            flexShrink: 0,
          }}
        >
          beta
        </span>
        <span
          style={{
            fontFamily: "monospace",
            fontSize: 11,
            fontWeight: 600,
            color: styles.primary,
          }}
        >
          AI Companion
        </span>
      </div>
      <span
        style={{
          fontFamily: "monospace",
          fontSize: 10,
          color: styles.muted,
          lineHeight: "14px",
        }}
      >
        Contextual suggestions powered by analysis of your workspace.
      </span>
    </div>
  );
}

function SectionHeader({ label }: { label: string }) {
  return (
    <span
      style={{
        fontFamily: "monospace",
        fontSize: 10,
        color: styles.muted,
        textTransform: "uppercase",
        letterSpacing: "0.08em",
        marginBottom: 4,
      }}
    >
      {label}
    </span>
  );
}

function EntityTypeBadge({ entityType }: { entityType: NonNullable<SelectionEntityType> }) {
  const color = ENTITY_TYPE_COLORS[entityType];
  return (
    <span
      style={{
        display: "inline-block",
        padding: "1px 5px",
        borderRadius: 3,
        background: `${color}22`,
        color,
        fontSize: 9,
        fontWeight: 600,
        fontFamily: "monospace",
        textTransform: "uppercase",
        letterSpacing: "0.06em",
        lineHeight: "14px",
        flexShrink: 0,
      }}
    >
      {entityType}
    </span>
  );
}

function SimilarityBar({
  similarity,
  color,
}: {
  similarity: number;
  color: string;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 6,
        width: "100%",
      }}
    >
      <div
        style={{
          flex: 1,
          height: 3,
          borderRadius: 2,
          background: "rgba(255,255,255,0.06)",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            width: `${similarity * 100}%`,
            height: "100%",
            borderRadius: 2,
            background: color,
            opacity: 0.7,
          }}
        />
      </div>
      <span
        style={{
          fontFamily: "monospace",
          fontSize: 9,
          color: styles.muted,
          flexShrink: 0,
          minWidth: 28,
          textAlign: "right",
        }}
      >
        {(similarity * 100).toFixed(0)}%
      </span>
    </div>
  );
}

function DocumentationSection({
  entityType,
}: {
  entityType: NonNullable<SelectionEntityType>;
}) {
  const hint = DOCUMENTATION_HINTS[entityType];
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
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ fontSize: 12, opacity: 0.5 }}>{"\u{1F50D}"}</span>
        <SectionHeader label="Documentation" />
      </div>
      <div
        style={{
          padding: 8,
          borderRadius: 8,
          border: styles.border,
          background: "rgba(255,255,255,0.02)",
        }}
      >
        <span
          style={{
            fontFamily: "monospace",
            fontSize: 11,
            color: styles.primary,
            lineHeight: "16px",
          }}
        >
          {hint}
        </span>
      </div>
    </div>
  );
}

function SimilarItemsSection({
  entityType,
}: {
  entityType: NonNullable<SelectionEntityType>;
}) {
  const items = MOCK_SIMILAR_ITEMS[entityType];
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
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ fontSize: 12, opacity: 0.5 }}>{"\u{1F4DA}"}</span>
        <SectionHeader label="Similar Items" />
      </div>
      <span
        style={{
          fontFamily: "monospace",
          fontSize: 10,
          color: styles.muted,
          fontStyle: "italic",
          marginBottom: 2,
        }}
      >
        Finding similar {entityType}s...
      </span>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {items.map((item, i) => {
          const color = ENTITY_TYPE_COLORS[item.entityType];
          return (
            <div
              key={i}
              style={{
                display: "flex",
                flexDirection: "column",
                gap: 4,
                padding: 8,
                borderRadius: 8,
                border: styles.border,
                background: "rgba(255,255,255,0.02)",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <EntityTypeBadge entityType={item.entityType} />
                <span
                  style={{
                    fontFamily: "monospace",
                    fontSize: 11,
                    color: styles.primary,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    minWidth: 0,
                  }}
                >
                  {item.name}
                </span>
              </div>
              <SimilarityBar similarity={item.similarity} color={color} />
            </div>
          );
        })}
      </div>
    </div>
  );
}

function RecommendationsSection({
  entityType,
}: {
  entityType: NonNullable<SelectionEntityType>;
}) {
  const recs = RECOMMENDATIONS[entityType];
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 6,
        padding: "8px 12px",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ fontSize: 12, opacity: 0.5 }}>{"\u{1F4A1}"}</span>
        <SectionHeader label="Recommendations" />
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {recs.map((rec, i) => (
          <div
            key={i}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: 8,
              borderRadius: 8,
              border: styles.border,
              background: "rgba(255,255,255,0.02)",
              cursor: "default",
            }}
          >
            <span
              style={{
                display: "inline-block",
                width: 4,
                height: 4,
                borderRadius: "50%",
                background: styles.gold,
                flexShrink: 0,
                opacity: 0.6,
              }}
            />
            <span
              style={{
                fontFamily: "monospace",
                fontSize: 11,
                color: styles.primary,
                lineHeight: "16px",
              }}
            >
              {rec}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function EmptySelectionSuggestions() {
  const categories = [
    { label: "Documentation", icon: "\u{1F50D}" },
    { label: "Similar Items", icon: "\u{1F4DA}" },
    { label: "Recommendations", icon: "\u{1F4A1}" },
  ];

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 0,
      }}
    >
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: 8,
          padding: "24px 16px 16px",
          color: styles.muted,
          fontFamily: "monospace",
          fontSize: 11,
          textAlign: "center",
        }}
      >
        Select an entity to get contextual suggestions
      </div>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: 6,
          padding: "8px 12px",
        }}
      >
        {categories.map((cat) => (
          <div
            key={cat.label}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: 8,
              borderRadius: 8,
              border: styles.border,
              background: "rgba(255,255,255,0.02)",
              opacity: 0.4,
            }}
          >
            <span style={{ fontSize: 12 }}>{cat.icon}</span>
            <span
              style={{
                fontFamily: "monospace",
                fontSize: 10,
                color: styles.muted,
                textTransform: "uppercase",
                letterSpacing: "0.08em",
              }}
            >
              {cat.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Main Component ──────────────────────────────────────────────────

export function CompanionTab() {
  const selection = useSelection();

  const hasSelection = selection.entityType != null && selection.entityId != null;

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
      <BetaHeader />
      {hasSelection ? (
        <>
          <DocumentationSection entityType={selection.entityType!} />
          <SimilarItemsSection entityType={selection.entityType!} />
          <RecommendationsSection entityType={selection.entityType!} />
        </>
      ) : (
        <EmptySelectionSuggestions />
      )}
    </div>
  );
}
