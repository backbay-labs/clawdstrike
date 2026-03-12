import { useState, useCallback, useMemo, useEffect, useRef } from "react";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { useToast } from "@/components/ui/toast";
import {
  renameOriginProfileIdInPolicy,
  renameOriginProfileIdInSavedPolicy,
} from "@/lib/workbench/origin-profile-utils";
import {
  ORIGIN_ACTOR_TYPE_OPTIONS as ACTOR_TYPE_OPTIONS,
  ORIGIN_PROVENANCE_OPTIONS as PROVENANCE_OPTIONS,
  ORIGIN_PROVIDER_OPTIONS as PROVIDERS,
  ORIGIN_SPACE_TYPE_OPTIONS as SPACE_TYPES,
  ORIGIN_VISIBILITY_OPTIONS as VISIBILITY_OPTIONS,
  isCustomOriginChoice as isCustomChoice,
} from "@/lib/workbench/origin-options";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import type {
  OriginsConfig,
  OriginProfile,
  OriginMatch,
  OriginProvider,
  OriginDefaultBehavior,
  SpaceType,
  Visibility,
  ProvenanceConfidence,
  ActorType,
  McpToolConfig,
  EgressAllowlistConfig,
  OriginDataPolicy,
  OriginBudgets,
  BridgePolicy,
  BridgeTarget,
  SavedPolicy,
} from "@/lib/workbench/types";
import {
  IconRoute,
  IconPlus,
  IconTrash,
  IconCopy,
  IconBrandSlack,
  IconBrandGithub,
  IconUsers,
  IconTicket,
  IconMail,
  IconBrandDiscord,
  IconWebhook,
  IconWorld,
  IconShieldLock,
  IconNetwork,
  IconDatabase,
  IconGauge,
  IconArrowsShuffle,
  IconCheck,
  IconX,
  IconSearch,
  IconChevronRight,
  IconChevronUp,
  IconChevronDown,
  IconInfoCircle,
  IconAlertTriangle,
  IconExternalLink,
  IconTool,
  IconDownload,
  IconCode,
} from "@tabler/icons-react";

// ---------------------------------------------------------------------------
// Local profile library — stored in localStorage, independent of any policy
// ---------------------------------------------------------------------------

const STORAGE_KEY = "clawdstrike:origin-profile-library";

function loadLibrary(): OriginProfile[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveLibrary(profiles: OriginProfile[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(profiles));
}

function useProfileLibrary() {
  const [profiles, setProfiles] = useState<OriginProfile[]>(loadLibrary);

  const persist = useCallback(
    (updater: (prev: OriginProfile[]) => OriginProfile[]) => {
      setProfiles((prev) => {
        const next = updater(prev);
        saveLibrary(next);
        return next;
      });
    },
    [],
  );

  const add = useCallback(
    (profile: OriginProfile) => {
      persist((prev) => [...prev, profile]);
    },
    [persist],
  );

  const update = useCallback(
    (id: string, updated: OriginProfile) => {
      persist((prev) => prev.map((p) => (p.id === id ? updated : p)));
    },
    [persist],
  );

  const remove = useCallback(
    (id: string) => {
      persist((prev) => prev.filter((p) => p.id !== id));
    },
    [persist],
  );

  const clone = useCallback(
    (id: string) => {
      const src = profiles.find((profile) => profile.id === id);
      if (!src) return undefined;

      const baseId = src.id.replace(/-copy-[a-f0-9]{6}$/, "");
      const cloned: OriginProfile = {
        ...structuredClone(src),
        id: `${baseId}-copy-${crypto.randomUUID().slice(0, 6)}`,
      };

      persist((prev) => [...prev, cloned]);
      return cloned.id;
    },
    [persist, profiles],
  );

  const reorder = useCallback(
    (fromIndex: number, toIndex: number) => {
      persist((prev) => {
        if (
          fromIndex < 0 ||
          toIndex < 0 ||
          fromIndex >= prev.length ||
          toIndex >= prev.length
        )
          return prev;
        const next = [...prev];
        const [moved] = next.splice(fromIndex, 1);
        next.splice(toIndex, 0, moved);
        return next;
      });
    },
    [persist],
  );

  return { profiles, add, update, remove, clone, reorder };
}

// ---------------------------------------------------------------------------
// Provider metadata
// ---------------------------------------------------------------------------

const PROVIDER_META: Record<
  OriginProvider,
  { label: string; icon: typeof IconBrandSlack; color: string; desc: string }
> = {
  slack: {
    label: "Slack",
    icon: IconBrandSlack,
    color: "#4A154B",
    desc: "Slack workspace channels, threads, and DMs",
  },
  github: {
    label: "GitHub",
    icon: IconBrandGithub,
    color: "#6e7681",
    desc: "GitHub issues, pull requests, and discussions",
  },
  teams: {
    label: "Teams",
    icon: IconUsers,
    color: "#464EB8",
    desc: "Microsoft Teams channels and chats",
  },
  jira: {
    label: "Jira",
    icon: IconTicket,
    color: "#0052CC",
    desc: "Jira issues and project boards",
  },
  email: {
    label: "Email",
    icon: IconMail,
    color: "#8b7355",
    desc: "Email threads and inboxes",
  },
  discord: {
    label: "Discord",
    icon: IconBrandDiscord,
    color: "#5865F2",
    desc: "Discord servers, channels, and threads",
  },
  webhook: {
    label: "Webhook",
    icon: IconWebhook,
    color: "#6f7f9a",
    desc: "External webhook integrations and API calls",
  },
  cli: {
    label: "CLI",
    icon: IconCode,
    color: "#5b8def",
    desc: "Local terminal and command-line initiated actions",
  },
  api: {
    label: "API",
    icon: IconNetwork,
    color: "#3dbf84",
    desc: "Direct API clients and service integrations",
  },
};

function getProviderMeta(provider: OriginProvider | string | undefined) {
  if (!provider) return null;
  return PROVIDER_META[provider as OriginProvider] ?? null;
}

function getProviderIcon(provider: OriginProvider | string | undefined) {
  return getProviderMeta(provider)?.icon ?? IconWorld;
}

function getProviderColor(provider: OriginProvider | string | undefined) {
  return getProviderMeta(provider)?.color ?? "#6f7f9a";
}

// ---------------------------------------------------------------------------
// Template blueprints
// ---------------------------------------------------------------------------

interface ProfileBlueprint {
  name: string;
  description: string;
  tags: string[];
  profile: OriginProfile;
}

const BLUEPRINTS: ProfileBlueprint[] = [
  {
    name: "Slack Incident Room",
    description:
      "Internal incident channel with elevated posture. Broad MCP tool access for responders, restricted data sharing, moderate budgets.",
    tags: ["incident-response", "internal", "elevated"],
    profile: {
      id: "slack-incident",
      match_rules: {
        provider: "slack",
        space_type: "channel",
        visibility: "internal",
        tags: ["incident"],
        provenance_confidence: "strong",
      },
      posture: "elevated",
      mcp: {
        allow: ["*"],
        block: [],
        default_action: "allow",
      },
      egress: {
        allow: ["*.internal.company.com", "api.pagerduty.com", "api.opsgenie.com"],
        block: [],
        default_action: "block",
      },
      data: {
        allow_external_sharing: false,
        redact_before_send: true,
        block_sensitive_outputs: false,
      },
      budgets: {
        mcp_tool_calls: 50,
        egress_calls: 30,
        shell_commands: 10,
      },
      bridge_policy: {
        allow_cross_origin: true,
        require_approval: false,
      },
      explanation:
        "Incident responders need broad tool access but restricted data sharing. Internal channels with incident tags get elevated permissions.",
    },
  },
  {
    name: "GitHub PR Review",
    description:
      "Pull request context with code-focused guards. Tight egress, generous MCP for code tools, no external sharing.",
    tags: ["code-review", "development", "restricted-egress"],
    profile: {
      id: "github-pr",
      match_rules: {
        provider: "github",
        space_type: "pull_request",
        visibility: "internal",
        provenance_confidence: "strong",
      },
      posture: "standard",
      mcp: {
        allow: ["code-*", "lint-*", "test-*", "review-*"],
        block: ["deploy-*", "infra-*"],
        default_action: "block",
      },
      egress: {
        allow: ["api.github.com", "*.githubusercontent.com"],
        block: [],
        default_action: "block",
      },
      data: {
        allow_external_sharing: false,
        redact_before_send: false,
        block_sensitive_outputs: true,
      },
      budgets: {
        mcp_tool_calls: 100,
        egress_calls: 20,
        shell_commands: 5,
      },
      bridge_policy: {
        allow_cross_origin: false,
        require_approval: true,
      },
      explanation:
        "Code review context grants broad code tooling but blocks deployment and infrastructure tools. Egress locked to GitHub only.",
    },
  },
  {
    name: "External Webhook",
    description:
      "Minimal trust for external API integrations. Strict budgets, no cross-origin, approval required for everything sensitive.",
    tags: ["external", "minimal-trust", "strict"],
    profile: {
      id: "external-webhook",
      match_rules: {
        provider: "webhook",
        provenance_confidence: "weak",
      },
      posture: "restricted",
      mcp: {
        allow: [],
        block: ["*"],
        default_action: "block",
      },
      egress: {
        allow: [],
        block: [],
        default_action: "block",
      },
      data: {
        allow_external_sharing: false,
        redact_before_send: true,
        block_sensitive_outputs: true,
      },
      budgets: {
        mcp_tool_calls: 5,
        egress_calls: 3,
        shell_commands: 0,
      },
      bridge_policy: {
        allow_cross_origin: false,
        require_approval: true,
      },
      explanation:
        "External webhooks have minimal trust. All tool access blocked by default, strict budgets, and approval required for cross-origin communication.",
    },
  },
  {
    name: "Teams Internal Chat",
    description:
      "Standard internal collaboration. Moderate permissions, standard data controls, reasonable budgets for daily work.",
    tags: ["collaboration", "internal", "standard"],
    profile: {
      id: "teams-internal",
      match_rules: {
        provider: "teams",
        space_type: "channel",
        visibility: "internal",
        provenance_confidence: "medium",
      },
      posture: "standard",
      mcp: {
        allow: ["search-*", "read-*", "summarize-*"],
        block: ["deploy-*", "delete-*", "admin-*"],
        default_action: "block",
      },
      egress: {
        allow: ["graph.microsoft.com", "*.sharepoint.com"],
        block: [],
        default_action: "block",
      },
      data: {
        allow_external_sharing: false,
        redact_before_send: false,
        block_sensitive_outputs: false,
      },
      budgets: {
        mcp_tool_calls: 30,
        egress_calls: 15,
        shell_commands: 3,
      },
      bridge_policy: {
        allow_cross_origin: true,
        require_approval: true,
      },
      explanation:
        "Standard internal Teams channel with read-heavy tool access. Destructive and admin operations blocked. Cross-origin bridges require approval.",
    },
  },
];

// ---------------------------------------------------------------------------
// Utility: count overrides on a profile
// ---------------------------------------------------------------------------

function countOverrides(profile: OriginProfile): number {
  let n = 0;
  if (profile.mcp) n++;
  if (profile.egress) n++;
  if (profile.data) n++;
  if (profile.budgets) n++;
  if (profile.bridge_policy) n++;
  return n;
}

function buildMatchSummary(match: OriginMatch | undefined): string {
  if (!match) return "No match rules — catches all origins";
  const parts: string[] = [];
  if (match.provider) parts.push(getProviderMeta(match.provider)?.label ?? match.provider);
  if (match.space_type) parts.push(match.space_type.replace(/_/g, " "));
  if (match.visibility) parts.push(match.visibility);
  if (match.tags?.length) parts.push(`tags: ${match.tags.join(", ")}`);
  if (match.provenance_confidence) parts.push(`provenance: ${match.provenance_confidence}`);
  return parts.length > 0 ? parts.join(" · ") : "Catch-all (no filters)";
}

// ---------------------------------------------------------------------------
// Sidebar profile card
// ---------------------------------------------------------------------------

function ProfileListItem({
  profile,
  isSelected,
  onSelect,
  onMoveUp,
  onMoveDown,
  isFirst,
  isLast,
}: {
  profile: OriginProfile;
  isSelected: boolean;
  onSelect: () => void;
  onMoveUp?: () => void;
  onMoveDown?: () => void;
  isFirst?: boolean;
  isLast?: boolean;
}) {
  const ProviderIcon = getProviderIcon(profile.match_rules?.provider);
  const providerColor = getProviderColor(profile.match_rules?.provider);
  const overrideCount = countOverrides(profile);

  return (
    <div
      className={cn(
        "w-full text-left rounded-lg px-3 py-2.5 transition-all duration-150 border-l-2 group cursor-pointer",
        isSelected
          ? "bg-[#131721] border-l-[#d4a84b] shadow-[0_0_8px_rgba(212,168,75,0.06)]"
          : "border-l-transparent hover:bg-[#131721]/40",
      )}
      onClick={onSelect}
    >
      <div className="flex items-center gap-2.5">
        <div
          className="w-7 h-7 rounded-md flex items-center justify-center shrink-0"
          style={{ backgroundColor: `${providerColor}15` }}
        >
          <ProviderIcon size={15} stroke={1.5} style={{ color: providerColor }} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5">
            <span
              className={cn(
                "text-xs font-mono font-medium truncate",
                isSelected ? "text-[#ece7dc]" : "text-[#ece7dc]/80",
              )}
            >
              {profile.id}
            </span>
            {overrideCount > 0 && (
              <span className="shrink-0 text-[9px] font-mono text-[#6f7f9a] bg-[#131721] px-1 py-0 rounded">
                {overrideCount}
              </span>
            )}
          </div>
          <p className="text-[10px] text-[#6f7f9a] truncate mt-0.5">
            {buildMatchSummary(profile.match_rules)}
          </p>
        </div>
        {/* Reorder buttons — visible on hover or when selected */}
        <div
          className={cn(
            "flex flex-col gap-0.5 shrink-0",
            isSelected ? "opacity-100" : "opacity-0 group-hover:opacity-100",
            "transition-opacity duration-150",
          )}
        >
          <button
            onClick={(e) => {
              e.stopPropagation();
              onMoveUp?.();
            }}
            disabled={isFirst}
            className={cn(
              "p-0.5 rounded transition-colors",
              isFirst
                ? "text-[#6f7f9a]/20 cursor-not-allowed"
                : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#2d3240]",
            )}
            title="Move up (higher priority)"
          >
            <IconChevronUp size={10} stroke={1.5} />
          </button>
          <button
            onClick={(e) => {
              e.stopPropagation();
              onMoveDown?.();
            }}
            disabled={isLast}
            className={cn(
              "p-0.5 rounded transition-colors",
              isLast
                ? "text-[#6f7f9a]/20 cursor-not-allowed"
                : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#2d3240]",
            )}
            title="Move down (lower priority)"
          >
            <IconChevronDown size={10} stroke={1.5} />
          </button>
        </div>
        <IconChevronRight
          size={12}
          stroke={1.5}
          className={cn(
            "shrink-0 transition-all duration-150",
            isSelected ? "text-[#d4a84b]" : "text-[#6f7f9a]/30 group-hover:text-[#6f7f9a]",
          )}
        />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Blueprint card (templates)
// ---------------------------------------------------------------------------

function BlueprintCard({
  blueprint,
  onAdd,
}: {
  blueprint: ProfileBlueprint;
  onAdd: () => void;
}) {
  const ProviderIcon = getProviderIcon(blueprint.profile.match_rules?.provider);
  const providerColor = getProviderColor(blueprint.profile.match_rules?.provider);
  const overrideCount = countOverrides(blueprint.profile);

  return (
    <button
      onClick={onAdd}
      className="w-full text-left rounded-lg px-3 py-2.5 border border-dashed border-[#2d3240] hover:border-[#d4a84b]/30 hover:bg-[#131721]/30 transition-all duration-150 group"
    >
      <div className="flex items-center gap-2.5">
        <ProviderIcon
          size={14}
          stroke={1.5}
          style={{ color: providerColor }}
          className="shrink-0 opacity-60 group-hover:opacity-100 transition-opacity"
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] font-medium text-[#ece7dc]/70 group-hover:text-[#ece7dc] transition-colors">
              {blueprint.name}
            </span>
            <span className="shrink-0 text-[8px] font-mono text-[#6f7f9a]/40 bg-[#131721]/50 px-1 rounded">
              {overrideCount} overrides
            </span>
          </div>
          <p className="text-[9px] text-[#6f7f9a] truncate mt-0.5">
            {blueprint.description}
          </p>
        </div>
        <IconPlus
          size={12}
          stroke={1.5}
          className="shrink-0 text-[#6f7f9a] opacity-0 group-hover:opacity-100 transition-opacity"
        />
      </div>
    </button>
  );
}

// ---------------------------------------------------------------------------
// Info callout
// ---------------------------------------------------------------------------

function InfoCallout({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-[#2d3240]/50 bg-[#131721]/20 px-3.5 py-3">
      <div className="flex items-start gap-2">
        <IconInfoCircle
          size={13}
          stroke={1.5}
          className="text-[#d4a84b]/60 shrink-0 mt-0.5"
        />
        <div>
          <span className="text-[10px] font-semibold text-[#ece7dc]/70">
            {title}
          </span>
          <p className="text-[10px] text-[#6f7f9a]/70 leading-relaxed mt-0.5">
            {children}
          </p>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Section wrapper for detail view
// ---------------------------------------------------------------------------

function DetailSection({
  icon: Icon,
  title,
  description,
  color = "#d4a84b",
  children,
  onToggle,
  enabled,
}: {
  icon: typeof IconShieldLock;
  title: string;
  description: string;
  color?: string;
  children: React.ReactNode;
  onToggle?: (enabled: boolean) => void;
  enabled?: boolean;
}) {
  return (
    <div>
      <div className="flex items-center gap-2 mb-1.5">
        <Icon size={13} stroke={1.5} style={{ color }} />
        <h3 className="text-[11px] font-semibold uppercase tracking-wider text-[#ece7dc]/70 flex-1">
          {title}
        </h3>
        {onToggle !== undefined && (
          <Switch
            checked={enabled ?? false}
            onCheckedChange={onToggle}
            className="data-checked:bg-[#d4a84b]"
            size="sm"
          />
        )}
      </div>
      <p className="text-[10px] text-[#6f7f9a]/60 leading-relaxed mb-3">
        {description}
      </p>
      {enabled === false ? (
        <div className="rounded-lg border border-dashed border-[#2d3240]/50 px-3.5 py-4 text-center">
          <p className="text-[10px] text-[#6f7f9a]/40">
            Not configured — toggle to enable
          </p>
        </div>
      ) : (
        children
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Shared micro-components for field editing
// ---------------------------------------------------------------------------

function FieldRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-center gap-3 px-3 py-2">
      <span className="text-[10px] text-[#6f7f9a] w-28 shrink-0">{label}</span>
      <div className="flex-1">{children}</div>
    </div>
  );
}

function ToggleRow({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <div className="flex items-center gap-3 px-3 py-2">
      <span className="text-[10px] text-[#6f7f9a] flex-1">{label}</span>
      <Switch
        checked={checked}
        onCheckedChange={(v) => onChange(!!v)}
        className="data-checked:bg-[#d4a84b]"
        size="sm"
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Match rules editor
// ---------------------------------------------------------------------------

function MatchRulesEditor({
  match,
  onChange,
}: {
  match: OriginMatch;
  onChange: (updated: OriginMatch) => void;
}) {
  const patch = useCallback(
    (p: Partial<OriginMatch>) => onChange({ ...match, ...p }),
    [match, onChange],
  );

  // C7: Track custom mode for provider and space_type dropdowns
  const [customProviderMode, setCustomProviderMode] = useState(() =>
    isCustomChoice(match.provider, PROVIDERS),
  );
  const [customProviderDraft, setCustomProviderDraft] = useState(
    () => match.provider ?? "",
  );
  const customProviderModeRef = useRef(customProviderMode);
  const [customSpaceTypeMode, setCustomSpaceTypeMode] = useState(() =>
    isCustomChoice(match.space_type, SPACE_TYPES),
  );
  const [customSpaceTypeDraft, setCustomSpaceTypeDraft] = useState(
    () => match.space_type ?? "",
  );
  const customSpaceTypeModeRef = useRef(customSpaceTypeMode);

  useEffect(() => {
    customProviderModeRef.current = customProviderMode;
  }, [customProviderMode]);

  useEffect(() => {
    customSpaceTypeModeRef.current = customSpaceTypeMode;
  }, [customSpaceTypeMode]);

  useEffect(() => {
    if (isCustomChoice(match.provider, PROVIDERS)) {
      setCustomProviderMode(true);
      setCustomProviderDraft(match.provider ?? "");
      return;
    }

    if (match.provider !== undefined) {
      setCustomProviderMode(false);
      setCustomProviderDraft(match.provider);
      return;
    }

    if (!customProviderModeRef.current) {
      setCustomProviderDraft("");
    }
  }, [match.provider]);

  useEffect(() => {
    if (isCustomChoice(match.space_type, SPACE_TYPES)) {
      setCustomSpaceTypeMode(true);
      setCustomSpaceTypeDraft(match.space_type ?? "");
      return;
    }

    if (match.space_type !== undefined) {
      setCustomSpaceTypeMode(false);
      setCustomSpaceTypeDraft(match.space_type);
      return;
    }

    if (!customSpaceTypeModeRef.current) {
      setCustomSpaceTypeDraft("");
    }
  }, [match.space_type]);

  const selectClass =
    "bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono w-full";
  const selectContentClass = "bg-[#131721] border-[#2d3240]";
  const selectItemClass =
    "text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]";
  const inputClass =
    "bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50 h-7";

  return (
    <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721]/30 divide-y divide-[#2d3240]/30">
      {/* Provider */}
      <FieldRow label="Provider">
        {customProviderMode ? (
          <div className="flex items-center gap-1.5">
            <Input
              value={customProviderDraft}
              onChange={(e) => {
                const nextValue = e.target.value;
                setCustomProviderDraft(nextValue);
                patch({ provider: nextValue || undefined });
              }}
              placeholder="custom provider name"
              className={inputClass}
              autoFocus
            />
            <button
              onClick={() => {
                setCustomProviderMode(false);
                setCustomProviderDraft("");
                patch({ provider: undefined });
              }}
              className="p-1 rounded text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#2d3240] transition-colors shrink-0"
              title="Switch to dropdown"
            >
              <IconX size={12} stroke={1.5} />
            </button>
          </div>
        ) : (
          <Select
            value={match.provider ?? "__none__"}
            onValueChange={(val: string | null) => {
              if (val === "__custom__") {
                setCustomProviderMode(true);
                setCustomProviderDraft(match.provider ?? "");
                patch({ provider: undefined });
              } else {
                setCustomProviderMode(false);
                setCustomProviderDraft(
                  val === "__none__" || val == null ? "" : val,
                );
                patch({
                  provider:
                    val === "__none__" || val == null
                      ? undefined
                      : (val as OriginProvider),
                });
              }
            }}
          >
            <SelectTrigger className={selectClass}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent className={selectContentClass}>
              <SelectItem
                value="__none__"
                className="text-xs font-mono text-[#6f7f9a]"
              >
                Any
              </SelectItem>
              {PROVIDERS.map((p) => (
                <SelectItem
                  key={p.value}
                  value={p.value}
                  className={selectItemClass}
                >
                  {p.label}
                </SelectItem>
              ))}
              <SelectItem
                value="__custom__"
                className="text-xs font-mono text-[#d4a84b] focus:bg-[#2d3240] focus:text-[#d4a84b]"
              >
                Custom...
              </SelectItem>
            </SelectContent>
          </Select>
        )}
      </FieldRow>

      {/* Space Type */}
      <FieldRow label="Space Type">
        {customSpaceTypeMode ? (
          <div className="flex items-center gap-1.5">
            <Input
              value={customSpaceTypeDraft}
              onChange={(e) => {
                const nextValue = e.target.value;
                setCustomSpaceTypeDraft(nextValue);
                patch({ space_type: nextValue || undefined });
              }}
              placeholder="custom space type"
              className={inputClass}
              autoFocus
            />
            <button
              onClick={() => {
                setCustomSpaceTypeMode(false);
                setCustomSpaceTypeDraft("");
                patch({ space_type: undefined });
              }}
              className="p-1 rounded text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#2d3240] transition-colors shrink-0"
              title="Switch to dropdown"
            >
              <IconX size={12} stroke={1.5} />
            </button>
          </div>
        ) : (
          <Select
            value={match.space_type ?? "__none__"}
            onValueChange={(val: string | null) => {
              if (val === "__custom__") {
                setCustomSpaceTypeMode(true);
                setCustomSpaceTypeDraft(match.space_type ?? "");
                patch({ space_type: undefined });
              } else {
                setCustomSpaceTypeMode(false);
                setCustomSpaceTypeDraft(
                  val === "__none__" || val == null ? "" : val,
                );
                patch({
                  space_type:
                    val === "__none__" || val == null
                      ? undefined
                      : (val as SpaceType),
                });
              }
            }}
          >
            <SelectTrigger className={selectClass}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent className={selectContentClass}>
              <SelectItem
                value="__none__"
                className="text-xs font-mono text-[#6f7f9a]"
              >
                Any
              </SelectItem>
              {SPACE_TYPES.map((st) => (
                <SelectItem
                  key={st.value}
                  value={st.value}
                  className={selectItemClass}
                >
                  {st.label}
                </SelectItem>
              ))}
              <SelectItem
                value="__custom__"
                className="text-xs font-mono text-[#d4a84b] focus:bg-[#2d3240] focus:text-[#d4a84b]"
              >
                Custom...
              </SelectItem>
            </SelectContent>
          </Select>
        )}
      </FieldRow>

      {/* Visibility */}
      <FieldRow label="Visibility">
        <Select
          value={match.visibility ?? "__none__"}
          onValueChange={(val: string | null) =>
            patch({ visibility: val === "__none__" || val == null ? undefined : (val as Visibility) })
          }
        >
          <SelectTrigger className={selectClass}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent className={selectContentClass}>
            <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">
              Any
            </SelectItem>
            {VISIBILITY_OPTIONS.map((v) => (
              <SelectItem key={v.value} value={v.value} className={selectItemClass}>
                {v.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </FieldRow>

      {/* Provenance */}
      <FieldRow label="Provenance">
        <Select
          value={match.provenance_confidence ?? "__none__"}
          onValueChange={(val: string | null) =>
            patch({
              provenance_confidence:
                val === "__none__" || val == null ? undefined : (val as ProvenanceConfidence),
            })
          }
        >
          <SelectTrigger className={selectClass}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent className={selectContentClass}>
            <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">
              Any
            </SelectItem>
            {PROVENANCE_OPTIONS.map((po) => (
              <SelectItem key={po.value} value={po.value} className={selectItemClass}>
                {po.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </FieldRow>

      {/* External Participants */}
      <FieldRow label="External Participants">
        <Select
          value={
            match.external_participants === undefined
              ? "__none__"
              : match.external_participants
                ? "true"
                : "false"
          }
          onValueChange={(val: string | null) =>
            patch({
              external_participants: val === "__none__" || val == null ? undefined : val === "true",
            })
          }
        >
          <SelectTrigger className={selectClass}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent className={selectContentClass}>
            <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">
              Any
            </SelectItem>
            <SelectItem value="true" className={selectItemClass}>
              Yes
            </SelectItem>
            <SelectItem value="false" className={selectItemClass}>
              No
            </SelectItem>
          </SelectContent>
        </Select>
      </FieldRow>

      {/* Tenant ID */}
      <FieldRow label="Tenant ID">
        <Input
          value={match.tenant_id ?? ""}
          onChange={(e) => patch({ tenant_id: e.target.value || undefined })}
          placeholder="e.g. T12345"
          className={inputClass}
        />
      </FieldRow>

      {/* Space ID */}
      <FieldRow label="Space ID">
        <Input
          value={match.space_id ?? ""}
          onChange={(e) => patch({ space_id: e.target.value || undefined })}
          placeholder="e.g. C99999"
          className={inputClass}
        />
      </FieldRow>

      {/* Thread ID */}
      <FieldRow label="Thread ID">
        <Input
          value={match.thread_id ?? ""}
          onChange={(e) => patch({ thread_id: e.target.value || undefined })}
          placeholder="e.g. 1234567890.123456"
          className={inputClass}
        />
      </FieldRow>

      {/* Tags */}
      <FieldRow label="Tags">
        <Input
          value={(match.tags ?? []).join(", ")}
          onChange={(e) => {
            const tags = e.target.value
              .split(",")
              .map((t) => t.trim())
              .filter(Boolean);
            patch({ tags: tags.length > 0 ? tags : undefined });
          }}
          placeholder="comma-separated"
          className={inputClass}
        />
      </FieldRow>

      {/* Sensitivity */}
      <FieldRow label="Sensitivity">
        <Input
          value={match.sensitivity ?? ""}
          onChange={(e) => patch({ sensitivity: e.target.value || undefined })}
          placeholder="e.g. high"
          className={inputClass}
        />
      </FieldRow>

      {/* Actor Role */}
      <FieldRow label="Actor Role">
        <Input
          value={match.actor_role ?? ""}
          onChange={(e) => patch({ actor_role: e.target.value || undefined })}
          placeholder="e.g. admin"
          className={inputClass}
        />
      </FieldRow>

      {/* C4: Actor ID */}
      <FieldRow label="Actor ID">
        <Input
          value={match.actor_id ?? ""}
          onChange={(e) => patch({ actor_id: e.target.value || undefined })}
          placeholder="e.g. U12345"
          className={inputClass}
        />
      </FieldRow>

      {/* C4: Actor Type */}
      <FieldRow label="Actor Type">
        <Select
          value={match.actor_type ?? "__none__"}
          onValueChange={(val: string | null) =>
            patch({
              actor_type:
                val === "__none__" || val == null ? undefined : (val as ActorType),
            })
          }
        >
          <SelectTrigger className={selectClass}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent className={selectContentClass}>
            <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">
              Any
            </SelectItem>
            {ACTOR_TYPE_OPTIONS.map((at) => (
              <SelectItem key={at.value} value={at.value} className={selectItemClass}>
                {at.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </FieldRow>
    </div>
  );
}

// ---------------------------------------------------------------------------
// MCP tool editor
// ---------------------------------------------------------------------------

function McpEditor({
  mcp,
  onChange,
}: {
  mcp: McpToolConfig;
  onChange: (updated: McpToolConfig) => void;
}) {
  const inputClass =
    "bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50 h-7";

  // Type-widened reference for merge-mode fields that may not yet be in the TS type
  const mcpAny = mcp as McpToolConfig & Record<string, unknown>;
  const patchAny = (patch: Record<string, unknown>) =>
    onChange({ ...mcp, ...patch } as McpToolConfig);

  const parseCommaSep = (v: string) =>
    v
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

  return (
    <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721]/30 divide-y divide-[#2d3240]/30">
      <FieldRow label="Allow">
        <Input
          value={(mcp.allow ?? []).join(", ")}
          onChange={(e) => onChange({ ...mcp, allow: parseCommaSep(e.target.value) })}
          placeholder="tool_a, tool_b, search-*"
          className={inputClass}
        />
      </FieldRow>
      <FieldRow label="Block">
        <Input
          value={(mcp.block ?? []).join(", ")}
          onChange={(e) => onChange({ ...mcp, block: parseCommaSep(e.target.value) })}
          placeholder="deploy-*, admin-*"
          className={inputClass}
        />
      </FieldRow>
      {/* C2: require_confirmation */}
      <FieldRow label="Require Confirmation">
        <Input
          value={(mcp.require_confirmation ?? []).join(", ")}
          onChange={(e) =>
            onChange({ ...mcp, require_confirmation: parseCommaSep(e.target.value) })
          }
          placeholder="tool names requiring manual confirmation"
          className={inputClass}
        />
      </FieldRow>
      <FieldRow label="Default Action">
        <Select
          value={mcp.default_action ?? "block"}
          onValueChange={(val: string | null) => {
            if (val) onChange({ ...mcp, default_action: val as "allow" | "block" });
          }}
        >
          <SelectTrigger className="bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-[#131721] border-[#2d3240]">
            <SelectItem
              value="allow"
              className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
            >
              Allow
            </SelectItem>
            <SelectItem
              value="block"
              className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
            >
              Block
            </SelectItem>
          </SelectContent>
        </Select>
      </FieldRow>
      {/* C6: max_args_size */}
      <FieldRow label="Max Args Size (bytes)">
        <Input
          type="number"
          min={0}
          value={mcp.max_args_size ?? ""}
          onChange={(e) => {
            const n = parseInt(e.target.value, 10);
            onChange({
              ...mcp,
              max_args_size: Number.isNaN(n) ? undefined : Math.max(0, n),
            });
          }}
          placeholder="unlimited"
          className={cn(inputClass, "w-32")}
        />
      </FieldRow>
      {/* C3: Merge-mode fields for profile inheritance */}
      <div className="px-3 py-2">
        <p className="text-[9px] text-[#6f7f9a]/50 font-medium uppercase tracking-wider mb-1.5">
          Merge-Mode Overrides
        </p>
        <p className="text-[9px] text-[#6f7f9a]/40 mb-2">
          When inheriting from a base policy, these fields add to or remove from the parent lists.
        </p>
      </div>
      <FieldRow label="Additional Allow">
        <Input
          value={((mcpAny.additional_allow as string[] | undefined) ?? []).join(", ")}
          onChange={(e) => patchAny({ additional_allow: parseCommaSep(e.target.value) })}
          placeholder="extra tools to allow"
          className={inputClass}
        />
      </FieldRow>
      <FieldRow label="Additional Block">
        <Input
          value={((mcpAny.additional_block as string[] | undefined) ?? []).join(", ")}
          onChange={(e) => patchAny({ additional_block: parseCommaSep(e.target.value) })}
          placeholder="extra tools to block"
          className={inputClass}
        />
      </FieldRow>
      <FieldRow label="Remove Allow">
        <Input
          value={((mcpAny.remove_allow as string[] | undefined) ?? []).join(", ")}
          onChange={(e) => patchAny({ remove_allow: parseCommaSep(e.target.value) })}
          placeholder="remove from parent allow list"
          className={inputClass}
        />
      </FieldRow>
      <FieldRow label="Remove Block">
        <Input
          value={((mcpAny.remove_block as string[] | undefined) ?? []).join(", ")}
          onChange={(e) => patchAny({ remove_block: parseCommaSep(e.target.value) })}
          placeholder="remove from parent block list"
          className={inputClass}
        />
      </FieldRow>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Egress editor
// ---------------------------------------------------------------------------

function EgressEditor({
  egress,
  onChange,
}: {
  egress: EgressAllowlistConfig;
  onChange: (updated: EgressAllowlistConfig) => void;
}) {
  const inputClass =
    "bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50 h-7";

  return (
    <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721]/30 divide-y divide-[#2d3240]/30">
      <FieldRow label="Allow">
        <Input
          value={(egress.allow ?? []).join(", ")}
          onChange={(e) => {
            const arr = e.target.value
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean);
            onChange({ ...egress, allow: arr });
          }}
          placeholder="*.example.com, api.github.com"
          className={inputClass}
        />
      </FieldRow>
      <FieldRow label="Block">
        <Input
          value={(egress.block ?? []).join(", ")}
          onChange={(e) => {
            const arr = e.target.value
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean);
            onChange({ ...egress, block: arr });
          }}
          placeholder="evil.com"
          className={inputClass}
        />
      </FieldRow>
      <FieldRow label="Default Action">
        <Select
          value={egress.default_action ?? "block"}
          onValueChange={(val: string | null) => {
            if (val) onChange({ ...egress, default_action: val as "allow" | "block" | "log" });
          }}
        >
          <SelectTrigger className="bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-[#131721] border-[#2d3240]">
            <SelectItem
              value="allow"
              className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
            >
              Allow
            </SelectItem>
            <SelectItem
              value="block"
              className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
            >
              Block
            </SelectItem>
            <SelectItem
              value="log"
              className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
            >
              Log
            </SelectItem>
          </SelectContent>
        </Select>
      </FieldRow>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Data policy editor
// ---------------------------------------------------------------------------

function DataPolicyEditor({
  data,
  onChange,
}: {
  data: OriginDataPolicy;
  onChange: (updated: OriginDataPolicy) => void;
}) {
  return (
    <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721]/30 divide-y divide-[#2d3240]/30">
      <ToggleRow
        label="Allow external sharing"
        checked={data.allow_external_sharing ?? false}
        onChange={(v) => onChange({ ...data, allow_external_sharing: v })}
      />
      <ToggleRow
        label="Redact before send"
        checked={data.redact_before_send ?? false}
        onChange={(v) => onChange({ ...data, redact_before_send: v })}
      />
      <ToggleRow
        label="Block sensitive outputs"
        checked={data.block_sensitive_outputs ?? false}
        onChange={(v) => onChange({ ...data, block_sensitive_outputs: v })}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Budgets editor
// ---------------------------------------------------------------------------

function BudgetsEditor({
  budgets,
  onChange,
}: {
  budgets: OriginBudgets;
  onChange: (updated: OriginBudgets) => void;
}) {
  const inputClass =
    "bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs w-24 placeholder:text-[#6f7f9a]/50 h-7";

  const parseNum = (v: string) => {
    const n = parseInt(v, 10);
    return Number.isNaN(n) ? undefined : Math.max(0, n);
  };

  return (
    <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721]/30 divide-y divide-[#2d3240]/30">
      <FieldRow label="MCP tool calls">
        <Input
          type="number"
          min={0}
          value={budgets.mcp_tool_calls ?? ""}
          onChange={(e) => onChange({ ...budgets, mcp_tool_calls: parseNum(e.target.value) })}
          placeholder="unlimited"
          className={inputClass}
        />
      </FieldRow>
      <FieldRow label="Egress calls">
        <Input
          type="number"
          min={0}
          value={budgets.egress_calls ?? ""}
          onChange={(e) => onChange({ ...budgets, egress_calls: parseNum(e.target.value) })}
          placeholder="unlimited"
          className={inputClass}
        />
      </FieldRow>
      <FieldRow label="Shell commands">
        <Input
          type="number"
          min={0}
          value={budgets.shell_commands ?? ""}
          onChange={(e) => onChange({ ...budgets, shell_commands: parseNum(e.target.value) })}
          placeholder="unlimited"
          className={inputClass}
        />
      </FieldRow>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Bridge policy editor
// ---------------------------------------------------------------------------

function BridgeEditor({
  bridge,
  onChange,
}: {
  bridge: BridgePolicy;
  onChange: (updated: BridgePolicy) => void;
}) {
  const targets = bridge.allowed_targets ?? [];

  // Stable unique keys for bridge targets to prevent input corruption on add/remove
  const targetKeyCounter = useRef(0);
  const targetKeysRef = useRef<string[]>([]);
  // Ensure keys array matches the current target count
  while (targetKeysRef.current.length < targets.length) {
    targetKeysRef.current.push(`bt-${++targetKeyCounter.current}`);
  }
  if (targetKeysRef.current.length > targets.length) {
    targetKeysRef.current = targetKeysRef.current.slice(0, targets.length);
  }

  const selectClass =
    "bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono w-full";
  const selectContentClass = "bg-[#131721] border-[#2d3240]";
  const selectItemClass =
    "text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]";

  const updateTarget = (index: number, patch: Partial<BridgeTarget>) => {
    const next = targets.map((t, i) => (i === index ? { ...t, ...patch } : t));
    onChange({ ...bridge, allowed_targets: next });
  };

  const removeTarget = (index: number) => {
    const next = targets.filter((_, i) => i !== index);
    // Also remove the corresponding stable key
    targetKeysRef.current = targetKeysRef.current.filter((_, i) => i !== index);
    onChange({ ...bridge, allowed_targets: next });
  };

  const addTarget = () => {
    targetKeysRef.current.push(`bt-${++targetKeyCounter.current}`);
    onChange({
      ...bridge,
      allowed_targets: [...targets, {}],
    });
  };

  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721]/30 divide-y divide-[#2d3240]/30">
        <ToggleRow
          label="Allow cross-origin communication"
          checked={bridge.allow_cross_origin ?? false}
          onChange={(v) => onChange({ ...bridge, allow_cross_origin: v })}
        />
        <ToggleRow
          label="Require approval"
          checked={bridge.require_approval ?? true}
          onChange={(v) => onChange({ ...bridge, require_approval: v })}
        />
      </div>

      {/* Allowed Targets */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] text-[#6f7f9a] font-medium">
            Allowed Targets
          </span>
          <button
            onClick={addTarget}
            className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-medium text-[#d4a84b] bg-[#d4a84b]/10 hover:bg-[#d4a84b]/15 border border-[#d4a84b]/20 transition-colors"
          >
            <IconPlus size={10} stroke={2} />
            Add Target
          </button>
        </div>

        {targets.length === 0 ? (
          <div className="rounded-lg border border-dashed border-[#2d3240]/50 px-3.5 py-3 text-center">
            <p className="text-[10px] text-[#6f7f9a]/40">
              No allowed targets — cross-origin communication is unrestricted when enabled
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {targets.map((target, index) => (
              <div
                key={targetKeysRef.current[index] ?? index}
                className="rounded-lg border border-[#2d3240]/60 bg-[#131721]/30 divide-y divide-[#2d3240]/30"
              >
                <div className="flex items-center justify-between px-3 py-1.5">
                  <span className="text-[10px] font-mono text-[#6f7f9a]">
                    Target {index + 1}
                  </span>
                  <button
                    onClick={() => removeTarget(index)}
                    className="p-1 rounded text-[#6f7f9a] hover:text-[#c45c5c] hover:bg-[#c45c5c]/10 transition-colors"
                    title="Remove target"
                  >
                    <IconTrash size={11} stroke={1.5} />
                  </button>
                </div>
                <FieldRow label="Provider">
                  <Select
                    value={target.provider ?? "__none__"}
                    onValueChange={(val: string | null) =>
                      updateTarget(index, {
                        provider: val === "__none__" || val == null ? undefined : val,
                      })
                    }
                  >
                    <SelectTrigger className={selectClass}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className={selectContentClass}>
                      <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">
                        Any
                      </SelectItem>
                      {PROVIDERS.map((p) => (
                        <SelectItem key={p.value} value={p.value} className={selectItemClass}>
                          {p.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FieldRow>
                <FieldRow label="Space Type">
                  <Select
                    value={target.space_type ?? "__none__"}
                    onValueChange={(val: string | null) =>
                      updateTarget(index, {
                        space_type: val === "__none__" || val == null ? undefined : val,
                      })
                    }
                  >
                    <SelectTrigger className={selectClass}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className={selectContentClass}>
                      <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">
                        Any
                      </SelectItem>
                      {SPACE_TYPES.map((st) => (
                        <SelectItem key={st.value} value={st.value} className={selectItemClass}>
                          {st.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FieldRow>
                <FieldRow label="Visibility">
                  <Select
                    value={target.visibility ?? "__none__"}
                    onValueChange={(val: string | null) =>
                      updateTarget(index, {
                        visibility: val === "__none__" || val == null ? undefined : (val as Visibility),
                      })
                    }
                  >
                    <SelectTrigger className={selectClass}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className={selectContentClass}>
                      <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">
                        Any
                      </SelectItem>
                      {VISIBILITY_OPTIONS.map((v) => (
                        <SelectItem key={v.value} value={v.value} className={selectItemClass}>
                          {v.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FieldRow>
                <FieldRow label="Tags">
                  <Input
                    value={(target.tags ?? []).join(", ")}
                    onChange={(e) => {
                      const tags = e.target.value
                        .split(",")
                        .map((t) => t.trim())
                        .filter(Boolean);
                      updateTarget(index, { tags: tags.length > 0 ? tags : undefined });
                    }}
                    placeholder="comma-separated"
                    className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50 h-7"
                  />
                </FieldRow>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Metadata editor — simple JSON textarea
// ---------------------------------------------------------------------------

function MetadataEditor({
  metadata,
  onChange,
}: {
  metadata: Record<string, unknown> | undefined;
  onChange: (updated: Record<string, unknown> | undefined) => void;
}) {
  const serializedMetadata =
    metadata && Object.keys(metadata).length > 0
      ? JSON.stringify(metadata, null, 2)
      : "";
  const [raw, setRaw] = useState(() =>
    serializedMetadata,
  );
  const [error, setError] = useState<string | null>(null);
  const lastCommittedSerializedRef = useRef(serializedMetadata);
  const skipOwnCommitSyncRef = useRef(false);

  // Sync external changes
  useEffect(() => {
    if (
      skipOwnCommitSyncRef.current &&
      serializedMetadata === lastCommittedSerializedRef.current
    ) {
      skipOwnCommitSyncRef.current = false;
      setError(null);
      return;
    }

    skipOwnCommitSyncRef.current = false;
    lastCommittedSerializedRef.current = serializedMetadata;
    setRaw(serializedMetadata);
    setError(null);
  }, [serializedMetadata]);

  const handleBlur = useCallback(() => {
    const trimmed = raw.trim();
    if (!trimmed) {
      setError(null);
      lastCommittedSerializedRef.current = "";
      skipOwnCommitSyncRef.current = true;
      onChange(undefined);
      return;
    }
    try {
      const parsed = JSON.parse(trimmed);
      if (typeof parsed !== "object" || Array.isArray(parsed) || parsed === null) {
        setError("Must be a JSON object");
        return;
      }
      setError(null);
      lastCommittedSerializedRef.current = JSON.stringify(parsed, null, 2);
      skipOwnCommitSyncRef.current = true;
      onChange(parsed as Record<string, unknown>);
    } catch {
      setError("Invalid JSON");
    }
  }, [raw, onChange]);

  return (
    <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721]/30 overflow-hidden">
      <textarea
        value={raw}
        onChange={(e) => setRaw(e.target.value)}
        onBlur={handleBlur}
        placeholder='{ "key": "value" }'
        rows={4}
        className="w-full bg-transparent text-[#ece7dc] font-mono text-xs p-3 resize-y placeholder:text-[#6f7f9a]/40 focus:outline-none"
      />
      {error && (
        <div className="px-3 py-1.5 bg-[#c45c5c]/10 border-t border-[#c45c5c]/20 text-[9px] text-[#c45c5c]">
          {error}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Policies-using-this-profile section
// ---------------------------------------------------------------------------

function AppliedPoliciesSection({
  profile,
  savedPolicies,
  activePolicy,
  onApplyToActive,
}: {
  profile: OriginProfile;
  savedPolicies: SavedPolicy[];
  activePolicy: { name: string; origins?: OriginsConfig };
  onApplyToActive: () => void;
}) {
  const usingPolicies = savedPolicies.filter((sp) =>
    sp.policy.origins?.profiles?.some((p) => p.id === profile.id) ?? false,
  );

  const isInActive =
    activePolicy.origins?.profiles?.some((p) => p.id === profile.id) ?? false;

  return (
    <div>
      <div className="flex items-center gap-2 mb-1.5">
        <IconExternalLink size={13} stroke={1.5} className="text-[#557b8b]" />
        <h3 className="text-[11px] font-semibold uppercase tracking-wider text-[#ece7dc]/70">
          Applied To Policies
        </h3>
      </div>
      <p className="text-[10px] text-[#6f7f9a]/60 leading-relaxed mb-3">
        Policies that include a profile with this ID. Apply to the active policy
        to enforce these origin rules.
      </p>

      <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721]/30 overflow-hidden">
        <div className="flex items-center justify-between px-3 py-2.5 border-b border-[#2d3240]/30">
          <div className="flex items-center gap-2">
            <span
              className={cn(
                "h-2 w-2 rounded-full shrink-0",
                isInActive ? "bg-[#3dbf84]" : "bg-[#6f7f9a]/30",
              )}
            />
            <span className="text-[11px] text-[#ece7dc]/80 font-medium">
              {activePolicy.name || "Active Policy"}
            </span>
            <span className="text-[8px] font-mono text-[#d4a84b]/60 bg-[#d4a84b]/10 px-1 rounded">
              active
            </span>
          </div>
          {!isInActive ? (
            <button
              onClick={onApplyToActive}
              className="flex items-center gap-1 px-2 py-1 rounded text-[9px] font-medium text-[#d4a84b] bg-[#d4a84b]/10 hover:bg-[#d4a84b]/15 border border-[#d4a84b]/20 transition-colors"
            >
              <IconDownload size={10} stroke={2} />
              Apply
            </button>
          ) : (
            <span className="flex items-center gap-1 text-[9px] text-[#3dbf84]">
              <IconCheck size={10} stroke={2} />
              Applied
            </span>
          )}
        </div>

        {usingPolicies.length > 0 ? (
          usingPolicies.map((sp) => (
            <div
              key={sp.id}
              className="flex items-center gap-2 px-3 py-2 border-b border-[#2d3240]/20 last:border-b-0"
            >
              <span className="h-1.5 w-1.5 rounded-full bg-[#6f7f9a]/30 shrink-0" />
              <span className="text-[10px] text-[#6f7f9a] truncate">
                {sp.policy.name || sp.id}
              </span>
            </div>
          ))
        ) : (
          <div className="px-3 py-3 text-[10px] text-[#6f7f9a]/40 text-center">
            No saved policies reference this profile yet
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Profile detail view (editable)
// ---------------------------------------------------------------------------

function ProfileDetail({
  profile,
  savedPolicies,
  activePolicy,
  onApplyToActive,
  onClone,
  onDelete,
  onUpdate,
}: {
  profile: OriginProfile;
  savedPolicies: SavedPolicy[];
  activePolicy: { name: string; origins?: OriginsConfig };
  onApplyToActive: () => void;
  onClone: () => void;
  onDelete: () => void;
  onUpdate: (updated: OriginProfile) => void;
}) {
  const ProviderIcon = getProviderIcon(profile.match_rules?.provider);
  const providerColor = getProviderColor(profile.match_rules?.provider);
  const providerMeta = getProviderMeta(profile.match_rules?.provider);
  const [profileIdDraft, setProfileIdDraft] = useState(profile.id);

  useEffect(() => {
    setProfileIdDraft(profile.id);
  }, [profile.id]);

  const commitProfileId = useCallback(() => {
    if (profileIdDraft !== profile.id) {
      onUpdate({ ...profile, id: profileIdDraft });
    }
  }, [onUpdate, profile, profile.id, profileIdDraft]);

  return (
    <div className="p-6 space-y-6 max-w-3xl mx-auto">
      {/* Profile header */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3 min-w-0 flex-1">
          <div
            className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0"
            style={{ backgroundColor: `${providerColor}15` }}
          >
            <ProviderIcon size={20} stroke={1.5} style={{ color: providerColor }} />
          </div>
          <div className="min-w-0 flex-1">
            <Input
              value={profileIdDraft}
              onChange={(e) => setProfileIdDraft(e.target.value)}
              onBlur={commitProfileId}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.currentTarget.blur();
                }
              }}
              maxLength={128}
              className="bg-transparent border-transparent hover:border-[#2d3240] focus:border-[#d4a84b]/40 text-base font-semibold text-[#ece7dc] font-mono h-auto py-0.5 px-1.5 -ml-1.5 transition-colors"
            />
            {providerMeta && (
              <p className="text-[10px] text-[#6f7f9a] mt-0.5 ml-1.5">
                {providerMeta.desc}
              </p>
            )}
            <div className="flex items-center gap-2 mt-1.5 ml-1.5">
              <span className="text-[9px] text-[#6f7f9a]">Posture:</span>
              <Select
                value={profile.posture ?? "__none__"}
                onValueChange={(val: string | null) =>
                  onUpdate({
                    ...profile,
                    posture: val === "__none__" || val == null ? undefined : val,
                  })
                }
              >
                <SelectTrigger className="bg-[#131721] border-[#2d3240] text-[#ece7dc] text-[10px] font-mono h-6 w-28">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-[#131721] border-[#2d3240]">
                  <SelectItem
                    value="__none__"
                    className="text-xs font-mono text-[#6f7f9a]"
                  >
                    None
                  </SelectItem>
                  <SelectItem
                    value="standard"
                    className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                  >
                    Standard
                  </SelectItem>
                  <SelectItem
                    value="elevated"
                    className="text-xs font-mono text-[#d4a84b] focus:bg-[#2d3240] focus:text-[#d4a84b]"
                  >
                    Elevated
                  </SelectItem>
                  <SelectItem
                    value="restricted"
                    className="text-xs font-mono text-[#c45c5c] focus:bg-[#2d3240] focus:text-[#c45c5c]"
                  >
                    Restricted
                  </SelectItem>
                  <SelectItem
                    value="locked"
                    className="text-xs font-mono text-[#c45c5c] focus:bg-[#2d3240] focus:text-[#c45c5c]"
                  >
                    Locked
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1 shrink-0">
          <button
            onClick={onClone}
            className="p-1.5 rounded-md text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721] transition-colors"
            title="Clone profile"
          >
            <IconCopy size={14} stroke={1.5} />
          </button>
          <button
            onClick={onDelete}
            className="p-1.5 rounded-md text-[#6f7f9a] hover:text-[#c45c5c] hover:bg-[#c45c5c]/10 transition-colors"
            title="Delete profile"
          >
            <IconTrash size={14} stroke={1.5} />
          </button>
        </div>
      </div>

      {/* Explanation (editable) */}
      <div className="rounded-lg border border-[#2d3240]/40 bg-[#131721]/20 px-4 py-3">
        <Input
          value={profile.explanation ?? ""}
          onChange={(e) =>
            onUpdate({ ...profile, explanation: e.target.value || undefined })
          }
          placeholder="Add a description for this profile..."
          className="bg-transparent border-transparent hover:border-[#2d3240] focus:border-[#d4a84b]/40 text-[11px] text-[#6f7f9a] italic w-full h-auto py-0.5 px-0 transition-colors placeholder:text-[#6f7f9a]/30"
        />
      </div>

      {/* Match rules */}
      <DetailSection
        icon={IconRoute}
        title="Match Rules"
        description="Rules that determine when this profile activates. An incoming request must match all specified criteria."
        color="#557b8b"
      >
        <MatchRulesEditor
          match={profile.match_rules}
          onChange={(match_rules) => onUpdate({ ...profile, match_rules })}
        />
      </DetailSection>

      {/* MCP Tool Access */}
      <DetailSection
        icon={IconTool}
        title="MCP Tool Access"
        description="Controls which MCP tools agents can invoke when operating in this origin context."
        color="#7b6b8b"
        onToggle={(enabled) =>
          onUpdate({
            ...profile,
            mcp: enabled
              ? { enabled: true, allow: [], block: [], default_action: "block" }
              : undefined,
          })
        }
        enabled={Boolean(profile.mcp) && profile.mcp?.enabled !== false}
      >
        {profile.mcp && (
          <McpEditor
            mcp={profile.mcp}
            onChange={(mcp) => onUpdate({ ...profile, mcp })}
          />
        )}
      </DetailSection>

      {/* Egress Allowlist */}
      <DetailSection
        icon={IconNetwork}
        title="Egress Allowlist"
        description="Network destinations agents can reach. Domains not in the allowlist are blocked by default."
        color="#557b8b"
        onToggle={(enabled) =>
          onUpdate({
            ...profile,
            egress: enabled
              ? { enabled: true, allow: [], block: [], default_action: "block" }
              : undefined,
          })
        }
        enabled={Boolean(profile.egress) && profile.egress?.enabled !== false}
      >
        {profile.egress && (
          <EgressEditor
            egress={profile.egress}
            onChange={(egress) => onUpdate({ ...profile, egress })}
          />
        )}
      </DetailSection>

      {/* Data Policy */}
      <DetailSection
        icon={IconDatabase}
        title="Data Policy"
        description="Controls for sensitive data handling — sharing, redaction, and output filtering."
        color="#6b7b55"
        onToggle={(enabled) =>
          onUpdate({
            ...profile,
            data: enabled
              ? {
                  allow_external_sharing: false,
                  redact_before_send: false,
                  block_sensitive_outputs: false,
                }
              : undefined,
          })
        }
        enabled={Boolean(profile.data)}
      >
        {profile.data && (
          <DataPolicyEditor
            data={profile.data}
            onChange={(data) => onUpdate({ ...profile, data })}
          />
        )}
      </DetailSection>

      {/* Budgets */}
      <DetailSection
        icon={IconGauge}
        title="Budgets"
        description="Per-session rate limits for tool calls, egress, and shell commands in this origin."
        color="#8b7355"
        onToggle={(enabled) =>
          onUpdate({
            ...profile,
            budgets: enabled ? {} : undefined,
          })
        }
        enabled={Boolean(profile.budgets)}
      >
        {profile.budgets && (
          <BudgetsEditor
            budgets={profile.budgets}
            onChange={(budgets) => onUpdate({ ...profile, budgets })}
          />
        )}
      </DetailSection>

      {/* Bridge Policy */}
      <DetailSection
        icon={IconArrowsShuffle}
        title="Bridge Policy"
        description="Rules for cross-origin communication — whether this origin can forward data to other origins."
        color="#8b5555"
        onToggle={(enabled) =>
          onUpdate({
            ...profile,
            bridge_policy: enabled
              ? { allow_cross_origin: false, allowed_targets: [], require_approval: true }
              : undefined,
          })
        }
        enabled={Boolean(profile.bridge_policy)}
      >
        {profile.bridge_policy && (
          <BridgeEditor
            bridge={profile.bridge_policy}
            onChange={(bridge_policy) => onUpdate({ ...profile, bridge_policy })}
          />
        )}
      </DetailSection>

      {/* C5: Metadata — arbitrary key-value data */}
      <DetailSection
        icon={IconCode}
        title="Metadata"
        description="Arbitrary key-value data attached to this profile. Passed through to receipts and audit logs."
        color="#6f7f9a"
        onToggle={(enabled) => {
          const profileAny = profile as OriginProfile & Record<string, unknown>;
          onUpdate({
            ...profile,
            ...(enabled
              ? { metadata: profileAny.metadata ?? {} }
              : { metadata: undefined }),
          } as OriginProfile);
        }}
        enabled={Boolean((profile as OriginProfile & Record<string, unknown>).metadata)}
      >
        <MetadataEditor
          metadata={
            (profile as OriginProfile & Record<string, unknown>).metadata as
              | Record<string, unknown>
              | undefined
          }
          onChange={(metadata) =>
            onUpdate({ ...profile, metadata } as OriginProfile)
          }
        />
      </DetailSection>

      {/* Applied to policies */}
      <AppliedPoliciesSection
        profile={profile}
        savedPolicies={savedPolicies}
        activePolicy={activePolicy}
        onApplyToActive={onApplyToActive}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Onboarding / intro panel (shown when no profiles exist or none selected)
// ---------------------------------------------------------------------------

function OriginsIntro() {
  return (
    <div className="flex flex-col items-center justify-center h-full px-8 py-12 text-center max-w-lg mx-auto">
      <div className="w-14 h-14 rounded-2xl bg-[#131721] border border-[#2d3240]/50 flex items-center justify-center mb-5">
        <IconRoute size={24} stroke={1.5} className="text-[#d4a84b]/60" />
      </div>

      <h2 className="text-lg font-semibold text-[#ece7dc] mb-2">
        Origin Profiles
      </h2>

      <p className="text-[12px] text-[#6f7f9a] leading-relaxed mb-6">
        Origin profiles define how your agents behave based on <em>where</em> a
        request comes from — a Slack channel, a GitHub PR, an external webhook.
        Each profile sets match rules, security overrides, and budgets for a
        specific origin context.
      </p>

      <div className="w-full space-y-3 text-left">
        <InfoCallout title="How it works">
          When a request arrives, the engine matches it against your profiles
          in order. The first profile whose match rules fit the request's origin
          context is applied. If no profile matches, the default behavior
          (deny or minimal) kicks in.
        </InfoCallout>

        <InfoCallout title="Getting started">
          Start from a template in the sidebar — they come pre-configured with
          sensible defaults. Customize the match rules and overrides, then apply
          the profile to any policy.
        </InfoCallout>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export function OriginsPage() {
  const { state, dispatch } = useWorkbench();
  const { toast } = useToast();
  const library = useProfileLibrary();

  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(
    library.profiles.length > 0 ? library.profiles[0].id : null,
  );
  const [searchQuery, setSearchQuery] = useState("");
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  // Stable key for ProfileDetail — only changes when the user selects a
  // DIFFERENT profile (sidebar click, clone, add), not when editing the
  // current profile's ID field.  During an ID edit the old ID disappears and
  // the new ID appears at the same array position; we detect that case and
  // suppress the key bump so React doesn't remount the component.
  const stableKeyRef = useRef(0);
  const prevSelectionRef = useRef<string | null>(selectedProfileId);
  const isIdEditRef = useRef(false);
  if (selectedProfileId !== prevSelectionRef.current) {
    if (isIdEditRef.current) {
      // handleProfileUpdate set this flag — don't bump.
      isIdEditRef.current = false;
    } else {
      stableKeyRef.current += 1;
    }
    prevSelectionRef.current = selectedProfileId;
  }

  // Sync selection when profiles change (e.g. after deletion)
  const prevProfileIdsRef = useRef<string[]>(library.profiles.map((p) => p.id));
  useEffect(() => {
    if (
      library.profiles.length > 0 &&
      !library.profiles.some((p) => p.id === selectedProfileId)
    ) {
      // Find the index of the previously selected profile to pick a neighbor
      const prevIds = prevProfileIdsRef.current;
      const oldIdx = selectedProfileId ? prevIds.indexOf(selectedProfileId) : -1;
      const nextIdx = Math.min(
        Math.max(oldIdx, 0),
        library.profiles.length - 1,
      );
      setSelectedProfileId(library.profiles[nextIdx].id);
    }
    prevProfileIdsRef.current = library.profiles.map((p) => p.id);
  }, [library.profiles, selectedProfileId]);

  const selectedProfile = useMemo(
    () => library.profiles.find((p) => p.id === selectedProfileId) ?? null,
    [library.profiles, selectedProfileId],
  );

  // Filter profiles — always include the currently selected profile so users
  // never lose sight of what they're editing.
  const filteredProfiles = useMemo(() => {
    if (!searchQuery.trim()) return library.profiles;
    const q = searchQuery.toLowerCase().trim();
    return library.profiles.filter(
      (p) =>
        p.id === selectedProfileId ||
        p.id.toLowerCase().includes(q) ||
        (p.match_rules?.provider ?? "").toLowerCase().includes(q) ||
        (p.explanation ?? "").toLowerCase().includes(q),
    );
  }, [library.profiles, searchQuery, selectedProfileId]);

  // Add from blueprint
  const handleAddFromBlueprint = useCallback(
    (blueprint: ProfileBlueprint) => {
      const newProfile: OriginProfile = {
        ...structuredClone(blueprint.profile),
        id: `${blueprint.profile.id}-${crypto.randomUUID().slice(0, 6)}`,
      };
      library.add(newProfile);
      setSelectedProfileId(newProfile.id);
      toast({
        type: "success",
        title: "Profile created",
        description: `Created "${newProfile.id}" from ${blueprint.name} template.`,
      });
    },
    [library, toast],
  );

  // Add blank profile
  const handleAddBlank = useCallback(() => {
    const newProfile: OriginProfile = {
      id: `profile-${crypto.randomUUID().slice(0, 8)}`,
      match_rules: {},
      explanation: "",
    };
    library.add(newProfile);
    setSelectedProfileId(newProfile.id);
    toast({
      type: "success",
      title: "Blank profile created",
      description: "Configure the match rules and security overrides.",
    });
  }, [library, toast]);

  // Clone
  const handleClone = useCallback(() => {
    if (!selectedProfileId) return;
    const newId = library.clone(selectedProfileId);
    if (newId) {
      setSelectedProfileId(newId);
      toast({ type: "success", title: "Profile cloned" });
    }
  }, [selectedProfileId, library, toast]);

  // B2: Compute which policies reference a given profile
  const getReferencingPolicies = useCallback(
    (profileId: string) => {
      const names: string[] = [];
      for (const sp of state.savedPolicies) {
        if (sp.policy.origins?.profiles?.some((p) => p.id === profileId)) {
          names.push(sp.policy.name || sp.id);
        }
      }
      if (state.activePolicy.origins?.profiles?.some((p) => p.id === profileId)) {
        names.push(`${state.activePolicy.name || "Active Policy"} (active)`);
      }
      return names;
    },
    [state.savedPolicies, state.activePolicy],
  );

  // State to track whether we're showing a "referenced in policies" warning
  const [deleteWarningPolicies, setDeleteWarningPolicies] = useState<string[]>([]);

  // Delete
  const handleDelete = useCallback(
    (id: string) => {
      library.remove(id);
      setDeleteConfirmId(null);
      setDeleteWarningPolicies([]);
      toast({ type: "success", title: "Profile deleted" });
    },
    [library, toast],
  );

  // Trigger delete — first check for references
  const handleDeleteRequest = useCallback(
    (id: string) => {
      const referencing = getReferencingPolicies(id);
      if (referencing.length > 0) {
        setDeleteWarningPolicies(referencing);
        setDeleteConfirmId(id);
      } else {
        setDeleteWarningPolicies([]);
        setDeleteConfirmId(id);
      }
    },
    [getReferencingPolicies],
  );

  // Update profile in library
  const handleProfileUpdate = useCallback(
    (updated: OriginProfile) => {
      if (!selectedProfileId) return;
      const normalizedId = updated.id.trim();
      const normalizedProfile =
        updated.id === normalizedId ? updated : { ...updated, id: normalizedId };

      // Validate ID changes
      if (normalizedProfile.id !== selectedProfileId) {
        if (normalizedProfile.id === "") {
          toast({
            type: "warning",
            title: "Invalid profile ID",
            description: "Profile ID cannot be empty.",
          });
          return;
        }
        if (
          library.profiles.some(
            (p) =>
              p.id.trim().toLowerCase() === normalizedProfile.id.toLowerCase() &&
              p.id !== selectedProfileId,
          )
        ) {
          toast({
            type: "warning",
            title: "Duplicate profile ID",
            description: `A profile with ID "${normalizedProfile.id}" already exists.`,
          });
          return;
        }
      }

      library.update(selectedProfileId, normalizedProfile);
      // Track ID changes — mark as an ID edit so the stable key doesn't bump
      if (normalizedProfile.id !== selectedProfileId) {
        const oldId = selectedProfileId;
        const newId = normalizedProfile.id;
        const updatedAt = new Date().toISOString();
        isIdEditRef.current = true;
        setSelectedProfileId(newId);

        // B1+B3: Cascade the ID rename to any saved or active policy that references the old ID
        for (const sp of state.savedPolicies) {
          const updatedSavedPolicy = renameOriginProfileIdInSavedPolicy(
            sp,
            oldId,
            newId,
            updatedAt,
          );
          if (updatedSavedPolicy) {
            dispatch({ type: "SAVE_POLICY", savedPolicy: updatedSavedPolicy });
          }
        }

        // Also update the active policy if it references the old ID
        const updatedActivePolicy = renameOriginProfileIdInPolicy(
          state.activePolicy,
          oldId,
          newId,
        );
        if (updatedActivePolicy?.origins) {
          dispatch({
            type: "UPDATE_ORIGINS",
            origins: updatedActivePolicy.origins,
          });
        }
      }
    },
    [selectedProfileId, library, toast, state.savedPolicies, state.activePolicy, dispatch],
  );

  // Apply to active policy
  const handleApplyToActive = useCallback(() => {
    if (!selectedProfile) return;

    const currentOrigins = state.activePolicy.origins;
    const currentProfiles = currentOrigins?.profiles ?? [];

    if (currentProfiles.some((p) => p.id === selectedProfile.id)) {
      toast({
        type: "info",
        title: "Already applied",
        description: "This profile is already in the active policy.",
      });
      return;
    }

    const updated: OriginsConfig = {
      default_behavior: currentOrigins?.default_behavior ?? "deny",
      profiles: [...currentProfiles, structuredClone(selectedProfile)],
    };
    dispatch({ type: "UPDATE_ORIGINS", origins: updated });
    toast({
      type: "success",
      title: "Applied to active policy",
      description: `Profile "${selectedProfile.id}" added to the active policy.`,
    });
  }, [selectedProfile, state.activePolicy.origins, dispatch, toast]);

  return (
    <div className="h-full bg-[#05060a] relative">
      <div className="absolute inset-0 flex overflow-hidden">
        {/* ---- Left Sidebar: Profile Library ---- */}
        <div className="w-72 shrink-0 border-r border-[#2d3240] flex flex-col bg-[#0b0d13]">
          {/* Header */}
          <div className="px-4 pt-4 pb-3 border-b border-[#2d3240] space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <IconRoute size={16} stroke={1.5} className="text-[#d4a84b]" />
                <h2 className="text-sm font-semibold text-[#ece7dc]">
                  Origins
                </h2>
                <span className="text-[10px] font-mono text-[#6f7f9a] bg-[#131721] px-1.5 py-0.5 rounded">
                  {library.profiles.length}
                </span>
              </div>
              <button
                onClick={handleAddBlank}
                className="flex items-center gap-1 px-2 py-1 rounded-md bg-[#d4a84b]/10 border border-[#d4a84b]/20 text-[#d4a84b] text-[11px] font-medium hover:bg-[#d4a84b]/20 transition-colors"
              >
                <IconPlus size={12} stroke={2} />
                Add
              </button>
            </div>

            {/* Default behavior for active policy */}
            <div className="flex items-center gap-2">
              <span className="text-[9px] text-[#6f7f9a] shrink-0">Default:</span>
              <Select
                value={state.activePolicy.origins?.default_behavior ?? "deny"}
                onValueChange={(val: string | null) => {
                  if (!val) return;
                  const currentOrigins = state.activePolicy.origins;
                  dispatch({
                    type: "UPDATE_ORIGINS",
                    origins: {
                      default_behavior: val as OriginDefaultBehavior,
                      profiles: currentOrigins?.profiles ?? [],
                    },
                  });
                }}
              >
                <SelectTrigger className="bg-[#131721] border-[#2d3240] text-[#ece7dc] text-[10px] font-mono h-6 flex-1">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-[#131721] border-[#2d3240]">
                  <SelectItem
                    value="deny"
                    className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                  >
                    Deny
                  </SelectItem>
                  <SelectItem
                    value="minimal_profile"
                    className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                  >
                    Minimal Profile
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Search */}
            {library.profiles.length >= 3 && (
              <div className="relative">
                <IconSearch
                  size={12}
                  stroke={1.5}
                  className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[#6f7f9a]/50 pointer-events-none"
                />
                <input
                  type="text"
                  placeholder="Search profiles..."
                  aria-label="Search profiles"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className={cn(
                    "w-full pl-7 pr-7 py-1.5 rounded-lg text-[11px] font-medium",
                    "bg-[#131721]/50 border border-[#2d3240] text-[#ece7dc] placeholder-[#6f7f9a]/40",
                    "focus:outline-none focus:border-[#d4a84b]/40 transition-colors",
                  )}
                />
                {searchQuery && (
                  <button
                    onClick={() => setSearchQuery("")}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-[#6f7f9a] hover:text-[#ece7dc]"
                  >
                    <IconX size={11} stroke={1.5} />
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Profile list + templates */}
          <div className="flex-1 min-h-0 overflow-y-auto">
            {library.profiles.length > 1 && (
              <div className="px-4 pt-2 pb-0">
                <p className="text-[9px] text-[#6f7f9a]/50 italic">
                  Higher profiles have priority in matching
                </p>
              </div>
            )}
            <div className="p-2 space-y-1">
              {filteredProfiles.length === 0 && library.profiles.length > 0 && (
                <div className="px-3 py-6 text-center">
                  <p className="text-[10px] text-[#6f7f9a]/50">
                    No profiles match "{searchQuery}"
                  </p>
                </div>
              )}

              {filteredProfiles.length === 0 &&
                library.profiles.length === 0 && (
                  <div className="px-3 py-6 text-center">
                    <p className="text-xs text-[#6f7f9a]">
                      No profiles yet. Start from a template below or add a
                      blank profile.
                    </p>
                  </div>
                )}

              {filteredProfiles.map((profile, idx) => {
                // Find the real index in the full library for reordering
                const libraryIndex = library.profiles.findIndex(
                  (p) => p.id === profile.id,
                );
                return (
                  <ProfileListItem
                    key={profile.id}
                    profile={profile}
                    isSelected={profile.id === selectedProfileId}
                    onSelect={() => setSelectedProfileId(profile.id)}
                    onMoveUp={
                      libraryIndex > 0
                        ? () => library.reorder(libraryIndex, libraryIndex - 1)
                        : undefined
                    }
                    onMoveDown={
                      libraryIndex < library.profiles.length - 1
                        ? () => library.reorder(libraryIndex, libraryIndex + 1)
                        : undefined
                    }
                    isFirst={libraryIndex === 0}
                    isLast={libraryIndex === library.profiles.length - 1}
                  />
                );
              })}
            </div>

            {/* Templates / blueprints */}
            <div className="px-2 pb-4 mt-2">
              <div className="px-2 mb-2 flex items-center gap-2">
                <span className="w-[2px] h-2.5 rounded-full bg-[#557b8b] shrink-0" />
                <span className="text-[8.5px] font-semibold uppercase tracking-[0.12em] text-[#557b8b]">
                  Templates
                </span>
              </div>
              <div className="space-y-1">
                {BLUEPRINTS.map((bp) => (
                  <BlueprintCard
                    key={bp.name}
                    blueprint={bp}
                    onAdd={() => handleAddFromBlueprint(bp)}
                  />
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ---- Center Panel: Detail ---- */}
        <div className="flex-1 min-w-0 min-h-0 overflow-y-auto relative">
          {selectedProfile ? (
            <>
              <ProfileDetail
                key={stableKeyRef.current}
                profile={selectedProfile}
                savedPolicies={state.savedPolicies}
                activePolicy={{
                  name: state.activePolicy.name,
                  origins: state.activePolicy.origins,
                }}
                onApplyToActive={handleApplyToActive}
                onClone={handleClone}
                onDelete={() => handleDeleteRequest(selectedProfile.id)}
                onUpdate={handleProfileUpdate}
              />

              {/* Delete confirmation bar — sticky at the bottom of the scroll container */}
              {deleteConfirmId === selectedProfile.id && (
                <div className="sticky bottom-0 z-10 mx-6 mb-0 flex flex-col gap-2 px-4 py-3 rounded-t-lg bg-[#0b0d13]/95 backdrop-blur border border-[#c45c5c]/20 border-b-0 shadow-[0_-4px_12px_rgba(0,0,0,0.4)]">
                  <div className="flex items-center gap-3">
                    <IconAlertTriangle
                      size={16}
                      stroke={1.5}
                      className="text-[#c45c5c] shrink-0"
                    />
                    <span className="text-[11px] text-[#c45c5c] flex-1">
                      Delete "{selectedProfile.id}" from your library?
                    </span>
                    <button
                      onClick={() => handleDelete(selectedProfile.id)}
                      className="px-2.5 py-1 rounded text-[10px] font-medium text-[#ece7dc] bg-[#c45c5c] hover:bg-[#c45c5c]/80 transition-colors"
                    >
                      Delete
                    </button>
                    <button
                      onClick={() => {
                        setDeleteConfirmId(null);
                        setDeleteWarningPolicies([]);
                      }}
                      className="px-2.5 py-1 rounded text-[10px] font-medium text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
                    >
                      Cancel
                    </button>
                  </div>
                  {deleteWarningPolicies.length > 0 && (
                    <div className="text-[10px] text-[#d4a84b] bg-[#d4a84b]/10 rounded px-3 py-2 border border-[#d4a84b]/20">
                      This profile is referenced in: {deleteWarningPolicies.join(", ")}
                    </div>
                  )}
                </div>
              )}
            </>
          ) : (
            <OriginsIntro />
          )}
        </div>
      </div>
    </div>
  );
}
