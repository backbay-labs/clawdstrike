import { useState, useCallback, useEffect, useRef } from "react";
import {
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
} from "@/components/ui/collapsible";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import {
  ORIGIN_ACTOR_TYPE_OPTIONS as ACTOR_TYPE_OPTIONS,
  ORIGIN_DEFAULT_BEHAVIOR_OPTIONS as DEFAULT_BEHAVIOR_OPTIONS,
  ORIGIN_PROVENANCE_OPTIONS as PROVENANCE_OPTIONS,
  ORIGIN_PROVIDER_OPTIONS as PROVIDERS,
  ORIGIN_SPACE_TYPE_OPTIONS as SPACE_TYPES,
  ORIGIN_VISIBILITY_OPTIONS as VISIBILITY_OPTIONS,
  isCustomOriginChoice as isCustomChoice,
} from "@/lib/workbench/origin-options";
import type {
  OriginsConfig,
  OriginProfile,
  OriginMatch,
  OriginDefaultBehavior,
  OriginProvider,
  SpaceType,
  Visibility,
  ProvenanceConfidence,
  ActorType,
  OriginDataPolicy,
  OriginBudgets,
  BridgePolicy,
  McpToolConfig,
  EgressAllowlistConfig,
} from "@/lib/workbench/types";
import { cn } from "@/lib/utils";
import {
  IconChevronDown,
  IconPlus,
  IconTrash,
  IconWorld,
  IconFingerprint,
} from "@tabler/icons-react";

function createEmptyProfile(): OriginProfile {
  return {
    id: `profile-${crypto.randomUUID()}`,
    match_rules: {},
    explanation: "",
  };
}

function createEmptyOriginsConfig(): OriginsConfig {
  return {
    default_behavior: "deny",
    profiles: [],
  };
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function OriginEditor() {
  const { state, dispatch } = useWorkbench();
  const origins = state.activePolicy.origins;
  const isV14 = state.activePolicy.version === "1.4.0";

  const handleToggleOrigins = useCallback(
    (checked: boolean) => {
      if (checked) {
        dispatch({
          type: "UPDATE_ORIGINS",
          origins: origins ?? createEmptyOriginsConfig(),
        });
      } else {
        dispatch({ type: "UPDATE_ORIGINS", origins: undefined });
      }
    },
    [dispatch, origins],
  );

  const updateOrigins = useCallback(
    (updated: OriginsConfig) => {
      dispatch({ type: "UPDATE_ORIGINS", origins: updated });
    },
    [dispatch],
  );

  const handleDefaultBehaviorChange = useCallback(
    (value: string | null) => {
      if (!origins || value == null) return;
      updateOrigins({
        ...origins,
        profiles: origins.profiles ?? [],
        default_behavior: value as OriginDefaultBehavior,
      });
    },
    [origins, updateOrigins],
  );

  const handleAddProfile = useCallback(() => {
    if (!origins) return;
    updateOrigins({
      ...origins,
      profiles: [...(origins.profiles ?? []), createEmptyProfile()],
    });
  }, [origins, updateOrigins]);

  const handleRemoveProfile = useCallback(
    (index: number) => {
      if (!origins) return;
      const profiles = (origins.profiles ?? []).filter((_, i) => i !== index);
      updateOrigins({ ...origins, profiles });
    },
    [origins, updateOrigins],
  );

  const handleUpdateProfile = useCallback(
    (index: number, updated: OriginProfile) => {
      if (!origins) return;
      const profiles = [...(origins.profiles ?? [])];
      profiles[index] = updated;
      updateOrigins({ ...origins, profiles });
    },
    [origins, updateOrigins],
  );

  // Don't render if not v1.4.0 — placed after all hooks to satisfy Rules of Hooks
  if (!isV14) return null;

  const enabled = Boolean(origins);
  const safeOrigins: OriginsConfig = {
    default_behavior: origins?.default_behavior ?? "deny",
    profiles: origins?.profiles ?? [],
  };

  return (
    <div className="flex flex-col gap-4 p-4 border-t border-[#2d3240]">
      {/* Section header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <IconWorld size={14} stroke={1.5} className="text-[#d4a84b]" />
          <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
            Origin Enforcement
          </h3>
          <span className="inline-flex items-center px-1.5 py-0 text-[9px] font-mono text-[#d4a84b] border border-[#d4a84b]/20 bg-[#d4a84b]/5 rounded">
            v1.4.0
          </span>
        </div>
        <Switch
          checked={enabled}
          onCheckedChange={handleToggleOrigins}
          className="data-checked:bg-[#d4a84b]"
          size="sm"
        />
      </div>

      {enabled && origins && (
        <div className="flex flex-col gap-4">
          {/* Default behavior selector */}
          <div className="flex items-center justify-between gap-3">
            <div className="flex flex-col gap-0.5">
              <label className="text-xs text-[#ece7dc]">Default Behavior</label>
              <span className="text-[10px] text-[#6f7f9a]">
                Action when no origin profile matches
              </span>
            </div>
            <Select
              value={safeOrigins.default_behavior ?? "deny"}
              onValueChange={handleDefaultBehaviorChange}
            >
              <SelectTrigger className="w-40 bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-[#131721] border-[#2d3240]">
                {DEFAULT_BEHAVIOR_OPTIONS.map((opt) => (
                  <SelectItem
                    key={opt.value}
                    value={opt.value}
                    className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                  >
                    {opt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Profile cards */}
          <div className="flex flex-col gap-2">
            {(origins?.profiles ?? []).map((profile, idx) => (
              <OriginProfileCard
                key={profile.id}
                profile={profile}
                index={idx}
                onUpdate={(updated) => handleUpdateProfile(idx, updated)}
                onRemove={() => handleRemoveProfile(idx)}
              />
            ))}
          </div>

          {/* Add profile button */}
          <button
            onClick={handleAddProfile}
            className="flex items-center justify-center gap-1.5 w-full py-2 rounded-lg border border-dashed border-[#2d3240] text-[#6f7f9a] text-xs font-mono hover:border-[#d4a84b]/40 hover:text-[#d4a84b] transition-colors"
          >
            <IconPlus size={14} stroke={1.5} />
            Add Origin Profile
          </button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Profile card
// ---------------------------------------------------------------------------

interface OriginProfileCardProps {
  profile: OriginProfile;
  index: number;
  onUpdate: (updated: OriginProfile) => void;
  onRemove: () => void;
}

function OriginProfileCard({ profile, index, onUpdate, onRemove }: OriginProfileCardProps) {
  const [open, setOpen] = useState(false);
  const serializedMetadata = profile.metadata
    ? JSON.stringify(profile.metadata, null, 2)
    : "";
  const [metadataText, setMetadataText] = useState(() =>
    serializedMetadata,
  );
  const [metadataError, setMetadataError] = useState(false);
  const [customProviderMode, setCustomProviderMode] = useState(() =>
    isCustomChoice(profile.match_rules.provider, PROVIDERS),
  );
  const [customProviderDraft, setCustomProviderDraft] = useState(
    () => profile.match_rules.provider ?? "",
  );
  const customProviderModeRef = useRef(customProviderMode);
  const [customSpaceTypeMode, setCustomSpaceTypeMode] = useState(() =>
    isCustomChoice(profile.match_rules.space_type, SPACE_TYPES),
  );
  const [customSpaceTypeDraft, setCustomSpaceTypeDraft] = useState(
    () => profile.match_rules.space_type ?? "",
  );
  const customSpaceTypeModeRef = useRef(customSpaceTypeMode);

  useEffect(() => {
    setMetadataText(serializedMetadata);
    setMetadataError(false);
  }, [serializedMetadata]);

  useEffect(() => {
    customProviderModeRef.current = customProviderMode;
  }, [customProviderMode]);

  useEffect(() => {
    customSpaceTypeModeRef.current = customSpaceTypeMode;
  }, [customSpaceTypeMode]);

  useEffect(() => {
    if (isCustomChoice(profile.match_rules.provider, PROVIDERS)) {
      setCustomProviderMode(true);
      setCustomProviderDraft(profile.match_rules.provider ?? "");
      return;
    }

    if (profile.match_rules.provider !== undefined) {
      setCustomProviderMode(false);
      setCustomProviderDraft(profile.match_rules.provider);
      return;
    }

    if (!customProviderModeRef.current) {
      setCustomProviderDraft("");
    }
  }, [profile.match_rules.provider]);

  useEffect(() => {
    if (isCustomChoice(profile.match_rules.space_type, SPACE_TYPES)) {
      setCustomSpaceTypeMode(true);
      setCustomSpaceTypeDraft(profile.match_rules.space_type ?? "");
      return;
    }

    if (profile.match_rules.space_type !== undefined) {
      setCustomSpaceTypeMode(false);
      setCustomSpaceTypeDraft(profile.match_rules.space_type);
      return;
    }

    if (!customSpaceTypeModeRef.current) {
      setCustomSpaceTypeDraft("");
    }
  }, [profile.match_rules.space_type]);

  const updateMatchRules = useCallback(
    (patch: Partial<OriginMatch>) => {
      onUpdate({
        ...profile,
        match_rules: { ...profile.match_rules, ...patch },
      });
    },
    [profile, onUpdate],
  );

  const providerLabel = profile.match_rules.provider
    ? PROVIDERS.find((p) => p.value === profile.match_rules.provider)?.label ?? profile.match_rules.provider
    : "Any";

  const matchFieldCount = Object.values(profile.match_rules).filter(
    (v) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && v.length === 0),
  ).length;

  const summary = matchFieldCount > 0
    ? `${matchFieldCount} match rule${matchFieldCount !== 1 ? "s" : ""}`
    : "catch-all (no match rules)";

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <div
        className={cn(
          "rounded-lg border bg-[#0b0d13] transition-colors",
          "border-l-2 border-l-[#6f7f9a]/40 border-t-[#2d3240] border-r-[#2d3240] border-b-[#2d3240]",
        )}
      >
        {/* Card header */}
        <CollapsibleTrigger
          className="flex items-center gap-3 w-full px-3 py-3 text-left cursor-pointer hover:bg-[#131721]/50 transition-colors rounded-t-lg"
          render={<div role="button" tabIndex={0} />}
          nativeButton={false}
        >
          <IconFingerprint
            size={16}
            stroke={1.5}
            className="shrink-0 text-[#6f7f9a]"
          />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-medium text-[#ece7dc] truncate">
                {profile.id}
              </span>
              <span className="inline-flex items-center px-1.5 py-0 text-[9px] font-mono text-[#6f7f9a] border border-[#2d3240] rounded">
                {providerLabel}
              </span>
            </div>
            {!open && (
              <p className="text-[10px] text-[#6f7f9a] truncate mt-0.5">
                {summary}
              </p>
            )}
          </div>
          <button
            onClick={(e) => {
              e.stopPropagation();
              onRemove();
            }}
            className="shrink-0 p-1 rounded hover:bg-[#c45c5c]/10 text-[#6f7f9a] hover:text-[#c45c5c] transition-colors"
            title="Remove profile"
          >
            <IconTrash size={14} stroke={1.5} />
          </button>
          <IconChevronDown
            size={14}
            stroke={1.5}
            className={cn(
              "shrink-0 text-[#6f7f9a] transition-transform duration-150",
              open && "rotate-180",
            )}
          />
        </CollapsibleTrigger>

        {/* Card body */}
        <CollapsibleContent>
          <div className="px-3 pb-3 border-t border-[#2d3240]/50 space-y-4 pt-3">
            {/* Profile ID */}
            <FieldRow label="Profile ID">
              <Input
                value={profile.id}
                onChange={(e) => onUpdate({ ...profile, id: e.target.value })}
                placeholder="e.g. slack-internal"
                className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
              />
            </FieldRow>

            {/* Explanation */}
            <FieldRow label="Explanation">
              <Input
                value={profile.explanation ?? ""}
                onChange={(e) => onUpdate({ ...profile, explanation: e.target.value || undefined })}
                placeholder="Human-readable description of this profile"
                className="bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs placeholder:text-[#6f7f9a]/50"
              />
            </FieldRow>

            {/* Match rules section */}
            <div className="border border-[#2d3240] rounded-lg p-3 bg-[#0b0d13]/50">
              <h4 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-3">
                Match Rules
              </h4>
              <div className="space-y-3">
                {/* Provider */}
                <FieldRow label="Provider">
                  {(() => {
                    const currentVal = profile.match_rules.provider;
                    const isCustom =
                      customProviderMode ||
                      isCustomChoice(currentVal, PROVIDERS);
                    const selectVal =
                      currentVal === undefined
                        ? isCustom
                          ? "__custom__"
                          : "__none__"
                        : isCustom
                          ? "__custom__"
                          : currentVal;
                    return (
                      <div className="flex flex-col gap-1.5">
                        <Select
                          value={selectVal}
                          onValueChange={(val) => {
                            if (val === "__none__") {
                              setCustomProviderMode(false);
                              setCustomProviderDraft("");
                              updateMatchRules({ provider: undefined });
                            } else if (val === "__custom__") {
                              setCustomProviderMode(true);
                              setCustomProviderDraft(currentVal ?? "");
                              updateMatchRules({ provider: undefined });
                            } else {
                              setCustomProviderMode(false);
                              setCustomProviderDraft(val ?? "");
                              updateMatchRules({ provider: val as OriginProvider });
                            }
                          }}
                        >
                          <SelectTrigger className="bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono w-full">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent className="bg-[#131721] border-[#2d3240]">
                            <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">
                              Any
                            </SelectItem>
                            {PROVIDERS.map((p) => (
                              <SelectItem
                                key={p.value}
                                value={p.value}
                                className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                              >
                                {p.label}
                              </SelectItem>
                            ))}
                            <SelectItem value="__custom__" className="text-xs font-mono text-[#d4a84b] focus:bg-[#2d3240] focus:text-[#d4a84b]">
                              Custom...
                            </SelectItem>
                          </SelectContent>
                        </Select>
                        {isCustom && (
                          <Input
                            value={customProviderDraft}
                            onChange={(e) => {
                              const nextValue = e.target.value;
                              setCustomProviderMode(true);
                              setCustomProviderDraft(nextValue);
                              updateMatchRules({
                                provider: nextValue || undefined,
                              });
                            }}
                            placeholder="e.g. my-custom-provider"
                            className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                          />
                        )}
                      </div>
                    );
                  })()}
                </FieldRow>

                {/* Space Type */}
                <FieldRow label="Space Type">
                  {(() => {
                    const currentVal = profile.match_rules.space_type;
                    const isCustom =
                      customSpaceTypeMode ||
                      isCustomChoice(currentVal, SPACE_TYPES);
                    const selectVal =
                      currentVal === undefined
                        ? isCustom
                          ? "__custom__"
                          : "__none__"
                        : isCustom
                          ? "__custom__"
                          : currentVal;
                    return (
                      <div className="flex flex-col gap-1.5">
                        <Select
                          value={selectVal}
                          onValueChange={(val) => {
                            if (val === "__none__") {
                              setCustomSpaceTypeMode(false);
                              setCustomSpaceTypeDraft("");
                              updateMatchRules({ space_type: undefined });
                            } else if (val === "__custom__") {
                              setCustomSpaceTypeMode(true);
                              setCustomSpaceTypeDraft(currentVal ?? "");
                              updateMatchRules({ space_type: undefined });
                            } else {
                              setCustomSpaceTypeMode(false);
                              setCustomSpaceTypeDraft(val ?? "");
                              updateMatchRules({ space_type: val as SpaceType });
                            }
                          }}
                        >
                          <SelectTrigger className="bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono w-full">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent className="bg-[#131721] border-[#2d3240]">
                            <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">
                              Any
                            </SelectItem>
                            {SPACE_TYPES.map((st) => (
                              <SelectItem
                                key={st.value}
                                value={st.value}
                                className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                              >
                                {st.label}
                              </SelectItem>
                            ))}
                            <SelectItem value="__custom__" className="text-xs font-mono text-[#d4a84b] focus:bg-[#2d3240] focus:text-[#d4a84b]">
                              Custom...
                            </SelectItem>
                          </SelectContent>
                        </Select>
                        {isCustom && (
                          <Input
                            value={customSpaceTypeDraft}
                            onChange={(e) => {
                              const nextValue = e.target.value;
                              setCustomSpaceTypeMode(true);
                              setCustomSpaceTypeDraft(nextValue);
                              updateMatchRules({
                                space_type: nextValue || undefined,
                              });
                            }}
                            placeholder="e.g. my-custom-space"
                            className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                          />
                        )}
                      </div>
                    );
                  })()}
                </FieldRow>

                {/* Visibility */}
                <FieldRow label="Visibility">
                  <Select
                    value={profile.match_rules.visibility ?? "__none__"}
                    onValueChange={(val) =>
                      updateMatchRules({
                        visibility: val === "__none__" ? undefined : val as Visibility,
                      })
                    }
                  >
                    <SelectTrigger className="bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-[#131721] border-[#2d3240]">
                      <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">
                        Any
                      </SelectItem>
                      {VISIBILITY_OPTIONS.map((v) => (
                        <SelectItem
                          key={v.value}
                          value={v.value}
                          className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                        >
                          {v.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FieldRow>

                {/* Tenant ID */}
                <FieldRow label="Tenant ID">
                  <Input
                    value={profile.match_rules.tenant_id ?? ""}
                    onChange={(e) =>
                      updateMatchRules({ tenant_id: e.target.value || undefined })
                    }
                    placeholder="e.g. T12345"
                    className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                  />
                </FieldRow>

                {/* Space ID */}
                <FieldRow label="Space ID">
                  <Input
                    value={profile.match_rules.space_id ?? ""}
                    onChange={(e) =>
                      updateMatchRules({ space_id: e.target.value || undefined })
                    }
                    placeholder="e.g. C99999"
                    className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                  />
                </FieldRow>

                {/* Thread ID */}
                <FieldRow label="Thread ID">
                  <Input
                    value={profile.match_rules.thread_id ?? ""}
                    onChange={(e) =>
                      updateMatchRules({ thread_id: e.target.value || undefined })
                    }
                    placeholder="e.g. 1234567890.123456"
                    className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                  />
                </FieldRow>

                {/* External Participants */}
                <div className="flex items-center justify-between gap-3">
                  <label className="text-xs text-[#ece7dc]">External Participants</label>
                  <div className="flex items-center gap-2">
                    <Select
                      value={
                        profile.match_rules.external_participants === undefined
                          ? "__none__"
                          : profile.match_rules.external_participants
                            ? "true"
                            : "false"
                      }
                      onValueChange={(val) =>
                        updateMatchRules({
                          external_participants:
                            val === "__none__" ? undefined : val === "true",
                        })
                      }
                    >
                      <SelectTrigger className="w-24 bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="bg-[#131721] border-[#2d3240]">
                        <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">Any</SelectItem>
                        <SelectItem value="true" className="text-xs font-mono text-[#ece7dc]">Yes</SelectItem>
                        <SelectItem value="false" className="text-xs font-mono text-[#ece7dc]">No</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                {/* Tags */}
                <FieldRow label="Tags">
                  <Input
                    value={(profile.match_rules.tags ?? []).join(", ")}
                    onChange={(e) => {
                      const raw = e.target.value;
                      const tags = raw
                        .split(",")
                        .map((t) => t.trim())
                        .filter(Boolean);
                      updateMatchRules({ tags: tags.length > 0 ? tags : undefined });
                    }}
                    placeholder="e.g. hipaa, pci (comma-separated)"
                    className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                  />
                </FieldRow>

                {/* Sensitivity */}
                <FieldRow label="Sensitivity">
                  <Input
                    value={profile.match_rules.sensitivity ?? ""}
                    onChange={(e) =>
                      updateMatchRules({ sensitivity: e.target.value || undefined })
                    }
                    placeholder="e.g. high, medium, low"
                    className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                  />
                </FieldRow>

                {/* Actor ID */}
                <FieldRow label="Actor ID">
                  <Input
                    value={profile.match_rules.actor_id ?? ""}
                    onChange={(e) =>
                      updateMatchRules({ actor_id: e.target.value || undefined })
                    }
                    placeholder="e.g. U12345, bot-ci-runner"
                    className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                  />
                </FieldRow>

                {/* Actor Type */}
                <FieldRow label="Actor Type">
                  <Select
                    value={profile.match_rules.actor_type ?? "__none__"}
                    onValueChange={(val) =>
                      updateMatchRules({
                        actor_type: val === "__none__" ? undefined : val as ActorType,
                      })
                    }
                  >
                    <SelectTrigger className="bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-[#131721] border-[#2d3240]">
                      <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">Any</SelectItem>
                      {ACTOR_TYPE_OPTIONS.map((at) => (
                        <SelectItem
                          key={at.value}
                          value={at.value}
                          className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                        >
                          {at.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FieldRow>

                {/* Actor Role */}
                <FieldRow label="Actor Role">
                  <Input
                    value={profile.match_rules.actor_role ?? ""}
                    onChange={(e) =>
                      updateMatchRules({ actor_role: e.target.value || undefined })
                    }
                    placeholder="e.g. admin, incident_commander"
                    className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                  />
                </FieldRow>

                {/* Provenance Confidence */}
                <FieldRow label="Provenance">
                  <Select
                    value={profile.match_rules.provenance_confidence ?? "__none__"}
                    onValueChange={(val) =>
                      updateMatchRules({
                        provenance_confidence: val === "__none__" ? undefined : val as ProvenanceConfidence,
                      })
                    }
                  >
                    <SelectTrigger className="bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-[#131721] border-[#2d3240]">
                      <SelectItem value="__none__" className="text-xs font-mono text-[#6f7f9a]">Any</SelectItem>
                      {PROVENANCE_OPTIONS.map((po) => (
                        <SelectItem
                          key={po.value}
                          value={po.value}
                          className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                        >
                          {po.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FieldRow>
              </div>
            </div>

            {/* Metadata */}
            <div className="border border-[#2d3240] rounded-lg p-3 bg-[#0b0d13]/50">
              <h4 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-3">
                Metadata
              </h4>
              <div className="space-y-1">
                <textarea
                  value={metadataText}
                  onChange={(e) => {
                    setMetadataText(e.target.value);
                    setMetadataError(false);
                  }}
                  onBlur={() => {
                    const trimmed = metadataText.trim();
                    if (trimmed === "") {
                      setMetadataError(false);
                      onUpdate({ ...profile, metadata: undefined });
                      return;
                    }
                    try {
                      const parsed = JSON.parse(trimmed);
                      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
                        setMetadataError(true);
                        return;
                      }
                      setMetadataError(false);
                      onUpdate({ ...profile, metadata: parsed as Record<string, unknown> });
                    } catch {
                      setMetadataError(true);
                    }
                  }}
                  placeholder='{"key": "value"}'
                  rows={3}
                  className={cn(
                    "w-full rounded-md px-3 py-2 bg-[#131721] border text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50 resize-y",
                    metadataError
                      ? "border-[#c45c5c] focus:ring-[#c45c5c]"
                      : "border-[#2d3240] focus:ring-[#d4a84b]",
                  )}
                />
                {metadataError && (
                  <p className="text-[10px] text-[#c45c5c] font-mono">
                    Invalid JSON object
                  </p>
                )}
              </div>
            </div>

            {/* Profile overrides section */}
            <ProfileOverrides profile={profile} onUpdate={onUpdate} />
          </div>
        </CollapsibleContent>
      </div>
    </Collapsible>
  );
}

// ---------------------------------------------------------------------------
// Profile overrides (guard/egress/data/budgets/bridge)
// ---------------------------------------------------------------------------

function ProfileOverrides({
  profile,
  onUpdate,
}: {
  profile: OriginProfile;
  onUpdate: (updated: OriginProfile) => void;
}) {
  return (
    <div className="border border-[#2d3240] rounded-lg p-3 bg-[#0b0d13]/50">
      <h4 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-3">
        Profile Overrides
      </h4>
      <div className="space-y-4">
        {/* Posture state */}
        <FieldRow label="Posture State" title="Resource usage limits and automated state transitions for agent capabilities">
          <Input
            value={profile.posture ?? ""}
            onChange={(e) =>
              onUpdate({ ...profile, posture: e.target.value || undefined })
            }
            placeholder="e.g. standard, locked"
            className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
          />
        </FieldRow>

        {/* MCP Tool Config */}
        <McpOverrideSection
          mcp={profile.mcp}
          onChange={(mcp) => onUpdate({ ...profile, mcp })}
        />

        {/* Egress Config */}
        <EgressOverrideSection
          egress={profile.egress}
          onChange={(egress) => onUpdate({ ...profile, egress })}
        />

        {/* Data Policy */}
        <DataPolicySection
          data={profile.data}
          onChange={(data) => onUpdate({ ...profile, data })}
        />

        {/* Budgets */}
        <BudgetsSection
          budgets={profile.budgets}
          onChange={(budgets) => onUpdate({ ...profile, budgets })}
        />

        {/* Bridge Policy */}
        <BridgePolicySection
          bridgePolicy={profile.bridge_policy}
          onChange={(bridge_policy) => onUpdate({ ...profile, bridge_policy })}
        />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// MCP override section
// ---------------------------------------------------------------------------

function McpOverrideSection({
  mcp,
  onChange,
}: {
  mcp: McpToolConfig | undefined;
  onChange: (mcp: McpToolConfig | undefined) => void;
}) {
  const enabled = Boolean(mcp);

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <label className="text-xs text-[#ece7dc]">MCP Tool Override</label>
        <Switch
          checked={enabled}
          onCheckedChange={(checked) => {
            if (checked) {
              onChange({ enabled: true, allow: [], block: [], default_action: "block" });
            } else {
              onChange(undefined);
            }
          }}
          className="data-checked:bg-[#d4a84b]"
          size="sm"
        />
      </div>
      {enabled && mcp && (
        <div className="pl-2 border-l-2 border-[#2d3240] space-y-2">
          <FieldRow label="Allow">
            <Input
              value={(mcp.allow ?? []).join(", ")}
              onChange={(e) => {
                const arr = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
                onChange({ ...mcp, allow: arr });
              }}
              placeholder="tool_a, tool_b"
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
          </FieldRow>
          <FieldRow label="Block">
            <Input
              value={(mcp.block ?? []).join(", ")}
              onChange={(e) => {
                const arr = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
                onChange({ ...mcp, block: arr });
              }}
              placeholder="dangerous_tool"
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
          </FieldRow>
          <FieldRow label="Require Confirmation">
            <Input
              value={(mcp.require_confirmation ?? []).join(", ")}
              onChange={(e) => {
                const arr = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
                onChange({ ...mcp, require_confirmation: arr.length > 0 ? arr : undefined });
              }}
              placeholder="deploy, delete_record"
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
          </FieldRow>
          <FieldRow label="Default Action">
            <Select
              value={mcp.default_action ?? "block"}
              onValueChange={(val) => onChange({ ...mcp, default_action: val as "allow" | "block" })}
            >
              <SelectTrigger className="w-24 bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-[#131721] border-[#2d3240]">
                <SelectItem value="allow" className="text-xs font-mono text-[#ece7dc]">Allow</SelectItem>
                <SelectItem value="block" className="text-xs font-mono text-[#ece7dc]">Block</SelectItem>
              </SelectContent>
            </Select>
          </FieldRow>
          <FieldRow label="Max Args Size">
            <Input
              type="number"
              min={0}
              value={mcp.max_args_size ?? ""}
              onChange={(e) => {
                const parsed = parseInt(e.target.value, 10);
                const v = Number.isNaN(parsed) ? undefined : Math.max(0, parsed);
                onChange({ ...mcp, max_args_size: v });
              }}
              placeholder="bytes"
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs w-24 placeholder:text-[#6f7f9a]/50"
            />
          </FieldRow>

          {/* Merge-mode fields for profile inheritance */}
          <div className="border-t border-[#2d3240]/50 pt-2 mt-2">
            <p className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-2">
              Merge Overrides
            </p>
            <div className="space-y-2">
              <FieldRow label="Additional Allow">
                <Input
                  value={(mcp.additional_allow ?? []).join(", ")}
                  onChange={(e) => {
                    const arr = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
                    onChange({ ...mcp, additional_allow: arr.length > 0 ? arr : undefined });
                  }}
                  placeholder="extra_tool_a"
                  className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                />
              </FieldRow>
              <FieldRow label="Additional Block">
                <Input
                  value={(mcp.additional_block ?? []).join(", ")}
                  onChange={(e) => {
                    const arr = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
                    onChange({ ...mcp, additional_block: arr.length > 0 ? arr : undefined });
                  }}
                  placeholder="extra_blocked_tool"
                  className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                />
              </FieldRow>
              <FieldRow label="Remove Allow">
                <Input
                  value={(mcp.remove_allow ?? []).join(", ")}
                  onChange={(e) => {
                    const arr = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
                    onChange({ ...mcp, remove_allow: arr.length > 0 ? arr : undefined });
                  }}
                  placeholder="revoke_tool_a"
                  className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                />
              </FieldRow>
              <FieldRow label="Remove Block">
                <Input
                  value={(mcp.remove_block ?? []).join(", ")}
                  onChange={(e) => {
                    const arr = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
                    onChange({ ...mcp, remove_block: arr.length > 0 ? arr : undefined });
                  }}
                  placeholder="unblock_tool_a"
                  className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
                />
              </FieldRow>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Egress override section
// ---------------------------------------------------------------------------

function EgressOverrideSection({
  egress,
  onChange,
}: {
  egress: EgressAllowlistConfig | undefined;
  onChange: (egress: EgressAllowlistConfig | undefined) => void;
}) {
  const enabled = Boolean(egress);

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <label className="text-xs text-[#ece7dc]">Egress Override</label>
        <Switch
          checked={enabled}
          onCheckedChange={(checked) => {
            if (checked) {
              onChange({ enabled: true, allow: [], block: [], default_action: "block" });
            } else {
              onChange(undefined);
            }
          }}
          className="data-checked:bg-[#d4a84b]"
          size="sm"
        />
      </div>
      {enabled && egress && (
        <div className="pl-2 border-l-2 border-[#2d3240] space-y-2">
          <FieldRow label="Allow">
            <Input
              value={(egress.allow ?? []).join(", ")}
              onChange={(e) => {
                const arr = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
                onChange({ ...egress, allow: arr });
              }}
              placeholder="*.example.com, api.github.com"
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
          </FieldRow>
          <FieldRow label="Block">
            <Input
              value={(egress.block ?? []).join(", ")}
              onChange={(e) => {
                const arr = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
                onChange({ ...egress, block: arr });
              }}
              placeholder="evil.com"
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/50"
            />
          </FieldRow>
          <FieldRow label="Default Action">
            <Select
              value={egress.default_action ?? "block"}
              onValueChange={(val) => onChange({ ...egress, default_action: val as "allow" | "block" | "log" })}
            >
              <SelectTrigger className="w-24 bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-[#131721] border-[#2d3240]">
                <SelectItem value="allow" className="text-xs font-mono text-[#ece7dc]">Allow</SelectItem>
                <SelectItem value="block" className="text-xs font-mono text-[#ece7dc]">Block</SelectItem>
                <SelectItem value="log" className="text-xs font-mono text-[#ece7dc]">Log</SelectItem>
              </SelectContent>
            </Select>
          </FieldRow>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Data policy section
// ---------------------------------------------------------------------------

function DataPolicySection({
  data,
  onChange,
}: {
  data: OriginDataPolicy | undefined;
  onChange: (data: OriginDataPolicy | undefined) => void;
}) {
  const enabled = Boolean(data);

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <label className="text-xs text-[#ece7dc]">Data Policy</label>
        <Switch
          checked={enabled}
          onCheckedChange={(checked) => {
            if (checked) {
              onChange({
                allow_external_sharing: false,
                redact_before_send: false,
                block_sensitive_outputs: false,
              });
            } else {
              onChange(undefined);
            }
          }}
          className="data-checked:bg-[#d4a84b]"
          size="sm"
        />
      </div>
      {enabled && data && (
        <div className="pl-2 border-l-2 border-[#2d3240] space-y-2">
          <ToggleRow
            label="Allow External Sharing"
            checked={data.allow_external_sharing ?? false}
            onChange={(v) => onChange({ ...data, allow_external_sharing: v })}
          />
          <ToggleRow
            label="Redact Before Send"
            checked={data.redact_before_send ?? false}
            onChange={(v) => onChange({ ...data, redact_before_send: v })}
          />
          <ToggleRow
            label="Block Sensitive Outputs"
            checked={data.block_sensitive_outputs ?? false}
            onChange={(v) => onChange({ ...data, block_sensitive_outputs: v })}
          />
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Budgets section
// ---------------------------------------------------------------------------

function BudgetsSection({
  budgets,
  onChange,
}: {
  budgets: OriginBudgets | undefined;
  onChange: (budgets: OriginBudgets | undefined) => void;
}) {
  const enabled = Boolean(budgets);

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <label className="text-xs text-[#ece7dc]">Budget Overrides</label>
        <Switch
          checked={enabled}
          onCheckedChange={(checked) => {
            if (checked) {
              onChange({});
            } else {
              onChange(undefined);
            }
          }}
          className="data-checked:bg-[#d4a84b]"
          size="sm"
        />
      </div>
      {enabled && budgets && (
        <div className="pl-2 border-l-2 border-[#2d3240] space-y-2">
          <FieldRow label="MCP Tool Calls">
            <Input
              type="number"
              min={0}
              value={budgets.mcp_tool_calls ?? ""}
              onChange={(e) => {
                const parsed = parseInt(e.target.value, 10);
                const v = Number.isNaN(parsed) ? undefined : Math.max(0, parsed);
                onChange({ ...budgets, mcp_tool_calls: v });
              }}
              placeholder="unlimited"
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs w-24 placeholder:text-[#6f7f9a]/50"
            />
          </FieldRow>
          <FieldRow label="Egress Calls">
            <Input
              type="number"
              min={0}
              value={budgets.egress_calls ?? ""}
              onChange={(e) => {
                const parsed = parseInt(e.target.value, 10);
                const v = Number.isNaN(parsed) ? undefined : Math.max(0, parsed);
                onChange({ ...budgets, egress_calls: v });
              }}
              placeholder="unlimited"
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs w-24 placeholder:text-[#6f7f9a]/50"
            />
          </FieldRow>
          <FieldRow label="Shell Commands">
            <Input
              type="number"
              min={0}
              value={budgets.shell_commands ?? ""}
              onChange={(e) => {
                const parsed = parseInt(e.target.value, 10);
                const v = Number.isNaN(parsed) ? undefined : Math.max(0, parsed);
                onChange({ ...budgets, shell_commands: v });
              }}
              placeholder="unlimited"
              className="bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono text-xs w-24 placeholder:text-[#6f7f9a]/50"
            />
          </FieldRow>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Bridge policy section
// ---------------------------------------------------------------------------

function BridgePolicySection({
  bridgePolicy,
  onChange,
}: {
  bridgePolicy: BridgePolicy | undefined;
  onChange: (bp: BridgePolicy | undefined) => void;
}) {
  const enabled = Boolean(bridgePolicy);

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <label className="text-xs text-[#ece7dc]">Bridge Policy</label>
        <Switch
          checked={enabled}
          onCheckedChange={(checked) => {
            if (checked) {
              onChange({
                allow_cross_origin: false,
                allowed_targets: [],
                require_approval: true,
              });
            } else {
              onChange(undefined);
            }
          }}
          className="data-checked:bg-[#d4a84b]"
          size="sm"
        />
      </div>
      {enabled && bridgePolicy && (
        <div className="pl-2 border-l-2 border-[#2d3240] space-y-2">
          <ToggleRow
            label="Allow Cross-Origin"
            checked={bridgePolicy.allow_cross_origin ?? false}
            onChange={(v) => onChange({ ...bridgePolicy, allow_cross_origin: v })}
          />
          <ToggleRow
            label="Require Approval"
            checked={bridgePolicy.require_approval ?? true}
            onChange={(v) => onChange({ ...bridgePolicy, require_approval: v })}
          />
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Shared micro-components
// ---------------------------------------------------------------------------

function FieldRow({
  label,
  children,
  title,
}: {
  label: string;
  children: React.ReactNode;
  title?: string;
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      <label className="text-xs text-[#ece7dc] whitespace-nowrap" title={title}>{label}</label>
      <div className="flex-1 max-w-[200px]">{children}</div>
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
    <div className="flex items-center justify-between gap-3">
      <label className="text-xs text-[#ece7dc]">{label}</label>
      <Switch
        checked={checked}
        onCheckedChange={(v) => onChange(!!v)}
        className="data-checked:bg-[#d4a84b]"
        size="sm"
      />
    </div>
  );
}
