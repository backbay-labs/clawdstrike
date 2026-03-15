import { useMemo, useCallback } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import YAML from "yaml";
import {
  parseSigmaYaml,
  type SigmaRule,
  type SigmaStatus,
  type SigmaLevel,
  type SigmaDetection,
} from "@/lib/workbench/sigma-types";
import {
  IconFileAnalytics,
  IconServer,
  IconSearch,
  IconTag,
  IconShieldQuestion,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import {
  Section,
  FieldLabel,
  TextInput,
  TextArea,
  SelectInput,
} from "./shared-form-fields";


// ---- Constants ----

const STATUS_OPTIONS: SigmaStatus[] = [
  "experimental",
  "test",
  "stable",
  "deprecated",
  "unsupported",
];

const LEVEL_OPTIONS: SigmaLevel[] = [
  "informational",
  "low",
  "medium",
  "high",
  "critical",
];

const CATEGORY_OPTIONS = [
  "process_creation",
  "file_event",
  "network_connection",
  "dns_query",
  "registry_set",
  "registry_add",
  "registry_delete",
  "registry_event",
  "image_load",
  "pipe_created",
  "driver_load",
  "file_access",
  "file_change",
  "file_delete",
  "file_rename",
  "create_remote_thread",
  "process_access",
  "process_termination",
  "sysmon_status",
  "wmi_event",
  "clipboard_capture",
  "create_stream_hash",
];

const PRODUCT_OPTIONS = [
  "windows",
  "linux",
  "macos",
  "azure",
  "aws",
  "gcp",
  "m365",
  "okta",
  "github",
  "zeek",
];

const ACCENT = "#7c9aef";


// ---- Props ----

interface SigmaVisualPanelProps {
  yaml: string;
  onYamlChange: (yaml: string) => void;
  readOnly?: boolean;
}




// ---- Detection Cards ----

function DetectionSection({ detection }: { detection: SigmaDetection }) {
  const { condition, ...selections } = detection;
  const selectionEntries = Object.entries(selections);

  return (
    <div className="flex flex-col gap-2">
      {selectionEntries.map(([name, value]) => (
        <SelectionCard key={name} name={name} value={value} />
      ))}

      {/* Condition display */}
      <div className="flex flex-col gap-1 mt-1">
        <FieldLabel label="Condition" />
        <div
          className="bg-[#0b0d13] border border-[#2d3240] rounded-lg px-3 py-2 font-mono text-[11px] leading-relaxed"
          style={{ color: ACCENT }}
        >
          {condition || "(empty)"}
        </div>
      </div>
    </div>
  );
}

function SelectionCard({ name, value }: { name: string; value: unknown }) {
  return (
    <div className="bg-[#0b0d13]/50 border border-[#2d3240] rounded-lg p-3">
      <div className="flex items-center gap-2 mb-2">
        <span
          className="text-[10px] font-semibold font-mono px-1.5 py-0.5 rounded"
          style={{
            color: ACCENT,
            backgroundColor: `${ACCENT}15`,
            border: `1px solid ${ACCENT}30`,
          }}
        >
          {name}
        </span>
      </div>
      <div className="flex flex-col gap-1">
        {renderSelectionValue(value)}
      </div>
    </div>
  );
}

function renderSelectionValue(value: unknown, depth = 0): React.ReactNode {
  if (value == null) {
    return <span className="text-[11px] font-mono text-[#6f7f9a]/50 italic">null</span>;
  }

  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return (
      <span className="text-[11px] font-mono text-[#ece7dc]/80 pl-2">
        {String(value)}
      </span>
    );
  }

  if (Array.isArray(value)) {
    return (
      <div className="flex flex-col gap-0.5" style={{ paddingLeft: depth > 0 ? 8 : 0 }}>
        {value.map((item, i) => (
          <div key={i} className="flex items-start gap-1.5">
            <span className="text-[10px] text-[#6f7f9a]/40 mt-0.5 shrink-0">-</span>
            <span className="text-[11px] font-mono text-[#ece7dc]/80 break-all">
              {typeof item === "object" ? JSON.stringify(item) : String(item)}
            </span>
          </div>
        ))}
      </div>
    );
  }

  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    return (
      <div className="flex flex-col gap-1" style={{ paddingLeft: depth > 0 ? 8 : 0 }}>
        {entries.map(([key, val]) => (
          <div key={key} className="flex flex-col gap-0.5">
            <span className="text-[10px] font-mono text-[#6f7f9a]">{key}:</span>
            {renderSelectionValue(val, depth + 1)}
          </div>
        ))}
      </div>
    );
  }

  return <span className="text-[11px] font-mono text-[#ece7dc]/50">{String(value)}</span>;
}


// ---- Tag Badges ----

function TagBadge({ tag }: { tag: string }) {
  const isAttack = tag.startsWith("attack.");
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono",
        isAttack
          ? "border"
          : "bg-[#2d3240]/50 text-[#ece7dc]/70 border border-[#2d3240]",
      )}
      style={
        isAttack
          ? {
              color: ACCENT,
              backgroundColor: `${ACCENT}10`,
              borderColor: `${ACCENT}30`,
            }
          : undefined
      }
    >
      {tag}
    </span>
  );
}


// ---- Level badge color helper ----

function levelColor(level: SigmaLevel): string {
  switch (level) {
    case "critical":
      return "#c45c5c";
    case "high":
      return "#e0915c";
    case "medium":
      return "#d4a84b";
    case "low":
      return "#3dbf84";
    case "informational":
      return "#7c9aef";
    default:
      return "#6f7f9a";
  }
}

function statusColor(status: SigmaStatus): string {
  switch (status) {
    case "stable":
      return "#3dbf84";
    case "test":
      return "#d4a84b";
    case "experimental":
      return "#7c9aef";
    case "deprecated":
      return "#e0915c";
    case "unsupported":
      return "#c45c5c";
    default:
      return "#6f7f9a";
  }
}


// ---- Main Panel ----

export function SigmaVisualPanel({ yaml: yamlText, onYamlChange, readOnly }: SigmaVisualPanelProps) {
  const { rule, errors } = useMemo(() => parseSigmaYaml(yamlText), [yamlText]);

  // Round-trip update: parse current YAML as a document, update a field, stringify back.
  const updateField = useCallback(
    (path: string[], value: unknown) => {
      try {
        const doc = YAML.parseDocument(yamlText);

        if (value === "" || value === undefined || value === null) {
          // Remove the field if value is empty
          if (path.length === 1) {
            doc.delete(path[0]);
          } else if (path.length === 2) {
            const parent = doc.get(path[0]) as YAML.YAMLMap | undefined;
            if (parent && parent instanceof YAML.YAMLMap) {
              parent.delete(path[1]);
            }
          }
        } else {
          doc.setIn(path, value);
        }

        onYamlChange(doc.toString());
      } catch {
        // If YAML doc manipulation fails, fall back to full rewrite
        // This can happen when the YAML is fundamentally broken
      }
    },
    [yamlText, onYamlChange],
  );

  return (
    <ScrollArea className="h-full">
      <div className="flex flex-col">
        {/* Format sigil */}
        <div className="flex items-center gap-2 px-4 pt-3 pb-1">
          <span className="text-base font-black tracking-tight" style={{ color: ACCENT }}>SIG</span>
          <span className="text-[10px] font-mono text-[#6f7f9a]">Sigma Detection Rule</span>
        </div>

        {/* Parse errors banner */}
        {errors.length > 0 && (
          <div className="mx-4 mt-3 p-2 bg-[#c45c5c]/10 border border-[#c45c5c]/20 rounded">
            <div className="flex flex-col gap-1">
              {errors.map((err, i) => (
                <span key={i} className="text-[10px] font-mono text-[#c45c5c]">
                  {err}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Status + Level summary bar */}
        {rule && (
          <div className="flex items-center gap-2 px-4 pt-3 pb-0">
            <span
              className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono border rounded"
              style={{
                color: statusColor(rule.status),
                borderColor: `${statusColor(rule.status)}30`,
                backgroundColor: `${statusColor(rule.status)}08`,
              }}
            >
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{ backgroundColor: statusColor(rule.status) }}
              />
              {rule.status}
            </span>
            <span
              className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono border rounded"
              style={{
                color: levelColor(rule.level),
                borderColor: `${levelColor(rule.level)}30`,
                backgroundColor: `${levelColor(rule.level)}08`,
              }}
            >
              {rule.level}
            </span>
          </div>
        )}

        {/* Section 1: Rule Header */}
        <Section title="Rule Header" icon={IconFileAnalytics} accentColor={ACCENT}>
          <TextInput
            label="Title"
            value={rule?.title ?? ""}
            onChange={(v) => updateField(["title"], v)}
            required
            readOnly={readOnly}
            accentColor={ACCENT}
          />
          <TextInput
            label="ID"
            value={rule?.id ?? ""}
            onChange={() => {}}
            readOnly
            mono
            accentColor={ACCENT}
          />
          <div className="grid grid-cols-2 gap-3">
            <SelectInput
              label="Status"
              value={rule?.status ?? "experimental"}
              options={STATUS_OPTIONS}
              onChange={(v) => updateField(["status"], v)}
              readOnly={readOnly}
              required
              accentColor={ACCENT}
            />
            <SelectInput
              label="Level"
              value={rule?.level ?? "medium"}
              options={LEVEL_OPTIONS}
              onChange={(v) => updateField(["level"], v)}
              readOnly={readOnly}
              required
              accentColor={ACCENT}
            />
          </div>
          <TextArea
            label="Description"
            value={rule?.description ?? ""}
            onChange={(v) => updateField(["description"], v || undefined)}
            placeholder="Describe what this rule detects and why it matters."
            readOnly={readOnly}
            accentColor={ACCENT}
          />
          <div className="grid grid-cols-2 gap-3">
            <TextInput
              label="Author"
              value={rule?.author ?? ""}
              onChange={(v) => updateField(["author"], v || undefined)}
              placeholder="Your name or team"
              readOnly={readOnly}
              accentColor={ACCENT}
            />
            <TextInput
              label="Date"
              value={rule?.date ?? ""}
              onChange={(v) => updateField(["date"], v || undefined)}
              placeholder="YYYY/MM/DD"
              readOnly={readOnly}
              mono
              accentColor={ACCENT}
            />
          </div>
        </Section>

        {/* Section 2: Logsource */}
        <Section title="Log Source" icon={IconServer} accentColor={ACCENT}>
          <div className="grid grid-cols-2 gap-3">
            <SelectInput
              label="Category"
              value={rule?.logsource?.category ?? ""}
              options={CATEGORY_OPTIONS}
              onChange={(v) => updateField(["logsource", "category"], v || undefined)}
              readOnly={readOnly}
              placeholder="Select category..."
              accentColor={ACCENT}
            />
            <SelectInput
              label="Product"
              value={rule?.logsource?.product ?? ""}
              options={PRODUCT_OPTIONS}
              onChange={(v) => updateField(["logsource", "product"], v || undefined)}
              readOnly={readOnly}
              placeholder="Select product..."
              accentColor={ACCENT}
            />
          </div>
          <TextInput
            label="Service"
            value={rule?.logsource?.service ?? ""}
            onChange={(v) => updateField(["logsource", "service"], v || undefined)}
            placeholder="e.g. sysmon, security, powershell"
            readOnly={readOnly}
            accentColor={ACCENT}
          />
        </Section>

        {/* Section 3: Detection */}
        <Section title="Detection" icon={IconSearch} accentColor={ACCENT}>
          {rule?.detection ? (
            <DetectionSection detection={rule.detection} />
          ) : (
            <div className="text-[11px] font-mono text-[#6f7f9a]/50 italic py-2">
              No detection logic found. Add a detection block in the YAML editor.
            </div>
          )}
        </Section>

        {/* Section 4: Tags */}
        <Section title="Tags" icon={IconTag} defaultOpen={!!(rule?.tags && rule.tags.length > 0)} accentColor={ACCENT}>
          {rule?.tags && rule.tags.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {rule.tags.map((tag, i) => (
                <TagBadge key={i} tag={tag} />
              ))}
            </div>
          ) : (
            <div className="text-[11px] font-mono text-[#6f7f9a]/50 italic py-1">
              No tags yet. Add ATT&CK tags like attack.t1059 to map this rule to techniques.
            </div>
          )}
        </Section>

        {/* Section 5: False Positives */}
        <Section
          title="False Positives"
          icon={IconShieldQuestion}
          defaultOpen={!!(rule?.falsepositives && rule.falsepositives.length > 0)}
          accentColor={ACCENT}
        >
          {rule?.falsepositives && rule.falsepositives.length > 0 ? (
            <div className="flex flex-col gap-1.5">
              {rule.falsepositives.map((fp, i) => (
                <div
                  key={i}
                  className="bg-[#0b0d13]/50 border border-[#2d3240] rounded px-3 py-2 text-[11px] font-mono text-[#ece7dc]/70 leading-relaxed"
                >
                  {fp}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-[11px] font-mono text-[#6f7f9a]/50 italic py-1">
              No false positives documented. Consider adding known benign triggers.
            </div>
          )}
        </Section>

        {/* Bottom padding */}
        <div className="h-6" />
      </div>
    </ScrollArea>
  );
}
