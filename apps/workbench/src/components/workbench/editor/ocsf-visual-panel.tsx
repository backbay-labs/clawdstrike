import { useMemo, useCallback, useState } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  IconFileAnalytics,
  IconInfoCircle,
  IconSearch,
  IconShieldCheck,
  IconChecks,
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

const ACCENT = "#5cc5c4";

const CLASS_UID_OPTIONS = [
  { value: 1001, label: "1001 — File Activity" },
  { value: 1007, label: "1007 — Process Activity" },
  { value: 2004, label: "2004 — Detection Finding" },
  { value: 4001, label: "4001 — Network Activity" },
];

const CATEGORY_FROM_CLASS: Record<number, { uid: number; name: string }> = {
  1001: { uid: 1, name: "System Activity" },
  1007: { uid: 1, name: "System Activity" },
  2004: { uid: 2, name: "Findings" },
  4001: { uid: 4, name: "Network Activity" },
};

const SEVERITY_OPTIONS = [
  { value: 0, label: "0 — Unknown" },
  { value: 1, label: "1 — Informational" },
  { value: 2, label: "2 — Low" },
  { value: 3, label: "3 — Medium" },
  { value: 4, label: "4 — High" },
  { value: 5, label: "5 — Critical" },
  { value: 6, label: "6 — Fatal" },
];

const ACTIVITY_OPTIONS = [
  { value: 1, label: "1 — Create" },
  { value: 2, label: "2 — Update" },
  { value: 3, label: "3 — Close" },
];

const STATUS_OPTIONS = [
  { value: 0, label: "0 — Unknown" },
  { value: 1, label: "1 — Success" },
  { value: 2, label: "2 — Failure" },
];

const ACTION_OPTIONS = [
  { value: 0, label: "0 — Unknown" },
  { value: 1, label: "1 — Allowed" },
  { value: 2, label: "2 — Denied" },
];

const DISPOSITION_OPTIONS = [
  { value: 1, label: "1 — Allowed" },
  { value: 2, label: "2 — Blocked" },
  { value: 17, label: "17 — Logged" },
];

/** Required top-level fields for a minimal OCSF event. */
const REQUIRED_FIELDS = ["class_uid", "category_uid", "activity_id", "severity_id", "time", "metadata"];


// ---- Props ----

interface OcsfVisualPanelProps {
  json: string;
  onJsonChange: (json: string) => void;
  readOnly?: boolean;
}


// ---- OCSF-specific Field Components ----

function NumberInput({
  label,
  value,
  onChange,
  placeholder,
  required,
  readOnly,
}: {
  label: string;
  value: number | undefined;
  onChange: (value: number | undefined) => void;
  placeholder?: string;
  required?: boolean;
  readOnly?: boolean;
}) {
  const [focused, setFocused] = useState(false);

  return (
    <div className="flex flex-col gap-1">
      <FieldLabel label={label} required={required} />
      <input
        type="number"
        value={value ?? ""}
        onChange={(e) => {
          const v = e.target.value;
          onChange(v === "" ? undefined : Number(v));
        }}
        placeholder={placeholder}
        readOnly={readOnly}
        style={focused ? { borderColor: `${ACCENT}80` } : undefined}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        className={cn(
          "bg-[#0b0d13] border border-[#2d3240] rounded text-[11px] font-mono text-[#ece7dc] px-2 py-1 outline-none transition-colors",
          readOnly && "opacity-60 cursor-default",
        )}
      />
    </div>
  );
}


// ---- Severity badge color helper ----

function severityColor(id: number): string {
  switch (id) {
    case 5: return "#c45c5c";   // Critical
    case 6: return "#c45c5c";   // Fatal
    case 4: return "#e0915c";   // High
    case 3: return "#d4a84b";   // Medium
    case 2: return "#3dbf84";   // Low
    case 1: return "#5cc5c4";   // Informational
    default: return "#6f7f9a";  // Unknown
  }
}

function severityLabel(id: number): string {
  const opt = SEVERITY_OPTIONS.find((o) => o.value === id);
  return opt ? opt.label : `${id}`;
}


// ---- Deep get/set helpers ----

function deepGet(obj: Record<string, unknown>, path: string[]): unknown {
  let current: unknown = obj;
  for (const key of path) {
    if (current == null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

function deepSet(obj: Record<string, unknown>, path: string[], value: unknown): Record<string, unknown> {
  const result = { ...obj };
  if (path.length === 1) {
    if (value === undefined || value === null || value === "") {
      delete result[path[0]];
    } else {
      result[path[0]] = value;
    }
    return result;
  }

  const [head, ...rest] = path;
  const child = (result[head] != null && typeof result[head] === "object")
    ? { ...(result[head] as Record<string, unknown>) }
    : {};
  result[head] = deepSet(child, rest, value);
  return result;
}


// ---- Main Panel ----

export function OcsfVisualPanel({ json, onJsonChange, readOnly }: OcsfVisualPanelProps) {
  const { event, parseError } = useMemo(() => {
    try {
      const parsed = JSON.parse(json || "{}");
      return { event: parsed as Record<string, unknown>, parseError: null };
    } catch (e) {
      return { event: {} as Record<string, unknown>, parseError: (e as Error).message };
    }
  }, [json]);

  const updateField = useCallback(
    (path: string[], value: unknown) => {
      try {
        const current = JSON.parse(json || "{}") as Record<string, unknown>;
        const updated = deepSet(current, path, value);
        onJsonChange(JSON.stringify(updated, null, 2));
      } catch {
        // If JSON is fundamentally broken, do nothing
      }
    },
    [json, onJsonChange],
  );

  // Convenience getters
  const classUid = (event.class_uid as number) ?? 0;
  const severityId = (event.severity_id as number) ?? 0;
  const isDetectionFinding = classUid === 2004;

  // Validation summary
  const filledRequired = useMemo(() => {
    let count = 0;
    for (const field of REQUIRED_FIELDS) {
      if (event[field] !== undefined && event[field] !== null && event[field] !== "") {
        count++;
      }
    }
    return count;
  }, [event]);

  const validationErrors = useMemo(() => {
    const errors: string[] = [];
    if (parseError) {
      errors.push(`JSON parse error: ${parseError}`);
    }
    if (!event.class_uid && event.class_uid !== 0) {
      errors.push("class_uid is required");
    }
    if (!event.category_uid && event.category_uid !== 0) {
      errors.push("category_uid is required");
    }
    if (event.time === undefined || event.time === null) {
      errors.push("time is required");
    }
    if (!event.metadata) {
      errors.push("metadata object is required");
    }
    return errors;
  }, [event, parseError]);

  // Derive category info
  const categoryInfo = CATEGORY_FROM_CLASS[classUid];

  return (
    <ScrollArea className="h-full">
      <div className="flex flex-col">
        {/* Parse errors banner */}
        {parseError && (
          <div className="mx-4 mt-3 p-2 bg-[#c45c5c]/10 border border-[#c45c5c]/20 rounded">
            <span className="text-[10px] font-mono text-[#c45c5c]">
              {parseError}
            </span>
          </div>
        )}

        {/* Severity + Class summary bar */}
        <div className="flex items-center gap-2 px-4 pt-3 pb-0">
          {classUid > 0 && (
            <span
              className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono border rounded"
              style={{
                color: ACCENT,
                borderColor: `${ACCENT}30`,
                backgroundColor: `${ACCENT}08`,
              }}
            >
              {CLASS_UID_OPTIONS.find((o) => o.value === classUid)?.label ?? `Class ${classUid}`}
            </span>
          )}
          {severityId > 0 && (
            <span
              className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono border rounded"
              style={{
                color: severityColor(severityId),
                borderColor: `${severityColor(severityId)}30`,
                backgroundColor: `${severityColor(severityId)}08`,
              }}
            >
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{ backgroundColor: severityColor(severityId) }}
              />
              {severityLabel(severityId)}
            </span>
          )}
        </div>

        {/* Section 1: Event Class */}
        <Section title="Event Class" icon={IconFileAnalytics} accentColor={ACCENT}>
          <SelectInput
            label="Class UID"
            value={classUid ? String(classUid) : ""}
            options={CLASS_UID_OPTIONS}
            onChange={(v) => {
              const numVal = Number(v);
              updateField(["class_uid"], numVal || undefined);
              // Auto-derive category_uid
              const cat = CATEGORY_FROM_CLASS[numVal];
              if (cat) {
                updateField(["category_uid"], cat.uid);
              }
            }}
            readOnly={readOnly}
            required
            placeholder="Select event class..."
            accentColor={ACCENT}
          />
          <div className="flex flex-col gap-1">
            <FieldLabel label="Category UID" />
            <div
              className="bg-[#0b0d13]/50 border border-[#2d3240] rounded px-2 py-1 text-[11px] font-mono text-[#ece7dc]/60"
            >
              {categoryInfo
                ? `${categoryInfo.uid} — ${categoryInfo.name}`
                : (event.category_uid != null ? String(event.category_uid) : "—")}
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <SelectInput
              label="Activity ID"
              value={event.activity_id != null ? String(event.activity_id) : ""}
              options={ACTIVITY_OPTIONS}
              onChange={(v) => updateField(["activity_id"], v ? Number(v) : undefined)}
              readOnly={readOnly}
              required
              placeholder="Select..."
              accentColor={ACCENT}
            />
            <SelectInput
              label="Severity ID"
              value={severityId ? String(severityId) : ""}
              options={SEVERITY_OPTIONS}
              onChange={(v) => updateField(["severity_id"], v ? Number(v) : undefined)}
              readOnly={readOnly}
              required
              placeholder="Select..."
              accentColor={ACCENT}
            />
          </div>
        </Section>

        {/* Section 2: Metadata */}
        <Section title="Metadata" icon={IconInfoCircle} accentColor={ACCENT}>
          <TextInput
            label="Version"
            value={String(deepGet(event, ["metadata", "version"]) ?? "1.4.0")}
            onChange={(v) => updateField(["metadata", "version"], v || undefined)}
            placeholder="1.4.0"
            readOnly={readOnly}
            mono
            accentColor={ACCENT}
          />
          <TextInput
            label="Product Name"
            value={String(deepGet(event, ["metadata", "product", "name"]) ?? "")}
            onChange={(v) => updateField(["metadata", "product", "name"], v || undefined)}
            placeholder="Product name"
            readOnly={readOnly}
            accentColor={ACCENT}
          />
          <TextInput
            label="Vendor Name"
            value={String(deepGet(event, ["metadata", "product", "vendor_name"]) ?? "")}
            onChange={(v) => updateField(["metadata", "product", "vendor_name"], v || undefined)}
            placeholder="Vendor name"
            readOnly={readOnly}
            accentColor={ACCENT}
          />
          <TextInput
            label="Product UID"
            value={String(deepGet(event, ["metadata", "product", "uid"]) ?? "")}
            onChange={(v) => updateField(["metadata", "product", "uid"], v || undefined)}
            placeholder="Unique product identifier"
            readOnly={readOnly}
            mono
            accentColor={ACCENT}
          />
        </Section>

        {/* Section 3: Finding Info (shown when class_uid is 2004) */}
        {isDetectionFinding && (
          <Section title="Finding Info" icon={IconSearch} accentColor={ACCENT}>
            <TextInput
              label="Finding UID"
              value={String(deepGet(event, ["finding_info", "uid"]) ?? "")}
              onChange={(v) => updateField(["finding_info", "uid"], v || undefined)}
              placeholder="Unique finding identifier"
              readOnly={readOnly}
              mono
              accentColor={ACCENT}
            />
            <TextInput
              label="Title"
              value={String(deepGet(event, ["finding_info", "title"]) ?? "")}
              onChange={(v) => updateField(["finding_info", "title"], v || undefined)}
              placeholder="Finding title"
              readOnly={readOnly}
              accentColor={ACCENT}
            />
            <TextArea
              label="Description"
              value={String(deepGet(event, ["finding_info", "desc"]) ?? "")}
              onChange={(v) => updateField(["finding_info", "desc"], v || undefined)}
              placeholder="Describe the finding..."
              readOnly={readOnly}
              accentColor={ACCENT}
            />
          </Section>
        )}

        {/* Section 4: Status & Actions */}
        <Section title="Status & Actions" icon={IconShieldCheck} accentColor={ACCENT}>
          <div className="grid grid-cols-2 gap-3">
            <SelectInput
              label="Status ID"
              value={event.status_id != null ? String(event.status_id) : ""}
              options={STATUS_OPTIONS}
              onChange={(v) => updateField(["status_id"], v ? Number(v) : undefined)}
              readOnly={readOnly}
              placeholder="Select..."
              accentColor={ACCENT}
            />
            <SelectInput
              label="Action ID"
              value={event.action_id != null ? String(event.action_id) : ""}
              options={ACTION_OPTIONS}
              onChange={(v) => updateField(["action_id"], v ? Number(v) : undefined)}
              readOnly={readOnly}
              placeholder="Select..."
              accentColor={ACCENT}
            />
          </div>
          <SelectInput
            label="Disposition ID"
            value={event.disposition_id != null ? String(event.disposition_id) : ""}
            options={DISPOSITION_OPTIONS}
            onChange={(v) => updateField(["disposition_id"], v ? Number(v) : undefined)}
            readOnly={readOnly}
            placeholder="Select..."
            accentColor={ACCENT}
          />
          <TextArea
            label="Message"
            value={String(event.message ?? "")}
            onChange={(v) => updateField(["message"], v || undefined)}
            placeholder="Event message..."
            readOnly={readOnly}
            rows={2}
            accentColor={ACCENT}
          />
          <NumberInput
            label="Time"
            value={event.time != null ? Number(event.time) : undefined}
            onChange={(v) => updateField(["time"], v)}
            placeholder="Epoch milliseconds"
            required
            readOnly={readOnly}
          />
        </Section>

        {/* Section 5: Validation Summary */}
        <Section title="Validation Summary" icon={IconChecks} defaultOpen={validationErrors.length > 0} accentColor={ACCENT}>
          <div className="flex flex-col gap-2">
            {/* Progress indicator */}
            <div className="flex items-center gap-2">
              <div className="flex-1 bg-[#0b0d13] rounded-full h-1.5 overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-300"
                  style={{
                    width: `${(filledRequired / REQUIRED_FIELDS.length) * 100}%`,
                    backgroundColor: filledRequired === REQUIRED_FIELDS.length ? "#3dbf84" : ACCENT,
                  }}
                />
              </div>
              <span
                className="text-[10px] font-mono"
                style={{
                  color: filledRequired === REQUIRED_FIELDS.length ? "#3dbf84" : ACCENT,
                }}
              >
                {filledRequired}/{REQUIRED_FIELDS.length}
              </span>
            </div>

            {/* Required field checklist */}
            <div className="flex flex-wrap gap-1.5">
              {REQUIRED_FIELDS.map((field) => {
                const filled = event[field] !== undefined && event[field] !== null && event[field] !== "";
                return (
                  <span
                    key={field}
                    className={cn(
                      "inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono border",
                      filled
                        ? "border-[#3dbf84]/30 text-[#3dbf84] bg-[#3dbf84]/08"
                        : "border-[#c45c5c]/30 text-[#c45c5c] bg-[#c45c5c]/08",
                    )}
                  >
                    {filled ? "\u2713" : "\u2717"} {field}
                  </span>
                );
              })}
            </div>

            {/* Validation errors */}
            {validationErrors.length > 0 && (
              <div className="flex flex-col gap-1 mt-1 p-2 bg-[#c45c5c]/10 border border-[#c45c5c]/20 rounded">
                {validationErrors.map((err, i) => (
                  <span key={i} className="text-[10px] font-mono text-[#c45c5c]">
                    {err}
                  </span>
                ))}
              </div>
            )}

            {validationErrors.length === 0 && (
              <div className="text-[10px] font-mono text-[#3dbf84] py-1">
                All validations passed
              </div>
            )}
          </div>
        </Section>

        {/* Bottom padding */}
        <div className="h-6" />
      </div>
    </ScrollArea>
  );
}
