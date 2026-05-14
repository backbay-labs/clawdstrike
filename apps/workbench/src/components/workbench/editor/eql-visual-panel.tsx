import { useMemo, useCallback, useState } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  IconArrowUp,
  IconArrowDown,
  IconPlus,
  IconX,
  IconChevronDown,
  IconChevronRight,
  IconFilter,
} from "@tabler/icons-react";
import {
  Section,
  FieldLabel,
  TextInput,
  SelectInput,
} from "./detection-panel-kit";
import type { DetectionVisualPanelProps } from "@/lib/workbench/detection-workflow/shared-types";
import { registerVisualPanel } from "@/lib/workbench/detection-workflow/visual-panels";
import {
  parseEql,
  generateEql,
  type EqlEventCategory,
  type EqlCondition,
  type EqlSingleQuery,
  type EqlSequenceQuery,
  type EqlSequenceStep,
} from "@/lib/workbench/detection-workflow/eql-parser";


/** Default accent color for EQL panels (Elastic pink). */
const DEFAULT_ACCENT = "#f04e98";

const EVENT_CATEGORIES: EqlEventCategory[] = [
  "process",
  "file",
  "network",
  "registry",
  "dns",
  "any",
];

const OPERATOR_OPTIONS = [
  { value: "==", label: "equals (==)" },
  { value: "!=", label: "not equals (!=)" },
  { value: ":", label: "wildcard (:)" },
  { value: "~", label: "regex (~)" },
  { value: ">=", label: ">=" },
  { value: "<=", label: "<=" },
  { value: ">", label: ">" },
  { value: "<", label: "<" },
  { value: "in", label: "in (...)" },
];


interface ConditionRowProps {
  condition: EqlCondition;
  onChange: (c: EqlCondition) => void;
  onRemove: () => void;
  readOnly: boolean;
}

function ConditionRow({ condition, onChange, onRemove, readOnly }: ConditionRowProps) {
  const handleFieldChange = useCallback(
    (v: string) => onChange({ ...condition, field: v }),
    [condition, onChange],
  );

  const handleOperatorChange = useCallback(
    (v: string) => {
      const op = v as EqlCondition["operator"];
      // When switching to/from "in", adjust value type
      if (op === "in" && !Array.isArray(condition.value)) {
        onChange({ ...condition, operator: op, value: condition.value ? [condition.value] : [] });
      } else if (op !== "in" && Array.isArray(condition.value)) {
        onChange({ ...condition, operator: op, value: condition.value.join(", ") });
      } else {
        onChange({ ...condition, operator: op });
      }
    },
    [condition, onChange],
  );

  const handleValueChange = useCallback(
    (v: string) => {
      if (condition.operator === "in") {
        // Split comma-separated values
        const values = v.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
        onChange({ ...condition, value: values });
      } else {
        onChange({ ...condition, value: v });
      }
    },
    [condition, onChange],
  );

  const displayValue = Array.isArray(condition.value)
    ? condition.value.join(", ")
    : condition.value;

  return (
    <div className="flex items-center gap-2">
      <input
        type="text"
        value={condition.field}
        onChange={(e) => handleFieldChange(e.target.value)}
        placeholder="process.name"
        readOnly={readOnly}
        className="flex-1 min-w-0 bg-[#0b0d13] border border-[#2d3240] rounded px-2 py-1 text-[11px] font-mono text-[#ece7dc] placeholder:text-[#6f7f9a]/40 focus:outline-none focus:border-[#4a5568]"
      />
      <select
        value={condition.operator}
        onChange={(e) => handleOperatorChange(e.target.value)}
        disabled={readOnly}
        className="bg-[#0b0d13] border border-[#2d3240] rounded px-1.5 py-1 text-[11px] font-mono text-[#ece7dc] focus:outline-none focus:border-[#4a5568] appearance-none cursor-pointer"
      >
        {OPERATOR_OPTIONS.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
      <input
        type="text"
        value={displayValue}
        onChange={(e) => handleValueChange(e.target.value)}
        placeholder={condition.operator === "in" ? '"val1", "val2"' : '"value"'}
        readOnly={readOnly}
        className="flex-1 min-w-0 bg-[#0b0d13] border border-[#2d3240] rounded px-2 py-1 text-[11px] font-mono text-[#ece7dc] placeholder:text-[#6f7f9a]/40 focus:outline-none focus:border-[#4a5568]"
      />
      {!readOnly && (
        <button
          type="button"
          onClick={onRemove}
          className="p-0.5 rounded text-[#6f7f9a] hover:text-[#c45c5c] hover:bg-[#c45c5c]/10 transition-colors"
          title="Remove condition"
        >
          <IconX size={14} />
        </button>
      )}
    </div>
  );
}


interface SingleQueryEditorProps {
  query: EqlSingleQuery;
  onUpdate: (q: EqlSingleQuery) => void;
  readOnly: boolean;
}

function SingleQueryEditor({ query, onUpdate, readOnly }: SingleQueryEditorProps) {
  const handleCategoryChange = useCallback(
    (v: string) => onUpdate({ ...query, eventCategory: v as EqlEventCategory }),
    [query, onUpdate],
  );

  const handleConditionChange = useCallback(
    (index: number, cond: EqlCondition) => {
      const conditions = [...query.conditions];
      conditions[index] = cond;
      onUpdate({ ...query, conditions });
    },
    [query, onUpdate],
  );

  const handleConditionRemove = useCallback(
    (index: number) => {
      const conditions = query.conditions.filter((_, i) => i !== index);
      onUpdate({ ...query, conditions });
    },
    [query, onUpdate],
  );

  const handleAddCondition = useCallback(() => {
    onUpdate({
      ...query,
      conditions: [
        ...query.conditions,
        { field: "", operator: "==", value: "", negated: false },
      ],
    });
  }, [query, onUpdate]);

  const handleLogicToggle = useCallback(() => {
    onUpdate({
      ...query,
      logicOperator: query.logicOperator === "and" ? "or" : "and",
    });
  }, [query, onUpdate]);

  return (
    <div className="flex flex-col gap-3">
      <SelectInput
        label="Event Category"
        value={query.eventCategory}
        options={EVENT_CATEGORIES}
        onChange={handleCategoryChange}
        readOnly={readOnly}
        accentColor={DEFAULT_ACCENT}
      />

      <div className="flex flex-col gap-1.5">
        <div className="flex items-center justify-between">
          <FieldLabel label="Conditions" />
          {query.conditions.length > 1 && !readOnly && (
            <button
              type="button"
              onClick={handleLogicToggle}
              className="px-2 py-0.5 text-[9px] font-mono font-bold rounded border transition-colors"
              style={{
                color: DEFAULT_ACCENT,
                borderColor: `${DEFAULT_ACCENT}40`,
                backgroundColor: `${DEFAULT_ACCENT}10`,
              }}
            >
              {query.logicOperator.toUpperCase()}
            </button>
          )}
        </div>

        {query.conditions.map((cond, i) => (
          <div key={i} className="flex flex-col gap-1">
            <ConditionRow
              condition={cond}
              onChange={(c) => handleConditionChange(i, c)}
              onRemove={() => handleConditionRemove(i)}
              readOnly={readOnly}
            />
            {i < query.conditions.length - 1 && (
              <div className="flex items-center gap-2 pl-2">
                <span
                  className="text-[9px] font-mono font-bold"
                  style={{ color: `${DEFAULT_ACCENT}80` }}
                >
                  {query.logicOperator.toUpperCase()}
                </span>
                <div className="flex-1 h-px bg-[#2d3240]" />
              </div>
            )}
          </div>
        ))}

        {!readOnly && (
          <button
            type="button"
            onClick={handleAddCondition}
            className="flex items-center gap-1.5 px-2 py-1 text-[10px] font-mono rounded border border-dashed transition-colors hover:bg-[#1a1a2e]/60"
            style={{
              color: `${DEFAULT_ACCENT}90`,
              borderColor: `${DEFAULT_ACCENT}30`,
            }}
          >
            <IconPlus size={12} />
            Add Condition
          </button>
        )}
      </div>
    </div>
  );
}


interface SequenceBuilderProps {
  query: EqlSequenceQuery;
  onUpdate: (q: EqlSequenceQuery) => void;
  readOnly: boolean;
}

function SequenceBuilder({ query, onUpdate, readOnly }: SequenceBuilderProps) {
  const [untilOpen, setUntilOpen] = useState(!!query.until);

  const handleByFieldsChange = useCallback(
    (v: string) => {
      const byFields = v
        .split(",")
        .map((f) => f.trim())
        .filter((f) => f.length > 0);
      onUpdate({ ...query, byFields });
    },
    [query, onUpdate],
  );

  const handleMaxspanChange = useCallback(
    (v: string) => {
      const updated = { ...query };
      if (v.trim()) {
        updated.maxspan = v.trim();
      } else {
        delete updated.maxspan;
      }
      onUpdate(updated);
    },
    [query, onUpdate],
  );

  const handleStepUpdate = useCallback(
    (index: number, step: EqlSequenceStep) => {
      const steps = [...query.steps];
      steps[index] = step;
      onUpdate({ ...query, steps });
    },
    [query, onUpdate],
  );

  const handleStepRemove = useCallback(
    (index: number) => {
      const steps = query.steps.filter((_, i) => i !== index);
      onUpdate({ ...query, steps });
    },
    [query, onUpdate],
  );

  const handleStepMoveUp = useCallback(
    (index: number) => {
      if (index <= 0) return;
      const steps = [...query.steps];
      [steps[index - 1], steps[index]] = [steps[index], steps[index - 1]];
      onUpdate({ ...query, steps });
    },
    [query, onUpdate],
  );

  const handleStepMoveDown = useCallback(
    (index: number) => {
      if (index >= query.steps.length - 1) return;
      const steps = [...query.steps];
      [steps[index], steps[index + 1]] = [steps[index + 1], steps[index]];
      onUpdate({ ...query, steps });
    },
    [query, onUpdate],
  );

  const handleAddStep = useCallback(() => {
    onUpdate({
      ...query,
      steps: [
        ...query.steps,
        { eventCategory: "process", conditions: [], logicOperator: "and" },
      ],
    });
  }, [query, onUpdate]);

  const handleUntilUpdate = useCallback(
    (q: EqlSingleQuery) => {
      onUpdate({ ...query, until: q });
    },
    [query, onUpdate],
  );

  const handleUntilRemove = useCallback(() => {
    const updated = { ...query };
    delete updated.until;
    onUpdate(updated);
    setUntilOpen(false);
  }, [query, onUpdate]);

  const handleUntilAdd = useCallback(() => {
    onUpdate({
      ...query,
      until: {
        type: "single",
        eventCategory: "process",
        conditions: [{ field: "", operator: "==", value: "", negated: false }],
        logicOperator: "and",
      },
    });
    setUntilOpen(true);
  }, [query, onUpdate]);

  return (
    <div className="flex flex-col gap-4">
      {/* Sequence Header */}
      <div className="flex flex-col gap-3">
        <TextInput
          label="Correlate By Fields"
          value={query.byFields.join(", ")}
          onChange={handleByFieldsChange}
          placeholder="host.id, user.name"
          readOnly={readOnly}
          accentColor={DEFAULT_ACCENT}
          mono
        />
        <TextInput
          label="Max Span"
          value={query.maxspan ?? ""}
          onChange={handleMaxspanChange}
          placeholder="e.g. 5m, 1h, 30s"
          readOnly={readOnly}
          accentColor={DEFAULT_ACCENT}
          mono
        />
      </div>

      {/* Step Cards */}
      <div className="flex flex-col gap-0">
        <FieldLabel label="Sequence Steps" />

        {query.steps.map((step, i) => (
          <div key={i} className="flex flex-col">
            {/* Connecting line between steps */}
            {i > 0 && (
              <div className="flex items-center ml-4 h-4">
                <div
                  className="w-0.5 h-full"
                  style={{ backgroundColor: `${DEFAULT_ACCENT}40` }}
                />
              </div>
            )}

            {/* Step Card */}
            <div className="bg-[#1a1a2e]/60 border border-white/10 rounded-lg p-3">
              <div className="flex items-start gap-2">
                {/* Step number badge */}
                <div
                  className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-mono font-bold shrink-0 mt-0.5"
                  style={{
                    color: DEFAULT_ACCENT,
                    backgroundColor: `${DEFAULT_ACCENT}1a`,
                    border: `1px solid ${DEFAULT_ACCENT}33`,
                  }}
                >
                  {i + 1}
                </div>

                {/* Step content */}
                <div className="flex-1 min-w-0 flex flex-col gap-2">
                  <div className="flex items-center gap-2">
                    <select
                      value={step.eventCategory}
                      onChange={(e) =>
                        handleStepUpdate(i, {
                          ...step,
                          eventCategory: e.target.value as EqlEventCategory,
                        })
                      }
                      disabled={readOnly}
                      className="bg-[#0b0d13] border border-[#2d3240] rounded px-2 py-1 text-[11px] font-mono text-[#ece7dc] focus:outline-none focus:border-[#4a5568] appearance-none cursor-pointer"
                    >
                      {EVENT_CATEGORIES.map((cat) => (
                        <option key={cat} value={cat}>
                          {cat}
                        </option>
                      ))}
                    </select>

                    {/* Step actions */}
                    {!readOnly && (
                      <div className="flex items-center gap-0.5 ml-auto">
                        {i > 0 && (
                          <button
                            type="button"
                            onClick={() => handleStepMoveUp(i)}
                            className="p-0.5 rounded text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#2d3240] transition-colors"
                            title="Move step up"
                          >
                            <IconArrowUp size={13} />
                          </button>
                        )}
                        {i < query.steps.length - 1 && (
                          <button
                            type="button"
                            onClick={() => handleStepMoveDown(i)}
                            className="p-0.5 rounded text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#2d3240] transition-colors"
                            title="Move step down"
                          >
                            <IconArrowDown size={13} />
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => handleStepRemove(i)}
                          className="p-0.5 rounded text-[#6f7f9a] hover:text-[#c45c5c] hover:bg-[#c45c5c]/10 transition-colors"
                          title="Remove step"
                        >
                          <IconX size={13} />
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Step conditions */}
                  <StepConditions
                    step={step}
                    onUpdate={(s) => handleStepUpdate(i, s)}
                    readOnly={readOnly}
                  />
                </div>
              </div>
            </div>
          </div>
        ))}

        {/* Add Step button */}
        {!readOnly && (
          <div className="flex flex-col">
            {query.steps.length > 0 && (
              <div className="flex items-center ml-4 h-3">
                <div
                  className="w-0.5 h-full"
                  style={{ backgroundColor: `${DEFAULT_ACCENT}30` }}
                />
              </div>
            )}
            <button
              type="button"
              onClick={handleAddStep}
              className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-mono rounded border border-dashed transition-colors hover:bg-[#1a1a2e]/60"
              style={{
                color: `${DEFAULT_ACCENT}90`,
                borderColor: `${DEFAULT_ACCENT}30`,
              }}
            >
              <IconPlus size={12} />
              Add Step
            </button>
          </div>
        )}
      </div>

      {/* Until Section (collapsible) */}
      <div className="flex flex-col gap-2">
        <button
          type="button"
          onClick={() => {
            if (query.until) {
              setUntilOpen((o) => !o);
            } else if (!readOnly) {
              handleUntilAdd();
            }
          }}
          className="flex items-center gap-1.5 text-[10px] font-mono font-bold uppercase tracking-wider transition-colors"
          style={{ color: "#6f7f9a" }}
        >
          {untilOpen ? <IconChevronDown size={12} /> : <IconChevronRight size={12} />}
          Until Clause
          {!query.until && !readOnly && (
            <span
              className="text-[8px] font-normal normal-case tracking-normal ml-1"
              style={{ color: `${DEFAULT_ACCENT}70` }}
            >
              (click to add)
            </span>
          )}
        </button>

        {untilOpen && query.until && (
          <div className="bg-[#1a1a2e]/40 border border-[#6f7f9a]/20 rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[9px] font-mono font-bold uppercase tracking-wider text-[#6f7f9a]">
                UNTIL
              </span>
              {!readOnly && (
                <button
                  type="button"
                  onClick={handleUntilRemove}
                  className="p-0.5 rounded text-[#6f7f9a] hover:text-[#c45c5c] hover:bg-[#c45c5c]/10 transition-colors"
                  title="Remove until clause"
                >
                  <IconX size={13} />
                </button>
              )}
            </div>
            <SingleQueryEditor
              query={query.until}
              onUpdate={handleUntilUpdate}
              readOnly={readOnly}
            />
          </div>
        )}
      </div>
    </div>
  );
}


interface StepConditionsProps {
  step: EqlSequenceStep;
  onUpdate: (s: EqlSequenceStep) => void;
  readOnly: boolean;
}

function StepConditions({ step, onUpdate, readOnly }: StepConditionsProps) {
  const handleConditionChange = useCallback(
    (index: number, cond: EqlCondition) => {
      const conditions = [...step.conditions];
      conditions[index] = cond;
      onUpdate({ ...step, conditions });
    },
    [step, onUpdate],
  );

  const handleConditionRemove = useCallback(
    (index: number) => {
      const conditions = step.conditions.filter((_, i) => i !== index);
      onUpdate({ ...step, conditions });
    },
    [step, onUpdate],
  );

  const handleAddCondition = useCallback(() => {
    onUpdate({
      ...step,
      conditions: [
        ...step.conditions,
        { field: "", operator: "==", value: "", negated: false },
      ],
    });
  }, [step, onUpdate]);

  const handleLogicToggle = useCallback(() => {
    onUpdate({
      ...step,
      logicOperator: step.logicOperator === "and" ? "or" : "and",
    });
  }, [step, onUpdate]);

  return (
    <div className="flex flex-col gap-1.5">
      {step.conditions.length > 1 && !readOnly && (
        <div className="flex justify-end">
          <button
            type="button"
            onClick={handleLogicToggle}
            className="px-2 py-0.5 text-[9px] font-mono font-bold rounded border transition-colors"
            style={{
              color: DEFAULT_ACCENT,
              borderColor: `${DEFAULT_ACCENT}40`,
              backgroundColor: `${DEFAULT_ACCENT}10`,
            }}
          >
            {step.logicOperator.toUpperCase()}
          </button>
        </div>
      )}

      {step.conditions.map((cond, i) => (
        <div key={i} className="flex flex-col gap-1">
          <ConditionRow
            condition={cond}
            onChange={(c) => handleConditionChange(i, c)}
            onRemove={() => handleConditionRemove(i)}
            readOnly={readOnly}
          />
          {i < step.conditions.length - 1 && (
            <div className="flex items-center gap-2 pl-2">
              <span
                className="text-[9px] font-mono font-bold"
                style={{ color: `${DEFAULT_ACCENT}60` }}
              >
                {step.logicOperator.toUpperCase()}
              </span>
              <div className="flex-1 h-px bg-[#2d3240]" />
            </div>
          )}
        </div>
      ))}

      {!readOnly && (
        <button
          type="button"
          onClick={handleAddCondition}
          className="flex items-center gap-1 px-2 py-0.5 text-[9px] font-mono rounded border border-dashed transition-colors hover:bg-[#0b0d13]/60"
          style={{
            color: `${DEFAULT_ACCENT}70`,
            borderColor: `${DEFAULT_ACCENT}20`,
          }}
        >
          <IconPlus size={10} />
          condition
        </button>
      )}
    </div>
  );
}


export function EqlVisualPanel(props: DetectionVisualPanelProps) {
  const { source, onSourceChange, readOnly, accentColor } = props;
  const ACCENT = accentColor ?? DEFAULT_ACCENT;
  const { ast, errors } = useMemo(() => parseEql(source), [source]);

  const handleSingleUpdate = useCallback(
    (query: EqlSingleQuery) => {
      onSourceChange(generateEql(query));
    },
    [onSourceChange],
  );

  const handleSequenceUpdate = useCallback(
    (query: EqlSequenceQuery) => {
      onSourceChange(generateEql(query));
    },
    [onSourceChange],
  );

  return (
    <ScrollArea className="h-full">
      <div className="flex flex-col pb-6">
        {/* Format sigil */}
        <div className="flex items-center gap-2 px-4 pt-3 pb-1">
          <span className="text-base font-black tracking-tight" style={{ color: ACCENT }}>
            EQL
          </span>
          <span className="text-[10px] font-mono text-[#6f7f9a]">
            Event Query Language
          </span>
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

        {/* Query type badge */}
        {ast && (
          <div className="flex items-center gap-2 px-4 pt-3 pb-0">
            <span
              className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono border rounded"
              style={{
                color: ACCENT,
                borderColor: `${ACCENT}30`,
                backgroundColor: `${ACCENT}08`,
              }}
            >
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{ backgroundColor: ACCENT }}
              />
              {ast.type === "single" ? "Single Event" : "Sequence"}
            </span>
            {ast.type === "single" && (
              <span
                className="inline-flex items-center px-2 py-0.5 text-[9px] font-mono border rounded"
                style={{
                  color: "#6f7f9a",
                  borderColor: "#2d324060",
                  backgroundColor: "#2d324020",
                }}
              >
                {ast.eventCategory}
              </span>
            )}
            {ast.type === "sequence" && (
              <span
                className="inline-flex items-center px-2 py-0.5 text-[9px] font-mono border rounded"
                style={{
                  color: "#6f7f9a",
                  borderColor: "#2d324060",
                  backgroundColor: "#2d324020",
                }}
              >
                {ast.steps.length} steps
              </span>
            )}
          </div>
        )}

        {/* Main editor content */}
        {ast ? (
          <Section title="Query Builder" icon={IconFilter} accentColor={ACCENT}>
            {ast.type === "single" ? (
              <SingleQueryEditor
                query={ast}
                onUpdate={handleSingleUpdate}
                readOnly={readOnly ?? false}
              />
            ) : (
              <SequenceBuilder
                query={ast}
                onUpdate={handleSequenceUpdate}
                readOnly={readOnly ?? false}
              />
            )}
          </Section>
        ) : (
          !errors.length && (
            <div className="px-4 py-6 text-[11px] font-mono text-[#6f7f9a]/50 italic text-center">
              Enter an EQL query in the editor to see the visual builder.
            </div>
          )
        )}
      </div>
    </ScrollArea>
  );
}


registerVisualPanel("eql_rule", EqlVisualPanel);
