/**
 * WorkflowsView - Automated response chains with visual editor
 */
import { useState, useEffect } from "react";
import type { ReactNode } from "react";
import { clsx } from "clsx";
import { GlassPanel, GlassHeader } from "@backbay/glia/primitives";
import { GlowButton } from "@backbay/glia/primitives";
import { GlowInput } from "@backbay/glia/primitives";
import { Badge } from "@backbay/glia/primitives";
import type {
  Workflow,
  WorkflowTrigger,
  WorkflowAction,
  TriggerCondition,
} from "@/services/tauri";
import {
  listWorkflows,
  saveWorkflow,
  deleteWorkflow,
  testWorkflow,
  isTauri,
} from "@/services/tauri";

// Mock workflows for browser testing
const MOCK_WORKFLOWS: Workflow[] = [
  {
    id: "wf_1",
    name: "Alert on Critical Blocks",
    enabled: true,
    trigger: {
      type: "event_match",
      conditions: [
        { field: "verdict", operator: "equals", value: "blocked" },
        { field: "severity", operator: "equals", value: "critical" },
      ],
    },
    actions: [
      {
        type: "slack_webhook",
        url: "https://hooks.slack.com/...",
        channel: "#security-alerts",
        template: "Critical block: {{target}}",
      },
    ],
    last_run: "2025-02-04T10:30:00Z",
    run_count: 42,
    created_at: "2025-01-15T00:00:00Z",
  },
  {
    id: "wf_2",
    name: "Daily Summary",
    enabled: true,
    trigger: {
      type: "schedule",
      cron: "0 9 * * *",
    },
    actions: [
      {
        type: "email",
        to: ["security@example.com"],
        subject: "Daily SDR Summary",
        template: "Events: {{total_events}}, Blocked: {{blocked_count}}",
      },
    ],
    run_count: 30,
    created_at: "2025-01-10T00:00:00Z",
  },
  {
    id: "wf_3",
    name: "PagerDuty Escalation",
    enabled: false,
    trigger: {
      type: "aggregation",
      conditions: [{ field: "verdict", operator: "equals", value: "blocked" }],
      threshold: 10,
      window: "5m",
    },
    actions: [
      { type: "pagerduty", routing_key: "...", severity: "critical" },
    ],
    run_count: 0,
    created_at: "2025-02-01T00:00:00Z",
  },
];

const TRIGGER_FIELDS: TriggerCondition["field"][] = [
  "severity",
  "action_type",
  "verdict",
  "guard",
  "agent",
];

const TRIGGER_OPERATORS: TriggerCondition["operator"][] = [
  "equals",
  "not_equals",
  "contains",
  "greater_than",
];

const ACTION_TYPES: WorkflowAction["type"][] = [
  "webhook",
  "slack_webhook",
  "pagerduty",
  "email",
  "log",
];

export function WorkflowsView() {
  const [workflows, setWorkflows] = useState<Workflow[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedWorkflow, setSelectedWorkflow] = useState<Workflow | null>(
    null
  );
  const [isEditing, setIsEditing] = useState(false);

  useEffect(() => {
    loadWorkflows();
  }, []);

  const loadWorkflows = async () => {
    setIsLoading(true);
    try {
      if (isTauri()) {
        const data = await listWorkflows();
        setWorkflows(data);
      } else {
        setWorkflows(MOCK_WORKFLOWS);
      }
    } catch (e) {
      console.error("Failed to load workflows:", e);
      setWorkflows(MOCK_WORKFLOWS);
    } finally {
      setIsLoading(false);
    }
  };

  const handleToggle = async (workflow: Workflow) => {
    const updated = { ...workflow, enabled: !workflow.enabled };
    try {
      if (isTauri()) {
        await saveWorkflow(updated);
      }
      setWorkflows((prev) =>
        prev.map((w) => (w.id === workflow.id ? updated : w))
      );
    } catch (e) {
      console.error("Failed to toggle workflow:", e);
    }
  };

  const handleDelete = async (workflowId: string) => {
    try {
      if (isTauri()) {
        await deleteWorkflow(workflowId);
      }
      setWorkflows((prev) => prev.filter((w) => w.id !== workflowId));
      if (selectedWorkflow?.id === workflowId) {
        setSelectedWorkflow(null);
      }
    } catch (e) {
      console.error("Failed to delete workflow:", e);
    }
  };

  const handleTest = async (workflowId: string) => {
    try {
      const result = await testWorkflow(workflowId);
      alert(
        result.success ? "Test passed!" : `Test failed: ${result.message}`
      );
    } catch (e) {
      console.error("Failed to test workflow:", e);
    }
  };

  const handleNewWorkflow = () => {
    const newWorkflow: Workflow = {
      id: `wf_${Date.now()}`,
      name: "New Workflow",
      enabled: false,
      trigger: { type: "event_match", conditions: [] },
      actions: [],
      run_count: 0,
      created_at: new Date().toISOString(),
    };
    setSelectedWorkflow(newWorkflow);
    setIsEditing(true);
  };

  return (
    <GlassPanel className="flex h-full">
      {/* Workflow list */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <GlassHeader className="flex items-center justify-between px-4 py-3">
          <div>
            <h1 className="text-lg font-semibold text-sdr-text-primary">
              Workflows
            </h1>
            <p className="text-sm text-sdr-text-muted mt-0.5">
              Automated response chains for policy events
            </p>
          </div>
          <GlowButton onClick={handleNewWorkflow}>New Workflow</GlowButton>
        </GlassHeader>

        {/* Workflow list */}
        <div className="flex-1 overflow-y-auto">
          {isLoading ? (
            <div className="flex items-center justify-center h-full text-sdr-text-muted">
              Loading...
            </div>
          ) : workflows.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-sdr-text-muted">
              <p>No workflows yet</p>
              <p className="text-sm mt-1">
                Create a workflow to automate responses
              </p>
            </div>
          ) : (
            <div className="divide-y divide-sdr-border">
              {workflows.map((workflow) => (
                <WorkflowRow
                  key={workflow.id}
                  workflow={workflow}
                  isSelected={selectedWorkflow?.id === workflow.id}
                  onSelect={() => {
                    setSelectedWorkflow(workflow);
                    setIsEditing(false);
                  }}
                  onToggle={() => handleToggle(workflow)}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Detail/Edit panel */}
      {selectedWorkflow && (
        <WorkflowDetailPanel
          workflow={selectedWorkflow}
          isEditing={isEditing}
          onEdit={() => setIsEditing(true)}
          onClose={() => {
            setSelectedWorkflow(null);
            setIsEditing(false);
          }}
          onSave={(updated) => {
            setWorkflows((prev) =>
              prev.some((w) => w.id === updated.id)
                ? prev.map((w) => (w.id === updated.id ? updated : w))
                : [...prev, updated]
            );
            setSelectedWorkflow(updated);
            setIsEditing(false);
          }}
          onDelete={() => handleDelete(selectedWorkflow.id)}
          onTest={() => handleTest(selectedWorkflow.id)}
        />
      )}
    </GlassPanel>
  );
}

interface WorkflowRowProps {
  workflow: Workflow;
  isSelected: boolean;
  onSelect: () => void;
  onToggle: () => void;
}

function WorkflowRow({
  workflow,
  isSelected,
  onSelect,
  onToggle,
}: WorkflowRowProps) {
  return (
    <div
      className={clsx(
        "flex items-center gap-4 px-4 py-3 cursor-pointer transition-colors",
        isSelected ? "bg-sdr-accent-blue/10" : "hover:bg-sdr-bg-tertiary"
      )}
      onClick={onSelect}
    >
      {/* Enable toggle */}
      <button
        onClick={(e) => {
          e.stopPropagation();
          onToggle();
        }}
        className={clsx(
          "w-10 h-6 rounded-full transition-colors relative",
          workflow.enabled ? "bg-sdr-accent-green" : "bg-sdr-bg-tertiary"
        )}
      >
        <span
          className={clsx(
            "absolute top-1 w-4 h-4 rounded-full bg-white transition-all",
            workflow.enabled ? "left-5" : "left-1"
          )}
        />
      </button>

      {/* Info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-medium text-sdr-text-primary">
            {workflow.name}
          </span>
          <TriggerBadge trigger={workflow.trigger} />
        </div>
        <div className="text-xs text-sdr-text-muted mt-0.5">
          {workflow.actions.length} action
          {workflow.actions.length !== 1 ? "s" : ""} · {workflow.run_count} runs
          {workflow.last_run && (
            <> · Last: {new Date(workflow.last_run).toLocaleString()}</>
          )}
        </div>
      </div>

      {/* Status indicator */}
      <div
        className={clsx(
          "w-2 h-2 rounded-full",
          workflow.enabled ? "bg-sdr-accent-green" : "bg-sdr-text-muted"
        )}
      />
    </div>
  );
}

function TriggerBadge({ trigger }: { trigger: WorkflowTrigger }) {
  const labels: Record<string, string> = {
    event_match: "Event",
    schedule: "Schedule",
    aggregation: "Aggregation",
  };

  return <Badge variant="outline">{labels[trigger.type] ?? trigger.type}</Badge>;
}

interface WorkflowDetailPanelProps {
  workflow: Workflow;
  isEditing: boolean;
  onEdit: () => void;
  onClose: () => void;
  onSave: (workflow: Workflow) => void;
  onDelete: () => void;
  onTest: () => void;
}

function WorkflowDetailPanel({
  workflow,
  isEditing,
  onEdit,
  onClose,
  onSave,
  onDelete,
  onTest,
}: WorkflowDetailPanelProps) {
  const [draft, setDraft] = useState(workflow);

  useEffect(() => {
    setDraft(workflow);
  }, [workflow]);

  const handleSave = async () => {
    try {
      if (isTauri()) {
        await saveWorkflow(draft);
      }
      onSave(draft);
    } catch (e) {
      console.error("Failed to save workflow:", e);
    }
  };

  const updateTrigger = (trigger: WorkflowTrigger) => {
    setDraft({ ...draft, trigger });
  };

  const updateConditions = (conditions: TriggerCondition[]) => {
    const trigger = draft.trigger;
    if (trigger.type === "event_match") {
      updateTrigger({ ...trigger, conditions });
    } else if (trigger.type === "aggregation") {
      updateTrigger({ ...trigger, conditions });
    }
  };

  const getConditions = (): TriggerCondition[] => {
    if (draft.trigger.type === "event_match") return draft.trigger.conditions;
    if (draft.trigger.type === "aggregation") return draft.trigger.conditions;
    return [];
  };

  const updateActions = (actions: WorkflowAction[]) => {
    setDraft({ ...draft, actions });
  };

  return (
    <div className="w-[420px] border-l border-sdr-border bg-sdr-bg-secondary flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-sdr-border">
        <h2 className="font-medium text-sdr-text-primary">
          {isEditing ? "Edit Workflow" : "Workflow Details"}
        </h2>
        <button
          onClick={onClose}
          className="p-1 text-sdr-text-muted hover:text-sdr-text-primary rounded"
        >
          <CloseIcon />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {isEditing ? (
          <>
            {/* Name */}
            <div>
              <label className="block text-sm font-medium text-sdr-text-primary mb-1">
                Name
              </label>
              <GlowInput
                type="text"
                value={draft.name}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                className="w-full"
              />
            </div>

            {/* Visual pipeline */}
            <PipelineVisual
              trigger={draft.trigger}
              conditions={getConditions()}
              actions={draft.actions}
            />

            {/* Trigger section */}
            <Section title="Trigger">
              <TriggerEditor trigger={draft.trigger} onChange={updateTrigger} />
            </Section>

            {/* Conditions section */}
            {(draft.trigger.type === "event_match" ||
              draft.trigger.type === "aggregation") && (
              <Section title="Conditions">
                <ConditionsEditor
                  conditions={getConditions()}
                  onChange={updateConditions}
                />
              </Section>
            )}

            {/* Actions section */}
            <Section title="Actions">
              <ActionsEditor
                actions={draft.actions}
                onChange={updateActions}
              />
            </Section>

            {/* Enable toggle */}
            <div className="flex items-center gap-3">
              <button
                onClick={() =>
                  setDraft({ ...draft, enabled: !draft.enabled })
                }
                className={clsx(
                  "w-10 h-6 rounded-full transition-colors relative shrink-0",
                  draft.enabled ? "bg-sdr-accent-green" : "bg-sdr-bg-tertiary"
                )}
              >
                <span
                  className={clsx(
                    "absolute top-1 w-4 h-4 rounded-full bg-white transition-all",
                    draft.enabled ? "left-5" : "left-1"
                  )}
                />
              </button>
              <span className="text-sm text-sdr-text-primary">
                {draft.enabled ? "Enabled" : "Disabled"}
              </span>
            </div>
          </>
        ) : (
          <>
            {/* Read-only view */}
            <Section title="Name">
              <p className="text-sm text-sdr-text-primary">{workflow.name}</p>
            </Section>

            <PipelineVisual
              trigger={workflow.trigger}
              conditions={
                workflow.trigger.type === "event_match"
                  ? workflow.trigger.conditions
                  : workflow.trigger.type === "aggregation"
                    ? workflow.trigger.conditions
                    : []
              }
              actions={workflow.actions}
            />

            <Section title="Trigger">
              <TriggerDisplay trigger={workflow.trigger} />
            </Section>

            <Section title="Actions">
              {workflow.actions.length === 0 ? (
                <p className="text-sm text-sdr-text-muted">
                  No actions configured
                </p>
              ) : (
                <div className="space-y-2">
                  {workflow.actions.map((action, i) => (
                    <ActionDisplay key={i} action={action} />
                  ))}
                </div>
              )}
            </Section>

            <Section title="Statistics">
              <div className="text-sm text-sdr-text-secondary space-y-1">
                <p>Run count: {workflow.run_count}</p>
                {workflow.last_run && (
                  <p>
                    Last run: {new Date(workflow.last_run).toLocaleString()}
                  </p>
                )}
                <p>
                  Created:{" "}
                  {new Date(workflow.created_at).toLocaleDateString()}
                </p>
              </div>
            </Section>
          </>
        )}
      </div>

      {/* Bottom actions */}
      <div className="p-4 border-t border-sdr-border space-y-2">
        {isEditing ? (
          <>
            <GlowButton onClick={handleSave} className="w-full">
              Save Workflow
            </GlowButton>
            <GlowButton
              variant="secondary"
              onClick={() => {
                setDraft(workflow);
                onClose();
              }}
              className="w-full"
            >
              Cancel
            </GlowButton>
          </>
        ) : (
          <>
            <div className="flex gap-2">
              <GlowButton
                variant="secondary"
                onClick={onEdit}
                className="flex-1"
              >
                Edit
              </GlowButton>
              <GlowButton
                variant="secondary"
                onClick={onTest}
                className="flex-1"
              >
                Test
              </GlowButton>
            </div>
            <GlowButton
              variant="secondary"
              onClick={onDelete}
              className="w-full text-sdr-accent-red"
            >
              Delete Workflow
            </GlowButton>
          </>
        )}
      </div>
    </div>
  );
}

// === Visual Pipeline ===

function PipelineVisual({
  trigger,
  conditions,
  actions,
}: {
  trigger: WorkflowTrigger;
  conditions: TriggerCondition[];
  actions: WorkflowAction[];
}) {
  const triggerLabel =
    trigger.type === "event_match"
      ? "Event Match"
      : trigger.type === "schedule"
        ? `Schedule: ${trigger.cron}`
        : `Aggregation: ${trigger.threshold}/${trigger.window}`;

  return (
    <div className="flex flex-col items-center gap-0">
      {/* Trigger node */}
      <PipelineNode
        label={triggerLabel}
        color="text-sdr-accent-blue"
        bgColor="bg-sdr-accent-blue/10"
        borderColor="border-sdr-accent-blue/30"
      />
      <PipelineConnector />

      {/* Conditions node */}
      <PipelineNode
        label={
          conditions.length === 0
            ? "No conditions"
            : `${conditions.length} condition${conditions.length !== 1 ? "s" : ""}`
        }
        color="text-sdr-accent-amber"
        bgColor="bg-sdr-accent-amber/10"
        borderColor="border-sdr-accent-amber/30"
      />
      <PipelineConnector />

      {/* Actions node */}
      <PipelineNode
        label={
          actions.length === 0
            ? "No actions"
            : `${actions.length} action${actions.length !== 1 ? "s" : ""}`
        }
        color="text-sdr-accent-green"
        bgColor="bg-sdr-accent-green/10"
        borderColor="border-sdr-accent-green/30"
      />
    </div>
  );
}

function PipelineNode({
  label,
  color,
  bgColor,
  borderColor,
}: {
  label: string;
  color: string;
  bgColor: string;
  borderColor: string;
}) {
  return (
    <div
      className={clsx(
        "w-full px-3 py-2 rounded-lg border text-center text-xs font-medium",
        color,
        bgColor,
        borderColor
      )}
    >
      {label}
    </div>
  );
}

function PipelineConnector() {
  return (
    <div className="flex flex-col items-center py-0.5">
      <div className="w-px h-4 bg-sdr-border" />
      <svg
        width="8"
        height="6"
        viewBox="0 0 8 6"
        className="text-sdr-border -mt-px"
      >
        <path d="M4 6L0 0h8z" fill="currentColor" />
      </svg>
    </div>
  );
}

// === Trigger Editor ===

function TriggerEditor({
  trigger,
  onChange,
}: {
  trigger: WorkflowTrigger;
  onChange: (trigger: WorkflowTrigger) => void;
}) {
  const handleTypeChange = (type: string) => {
    if (type === "event_match") {
      onChange({ type: "event_match", conditions: [] });
    } else if (type === "schedule") {
      onChange({ type: "schedule", cron: "0 * * * *" });
    } else if (type === "aggregation") {
      onChange({
        type: "aggregation",
        conditions: [],
        threshold: 10,
        window: "5m",
      });
    }
  };

  return (
    <div className="space-y-3">
      <div>
        <label className="block text-xs text-sdr-text-muted mb-1">Type</label>
        <select
          value={trigger.type}
          onChange={(e) => handleTypeChange(e.target.value)}
          className="w-full px-3 py-2 bg-sdr-bg-tertiary text-sdr-text-primary text-sm rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue"
        >
          <option value="event_match">Event Match</option>
          <option value="schedule">Schedule (Cron)</option>
          <option value="aggregation">Aggregation</option>
        </select>
      </div>

      {trigger.type === "schedule" && (
        <div>
          <label className="block text-xs text-sdr-text-muted mb-1">
            Cron Expression
          </label>
          <GlowInput
            type="text"
            value={trigger.cron}
            onChange={(e) => onChange({ ...trigger, cron: e.target.value })}
            placeholder="0 9 * * *"
            className="w-full font-mono text-sm"
          />
        </div>
      )}

      {trigger.type === "aggregation" && (
        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="block text-xs text-sdr-text-muted mb-1">
              Threshold
            </label>
            <GlowInput
              type="number"
              value={String(trigger.threshold)}
              onChange={(e) =>
                onChange({
                  ...trigger,
                  threshold: Number.parseInt(e.target.value, 10) || 1,
                })
              }
              className="w-full text-sm"
            />
          </div>
          <div>
            <label className="block text-xs text-sdr-text-muted mb-1">
              Window
            </label>
            <GlowInput
              type="text"
              value={trigger.window}
              onChange={(e) => onChange({ ...trigger, window: e.target.value })}
              placeholder="5m"
              className="w-full font-mono text-sm"
            />
          </div>
        </div>
      )}
    </div>
  );
}

// === Conditions Editor ===

function ConditionsEditor({
  conditions,
  onChange,
}: {
  conditions: TriggerCondition[];
  onChange: (conditions: TriggerCondition[]) => void;
}) {
  const addCondition = () => {
    onChange([
      ...conditions,
      { field: "severity", operator: "equals", value: "" },
    ]);
  };

  const updateCondition = (index: number, updates: Partial<TriggerCondition>) => {
    onChange(
      conditions.map((c, i) => (i === index ? { ...c, ...updates } : c))
    );
  };

  const removeCondition = (index: number) => {
    onChange(conditions.filter((_, i) => i !== index));
  };

  return (
    <div className="space-y-2">
      {conditions.map((condition, index) => (
        <div
          key={index}
          className="flex items-center gap-1.5 p-2 bg-sdr-bg-tertiary rounded-md border border-sdr-border"
        >
          <select
            value={condition.field}
            onChange={(e) =>
              updateCondition(index, {
                field: e.target.value as TriggerCondition["field"],
              })
            }
            className="flex-1 px-2 py-1 bg-sdr-bg-secondary text-sdr-text-primary text-xs rounded border border-sdr-border focus:outline-none focus:border-sdr-accent-blue"
          >
            {TRIGGER_FIELDS.map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </select>
          <select
            value={condition.operator}
            onChange={(e) =>
              updateCondition(index, {
                operator: e.target.value as TriggerCondition["operator"],
              })
            }
            className="w-20 px-2 py-1 bg-sdr-bg-secondary text-sdr-text-primary text-xs rounded border border-sdr-border focus:outline-none focus:border-sdr-accent-blue"
          >
            {TRIGGER_OPERATORS.map((o) => (
              <option key={o} value={o}>
                {o === "equals"
                  ? "=="
                  : o === "not_equals"
                    ? "!="
                    : o === "contains"
                      ? "~="
                      : ">="}
              </option>
            ))}
          </select>
          <input
            type="text"
            value={String(condition.value)}
            onChange={(e) => updateCondition(index, { value: e.target.value })}
            placeholder="value"
            className="flex-1 px-2 py-1 bg-sdr-bg-secondary text-sdr-text-primary text-xs rounded border border-sdr-border focus:outline-none focus:border-sdr-accent-blue font-mono"
          />
          <button
            onClick={() => removeCondition(index)}
            className="p-1 text-sdr-text-muted hover:text-sdr-accent-red"
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none">
              <path
                d="M18 6L6 18M6 6l12 12"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
              />
            </svg>
          </button>
        </div>
      ))}

      <button
        onClick={addCondition}
        className="flex items-center gap-1 text-xs text-sdr-accent-blue hover:text-sdr-accent-blue/80 transition-colors"
      >
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none">
          <path
            d="M12 5v14M5 12h14"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
          />
        </svg>
        Add condition
      </button>
    </div>
  );
}

// === Actions Editor ===

function ActionsEditor({
  actions,
  onChange,
}: {
  actions: WorkflowAction[];
  onChange: (actions: WorkflowAction[]) => void;
}) {
  const addAction = (type: WorkflowAction["type"]) => {
    const newAction = createDefaultAction(type);
    onChange([...actions, newAction]);
  };

  const updateAction = (index: number, action: WorkflowAction) => {
    onChange(actions.map((a, i) => (i === index ? action : a)));
  };

  const removeAction = (index: number) => {
    onChange(actions.filter((_, i) => i !== index));
  };

  return (
    <div className="space-y-3">
      {actions.map((action, index) => (
        <ActionEditor
          key={index}
          action={action}
          onChange={(updated) => updateAction(index, updated)}
          onRemove={() => removeAction(index)}
        />
      ))}

      <div className="flex flex-wrap gap-1">
        {ACTION_TYPES.map((type) => (
          <button
            key={type}
            onClick={() => addAction(type)}
            className="px-2 py-1 text-xs bg-sdr-bg-tertiary text-sdr-text-secondary hover:text-sdr-text-primary rounded border border-sdr-border hover:border-sdr-accent-blue transition-colors"
          >
            + {ACTION_TYPE_LABELS[type]}
          </button>
        ))}
      </div>
    </div>
  );
}

const ACTION_TYPE_LABELS: Record<WorkflowAction["type"], string> = {
  webhook: "Webhook",
  slack_webhook: "Slack",
  pagerduty: "PagerDuty",
  email: "Email",
  log: "Log",
};

function createDefaultAction(type: WorkflowAction["type"]): WorkflowAction {
  switch (type) {
    case "webhook":
      return { type: "webhook", url: "", method: "POST", headers: {}, body: "" };
    case "slack_webhook":
      return { type: "slack_webhook", url: "", channel: "", template: "" };
    case "pagerduty":
      return { type: "pagerduty", routing_key: "", severity: "critical" };
    case "email":
      return { type: "email", to: [], subject: "", template: "" };
    case "log":
      return { type: "log", path: "", format: "json" };
  }
}

function ActionEditor({
  action,
  onChange,
  onRemove,
}: {
  action: WorkflowAction;
  onChange: (action: WorkflowAction) => void;
  onRemove: () => void;
}) {
  return (
    <div className="p-3 bg-sdr-bg-tertiary rounded-lg border border-sdr-border space-y-2">
      <div className="flex items-center justify-between">
        <Badge variant="outline">{ACTION_TYPE_LABELS[action.type]}</Badge>
        <button
          onClick={onRemove}
          className="p-1 text-sdr-text-muted hover:text-sdr-accent-red"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
            <path
              d="M18 6L6 18M6 6l12 12"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
            />
          </svg>
        </button>
      </div>

      {action.type === "webhook" && (
        <WebhookFields action={action} onChange={onChange} />
      )}
      {action.type === "slack_webhook" && (
        <SlackFields action={action} onChange={onChange} />
      )}
      {action.type === "pagerduty" && (
        <PagerDutyFields action={action} onChange={onChange} />
      )}
      {action.type === "email" && (
        <EmailFields action={action} onChange={onChange} />
      )}
      {action.type === "log" && (
        <LogFields action={action} onChange={onChange} />
      )}
    </div>
  );
}

function WebhookFields({
  action,
  onChange,
}: {
  action: Extract<WorkflowAction, { type: "webhook" }>;
  onChange: (action: WorkflowAction) => void;
}) {
  return (
    <>
      <FieldInput
        label="URL"
        value={action.url}
        onChange={(url) => onChange({ ...action, url })}
        placeholder="https://..."
        mono
      />
      <FieldInput
        label="Method"
        value={action.method}
        onChange={(method) => onChange({ ...action, method })}
        placeholder="POST"
      />
      <FieldInput
        label="Body template"
        value={action.body}
        onChange={(body) => onChange({ ...action, body })}
        placeholder='{"event": "{{event}}"}'
        mono
      />
    </>
  );
}

function SlackFields({
  action,
  onChange,
}: {
  action: Extract<WorkflowAction, { type: "slack_webhook" }>;
  onChange: (action: WorkflowAction) => void;
}) {
  return (
    <>
      <FieldInput
        label="Webhook URL"
        value={action.url}
        onChange={(url) => onChange({ ...action, url })}
        placeholder="https://hooks.slack.com/services/..."
        mono
      />
      <FieldInput
        label="Channel"
        value={action.channel}
        onChange={(channel) => onChange({ ...action, channel })}
        placeholder="#security-alerts"
      />
      <FieldInput
        label="Message template"
        value={action.template}
        onChange={(template) => onChange({ ...action, template })}
        placeholder="Alert: {{target}} was {{decision}}"
      />
    </>
  );
}

function PagerDutyFields({
  action,
  onChange,
}: {
  action: Extract<WorkflowAction, { type: "pagerduty" }>;
  onChange: (action: WorkflowAction) => void;
}) {
  return (
    <>
      <FieldInput
        label="Routing key"
        value={action.routing_key}
        onChange={(routing_key) => onChange({ ...action, routing_key })}
        placeholder="Integration key"
        mono
      />
      <div>
        <label className="block text-xs text-sdr-text-muted mb-1">
          Severity
        </label>
        <select
          value={action.severity}
          onChange={(e) => onChange({ ...action, severity: e.target.value })}
          className="w-full px-2 py-1.5 bg-sdr-bg-secondary text-sdr-text-primary text-xs rounded border border-sdr-border focus:outline-none focus:border-sdr-accent-blue"
        >
          <option value="critical">Critical</option>
          <option value="error">Error</option>
          <option value="warning">Warning</option>
          <option value="info">Info</option>
        </select>
      </div>
    </>
  );
}

function EmailFields({
  action,
  onChange,
}: {
  action: Extract<WorkflowAction, { type: "email" }>;
  onChange: (action: WorkflowAction) => void;
}) {
  return (
    <>
      <FieldInput
        label="Recipient(s)"
        value={action.to.join(", ")}
        onChange={(val) =>
          onChange({
            ...action,
            to: val
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean),
          })
        }
        placeholder="team@example.com, alerts@example.com"
      />
      <FieldInput
        label="Subject template"
        value={action.subject}
        onChange={(subject) => onChange({ ...action, subject })}
        placeholder="[SDR] {{decision}} on {{target}}"
      />
      <FieldInput
        label="Body template"
        value={action.template}
        onChange={(template) => onChange({ ...action, template })}
        placeholder="Event details: {{message}}"
      />
    </>
  );
}

function LogFields({
  action,
  onChange,
}: {
  action: Extract<WorkflowAction, { type: "log" }>;
  onChange: (action: WorkflowAction) => void;
}) {
  return (
    <>
      <FieldInput
        label="Log path"
        value={action.path}
        onChange={(path) => onChange({ ...action, path })}
        placeholder="/var/log/sdr/workflows.log"
        mono
      />
      <div>
        <label className="block text-xs text-sdr-text-muted mb-1">
          Format
        </label>
        <select
          value={action.format}
          onChange={(e) => onChange({ ...action, format: e.target.value })}
          className="w-full px-2 py-1.5 bg-sdr-bg-secondary text-sdr-text-primary text-xs rounded border border-sdr-border focus:outline-none focus:border-sdr-accent-blue"
        >
          <option value="json">JSON</option>
          <option value="text">Text</option>
          <option value="csv">CSV</option>
        </select>
      </div>
    </>
  );
}

function FieldInput({
  label,
  value,
  onChange,
  placeholder,
  mono,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  mono?: boolean;
}) {
  return (
    <div>
      <label className="block text-xs text-sdr-text-muted mb-1">{label}</label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={clsx(
          "w-full px-2 py-1.5 bg-sdr-bg-secondary text-sdr-text-primary text-xs rounded border border-sdr-border focus:outline-none focus:border-sdr-accent-blue placeholder:text-sdr-text-muted",
          mono && "font-mono"
        )}
      />
    </div>
  );
}

// === Display components ===

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <h3 className="text-xs font-medium text-sdr-text-muted uppercase tracking-wide mb-2">
        {title}
      </h3>
      {children}
    </div>
  );
}

function TriggerDisplay({ trigger }: { trigger: WorkflowTrigger }) {
  if (trigger.type === "event_match") {
    return (
      <div className="text-sm text-sdr-text-secondary">
        <p>When event matches:</p>
        {trigger.conditions.map((cond, i) => (
          <p key={i} className="ml-2 font-mono text-xs">
            {cond.field} {cond.operator} {String(cond.value)}
          </p>
        ))}
      </div>
    );
  }
  if (trigger.type === "schedule") {
    return (
      <p className="text-sm text-sdr-text-secondary font-mono">
        {trigger.cron}
      </p>
    );
  }
  if (trigger.type === "aggregation") {
    return (
      <p className="text-sm text-sdr-text-secondary">
        {trigger.threshold} events in {trigger.window}
      </p>
    );
  }
  return null;
}

function ActionDisplay({ action }: { action: WorkflowAction }) {
  return (
    <div className="flex items-center gap-2 text-sm">
      <Badge variant="outline">{ACTION_TYPE_LABELS[action.type]}</Badge>
      <span className="text-sdr-text-secondary truncate">
        {action.type === "slack_webhook" && action.channel}
        {action.type === "email" && action.to.join(", ")}
        {action.type === "pagerduty" && action.severity}
        {action.type === "webhook" && action.url}
        {action.type === "log" && action.path}
      </span>
    </div>
  );
}

function CloseIcon() {
  return (
    <svg
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
    >
      <path d="M18 6L6 18M6 6l12 12" />
    </svg>
  );
}
