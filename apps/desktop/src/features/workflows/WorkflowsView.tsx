/**
 * WorkflowsView - Automated response chains
 */
import { useState, useEffect } from "react";
import type { ReactNode } from "react";
import { clsx } from "clsx";
import type { Workflow, WorkflowTrigger, WorkflowAction } from "@/services/tauri";
import { listWorkflows, saveWorkflow, deleteWorkflow, testWorkflow, isTauri } from "@/services/tauri";

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
      { type: "slack_webhook", url: "https://hooks.slack.com/...", channel: "#security-alerts", template: "Critical block: {{target}}" },
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
      { type: "email", to: ["security@example.com"], subject: "Daily SDR Summary", template: "Events: {{total_events}}, Blocked: {{blocked_count}}" },
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

export function WorkflowsView() {
  const [workflows, setWorkflows] = useState<Workflow[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedWorkflow, setSelectedWorkflow] = useState<Workflow | null>(null);
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
        // Use mock data in browser
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
      setWorkflows((prev) => prev.map((w) => (w.id === workflow.id ? updated : w)));
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
      alert(result.success ? "Test passed!" : `Test failed: ${result.message}`);
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
    <div className="flex h-full">
      {/* Workflow list */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-sdr-border bg-sdr-bg-secondary">
          <div>
            <h1 className="text-lg font-semibold text-sdr-text-primary">Workflows</h1>
            <p className="text-sm text-sdr-text-muted mt-0.5">
              Automated response chains for policy events
            </p>
          </div>
          <button
            onClick={handleNewWorkflow}
            className="px-3 py-1.5 text-sm bg-sdr-accent-blue text-white font-medium rounded-md hover:bg-sdr-accent-blue/90 transition-colors"
          >
            New Workflow
          </button>
        </div>

        {/* Workflow list */}
        <div className="flex-1 overflow-y-auto">
          {isLoading ? (
            <div className="flex items-center justify-center h-full text-sdr-text-muted">
              Loading...
            </div>
          ) : workflows.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-sdr-text-muted">
              <p>No workflows yet</p>
              <p className="text-sm mt-1">Create a workflow to automate responses</p>
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
    </div>
  );
}

interface WorkflowRowProps {
  workflow: Workflow;
  isSelected: boolean;
  onSelect: () => void;
  onToggle: () => void;
}

function WorkflowRow({ workflow, isSelected, onSelect, onToggle }: WorkflowRowProps) {
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
          <span className="font-medium text-sdr-text-primary">{workflow.name}</span>
          <TriggerBadge trigger={workflow.trigger} />
        </div>
        <div className="text-xs text-sdr-text-muted mt-0.5">
          {workflow.actions.length} action{workflow.actions.length !== 1 ? "s" : ""} ·{" "}
          {workflow.run_count} runs
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

  return (
    <span className="px-1.5 py-0.5 text-xs bg-sdr-bg-tertiary text-sdr-text-muted rounded">
      {labels[trigger.type] ?? trigger.type}
    </span>
  );
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

  return (
    <div className="w-96 border-l border-sdr-border bg-sdr-bg-secondary flex flex-col">
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
              <input
                type="text"
                value={draft.name}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                className="w-full px-3 py-2 bg-sdr-bg-tertiary text-sdr-text-primary rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue"
              />
            </div>

            {/* Trigger type */}
            <div>
              <label className="block text-sm font-medium text-sdr-text-primary mb-1">
                Trigger Type
              </label>
              <select
                value={draft.trigger.type}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    trigger: { type: e.target.value as "event_match" | "schedule" | "aggregation", conditions: [] } as WorkflowTrigger,
                  })
                }
                className="w-full px-3 py-2 bg-sdr-bg-tertiary text-sdr-text-primary rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue"
              >
                <option value="event_match">Event Match</option>
                <option value="schedule">Schedule (Cron)</option>
                <option value="aggregation">Aggregation</option>
              </select>
            </div>

            <p className="text-xs text-sdr-text-muted">
              Full workflow editor coming soon. Configure triggers and actions in the JSON editor.
            </p>
          </>
        ) : (
          <>
            {/* Name */}
            <Section title="Name">
              <p className="text-sm text-sdr-text-primary">{workflow.name}</p>
            </Section>

            {/* Trigger */}
            <Section title="Trigger">
              <TriggerDisplay trigger={workflow.trigger} />
            </Section>

            {/* Actions */}
            <Section title="Actions">
              {workflow.actions.length === 0 ? (
                <p className="text-sm text-sdr-text-muted">No actions configured</p>
              ) : (
                <div className="space-y-2">
                  {workflow.actions.map((action, i) => (
                    <ActionDisplay key={i} action={action} />
                  ))}
                </div>
              )}
            </Section>

            {/* Stats */}
            <Section title="Statistics">
              <div className="text-sm text-sdr-text-secondary space-y-1">
                <p>Run count: {workflow.run_count}</p>
                {workflow.last_run && (
                  <p>Last run: {new Date(workflow.last_run).toLocaleString()}</p>
                )}
                <p>Created: {new Date(workflow.created_at).toLocaleDateString()}</p>
              </div>
            </Section>
          </>
        )}
      </div>

      {/* Actions */}
      <div className="p-4 border-t border-sdr-border space-y-2">
        {isEditing ? (
          <>
            <button
              onClick={handleSave}
              className="w-full px-3 py-2 bg-sdr-accent-blue text-white font-medium rounded-md hover:bg-sdr-accent-blue/90 transition-colors"
            >
              Save Workflow
            </button>
            <button
              onClick={() => {
                setDraft(workflow);
                onClose();
              }}
              className="w-full px-3 py-2 bg-sdr-bg-tertiary text-sdr-text-secondary hover:text-sdr-text-primary rounded-md transition-colors"
            >
              Cancel
            </button>
          </>
        ) : (
          <>
            <div className="flex gap-2">
              <button
                onClick={onEdit}
                className="flex-1 px-3 py-2 bg-sdr-bg-tertiary text-sdr-text-secondary hover:text-sdr-text-primary rounded-md transition-colors"
              >
                Edit
              </button>
              <button
                onClick={onTest}
                className="flex-1 px-3 py-2 bg-sdr-bg-tertiary text-sdr-text-secondary hover:text-sdr-text-primary rounded-md transition-colors"
              >
                Test
              </button>
            </div>
            <button
              onClick={onDelete}
              className="w-full px-3 py-2 text-sdr-accent-red hover:bg-sdr-accent-red/10 rounded-md transition-colors"
            >
              Delete Workflow
            </button>
          </>
        )}
      </div>
    </div>
  );
}

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
    return <p className="text-sm text-sdr-text-secondary font-mono">{trigger.cron}</p>;
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
  const labels: Record<string, string> = {
    slack_webhook: "Slack",
    pagerduty: "PagerDuty",
    email: "Email",
    webhook: "Webhook",
    log: "Log",
  };

  return (
    <div className="flex items-center gap-2 text-sm">
      <span className="px-2 py-0.5 bg-sdr-bg-tertiary text-sdr-text-muted rounded text-xs">
        {labels[action.type] ?? action.type}
      </span>
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
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M18 6L6 18M6 6l12 12" />
    </svg>
  );
}
