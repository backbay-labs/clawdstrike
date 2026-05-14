import { useMemo } from "react";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import type { WorkbenchPolicy, GuardId, GuardConfigMap } from "@/lib/workbench/types";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  IconPlus,
  IconMinus,
  IconArrowsExchange,
  IconEqual,
} from "@tabler/icons-react";

interface SemanticDiffViewProps {
  policyA: WorkbenchPolicy;
  policyB: WorkbenchPolicy;
}

type ChangeType = "added" | "removed" | "changed" | "unchanged";

interface GuardChange {
  guardId: GuardId;
  guardName: string;
  changeType: ChangeType;
  fieldChanges: FieldChange[];
}

interface FieldChange {
  field: string;
  oldValue: string;
  newValue: string;
}

interface MetaChange {
  field: string;
  oldValue: string;
  newValue: string;
}

function stringify(val: unknown): string {
  if (val === undefined || val === null) return "(none)";
  if (typeof val === "boolean") return val ? "true" : "false";
  if (typeof val === "number") return String(val);
  if (typeof val === "string") return val;
  if (Array.isArray(val)) {
    if (val.length === 0) return "[]";
    return JSON.stringify(val, null, 0);
  }
  return JSON.stringify(val, null, 0);
}

function compareObjects(
  a: Record<string, unknown> | undefined,
  b: Record<string, unknown> | undefined
): FieldChange[] {
  const changes: FieldChange[] = [];
  const allKeys = new Set([
    ...Object.keys(a ?? {}),
    ...Object.keys(b ?? {}),
  ]);

  for (const key of allKeys) {
    if (key === "enabled") continue; // handled at guard level
    const valA = (a ?? {})[key];
    const valB = (b ?? {})[key];
    const strA = stringify(valA);
    const strB = stringify(valB);
    if (strA !== strB) {
      changes.push({ field: key, oldValue: strA, newValue: strB });
    }
  }

  return changes;
}

function computeGuardChanges(
  policyA: WorkbenchPolicy,
  policyB: WorkbenchPolicy
): GuardChange[] {
  const changes: GuardChange[] = [];

  for (const guard of GUARD_REGISTRY) {
    const configA = policyA.guards[guard.id] as Record<string, unknown> | undefined;
    const configB = policyB.guards[guard.id] as Record<string, unknown> | undefined;

    const enabledA = configA?.enabled === true;
    const enabledB = configB?.enabled === true;
    const presentA = configA !== undefined;
    const presentB = configB !== undefined;

    if (!presentA && !presentB) {
      // Neither has it - skip
      continue;
    }

    if (!presentA && presentB) {
      changes.push({
        guardId: guard.id,
        guardName: guard.name,
        changeType: "added",
        fieldChanges: [],
      });
    } else if (presentA && !presentB) {
      changes.push({
        guardId: guard.id,
        guardName: guard.name,
        changeType: "removed",
        fieldChanges: [],
      });
    } else {
      // Both present
      const enabledChange = enabledA !== enabledB;
      const fieldChanges = compareObjects(configA, configB);

      if (enabledChange || fieldChanges.length > 0) {
        const allChanges = [...fieldChanges];
        if (enabledChange) {
          allChanges.unshift({
            field: "enabled",
            oldValue: String(enabledA),
            newValue: String(enabledB),
          });
        }
        changes.push({
          guardId: guard.id,
          guardName: guard.name,
          changeType: "changed",
          fieldChanges: allChanges,
        });
      } else {
        changes.push({
          guardId: guard.id,
          guardName: guard.name,
          changeType: "unchanged",
          fieldChanges: [],
        });
      }
    }
  }

  return changes;
}

function computeMetaChanges(
  policyA: WorkbenchPolicy,
  policyB: WorkbenchPolicy
): MetaChange[] {
  const changes: MetaChange[] = [];

  if (policyA.name !== policyB.name) {
    changes.push({ field: "name", oldValue: policyA.name, newValue: policyB.name });
  }
  if (policyA.version !== policyB.version) {
    changes.push({ field: "version", oldValue: policyA.version, newValue: policyB.version });
  }
  if ((policyA.extends ?? "") !== (policyB.extends ?? "")) {
    changes.push({
      field: "extends",
      oldValue: policyA.extends ?? "(none)",
      newValue: policyB.extends ?? "(none)",
    });
  }
  if (policyA.description !== policyB.description) {
    changes.push({
      field: "description",
      oldValue: policyA.description || "(none)",
      newValue: policyB.description || "(none)",
    });
  }

  return changes;
}

function computeSettingsChanges(
  policyA: WorkbenchPolicy,
  policyB: WorkbenchPolicy
): FieldChange[] {
  return compareObjects(
    policyA.settings as unknown as Record<string, unknown>,
    policyB.settings as unknown as Record<string, unknown>
  );
}

const changeTypeConfig: Record<
  ChangeType,
  { label: string; color: string; bgColor: string; borderColor: string; icon: typeof IconPlus }
> = {
  added: {
    label: "Added",
    color: "#3dbf84",
    bgColor: "#3dbf84/10",
    borderColor: "#3dbf84/20",
    icon: IconPlus,
  },
  removed: {
    label: "Removed",
    color: "#c45c5c",
    bgColor: "#c45c5c/10",
    borderColor: "#c45c5c/20",
    icon: IconMinus,
  },
  changed: {
    label: "Changed",
    color: "#d4a84b",
    bgColor: "#d4a84b/10",
    borderColor: "#d4a84b/20",
    icon: IconArrowsExchange,
  },
  unchanged: {
    label: "Unchanged",
    color: "#6f7f9a",
    bgColor: "#6f7f9a/10",
    borderColor: "#6f7f9a/20",
    icon: IconEqual,
  },
};

function ChangeTypeBadge({ type }: { type: ChangeType }) {
  const cfg = changeTypeConfig[type];
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono uppercase border rounded-md select-none"
      style={{
        color: cfg.color,
        backgroundColor: `${cfg.color}10`,
        borderColor: `${cfg.color}33`,
      }}
    >
      <cfg.icon size={10} stroke={1.5} />
      {cfg.label}
    </span>
  );
}

function GuardChangeCard({ change }: { change: GuardChange }) {
  return (
    <div className="border border-[#2d3240] rounded-lg bg-[#0b0d13] overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 border-b border-[#2d3240]">
        <span className="text-xs font-medium text-[#ece7dc]">
          {change.guardName}
        </span>
        <ChangeTypeBadge type={change.changeType} />
      </div>
      {change.fieldChanges.length > 0 && (
        <div className="px-3 py-2 space-y-1">
          {change.fieldChanges.map((fc) => (
            <div key={fc.field} className="flex items-start gap-2 text-xs">
              <span className="shrink-0 font-mono text-[#6f7f9a] min-w-[120px]">
                {fc.field}
              </span>
              <span className="font-mono text-[#c45c5c] line-through">
                {fc.oldValue}
              </span>
              <span className="text-[#6f7f9a]">&rarr;</span>
              <span className="font-mono text-[#3dbf84]">{fc.newValue}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function SemanticDiffView({ policyA, policyB }: SemanticDiffViewProps) {
  const guardChanges = useMemo(
    () => computeGuardChanges(policyA, policyB),
    [policyA, policyB]
  );
  const metaChanges = useMemo(
    () => computeMetaChanges(policyA, policyB),
    [policyA, policyB]
  );
  const settingsChanges = useMemo(
    () => computeSettingsChanges(policyA, policyB),
    [policyA, policyB]
  );

  const added = guardChanges.filter((g) => g.changeType === "added");
  const removed = guardChanges.filter((g) => g.changeType === "removed");
  const changed = guardChanges.filter((g) => g.changeType === "changed");
  const unchanged = guardChanges.filter((g) => g.changeType === "unchanged");

  const noChanges =
    metaChanges.length === 0 &&
    settingsChanges.length === 0 &&
    added.length === 0 &&
    removed.length === 0 &&
    changed.length === 0;

  return (
    <ScrollArea className="h-full">
      <div className="p-4 space-y-6">
        {/* Meta changes */}
        {metaChanges.length > 0 && (
          <section>
            <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-3">
              Metadata
            </h3>
            <div className="border border-[#2d3240] rounded-lg bg-[#0b0d13] px-3 py-2 space-y-1">
              {metaChanges.map((mc) => (
                <div key={mc.field} className="flex items-start gap-2 text-xs">
                  <span className="shrink-0 font-mono text-[#6f7f9a] min-w-[100px]">
                    {mc.field}
                  </span>
                  <span className="font-mono text-[#c45c5c] line-through">
                    {mc.oldValue}
                  </span>
                  <span className="text-[#6f7f9a]">&rarr;</span>
                  <span className="font-mono text-[#3dbf84]">{mc.newValue}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Settings changes */}
        {settingsChanges.length > 0 && (
          <section>
            <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-3">
              Settings
            </h3>
            <div className="border border-[#2d3240] rounded-lg bg-[#0b0d13] px-3 py-2 space-y-1">
              {settingsChanges.map((sc) => (
                <div key={sc.field} className="flex items-start gap-2 text-xs">
                  <span className="shrink-0 font-mono text-[#6f7f9a] min-w-[160px]">
                    {sc.field}
                  </span>
                  <span className="font-mono text-[#c45c5c] line-through">
                    {sc.oldValue}
                  </span>
                  <span className="text-[#6f7f9a]">&rarr;</span>
                  <span className="font-mono text-[#3dbf84]">{sc.newValue}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Guard changes by category */}
        {added.length > 0 && (
          <section>
            <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#3dbf84] mb-3">
              Added Guards ({added.length})
            </h3>
            <div className="space-y-2">
              {added.map((g) => (
                <GuardChangeCard key={g.guardId} change={g} />
              ))}
            </div>
          </section>
        )}

        {removed.length > 0 && (
          <section>
            <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#c45c5c] mb-3">
              Removed Guards ({removed.length})
            </h3>
            <div className="space-y-2">
              {removed.map((g) => (
                <GuardChangeCard key={g.guardId} change={g} />
              ))}
            </div>
          </section>
        )}

        {changed.length > 0 && (
          <section>
            <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#d4a84b] mb-3">
              Changed Guards ({changed.length})
            </h3>
            <div className="space-y-2">
              {changed.map((g) => (
                <GuardChangeCard key={g.guardId} change={g} />
              ))}
            </div>
          </section>
        )}

        {unchanged.length > 0 && (
          <section>
            <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-3">
              Unchanged Guards ({unchanged.length})
            </h3>
            <div className="space-y-2">
              {unchanged.map((g) => (
                <GuardChangeCard key={g.guardId} change={g} />
              ))}
            </div>
          </section>
        )}

        {noChanges && (
          <div className="flex items-center justify-center py-16 text-[#6f7f9a] text-sm">
            Policies are identical
          </div>
        )}
      </div>
    </ScrollArea>
  );
}
