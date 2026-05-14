import { useState, useCallback, useRef, useEffect, useMemo } from "react";
import { useToast } from "@/components/ui/toast";
import { YamlEditor, type YamlEditorError } from "@/components/ui/yaml-editor";
import { cn } from "@/lib/utils";
import type { FileType } from "@/lib/workbench/file-type-registry";
import { generateScenariosFromPolicy } from "@/lib/workbench/scenario-generator";
import { useTestRunnerOptional } from "@/lib/workbench/test-store";
import type { SuiteScenario } from "@/lib/workbench/suite-parser";
import type { TestScenario } from "@/lib/workbench/types";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";
import { useWorkbenchUIStore } from "@/features/policy/stores/workbench-ui-store";
import { DEFAULT_POLICY } from "@/features/policy/stores/policy-store";

type Tab = "preview" | "edit";

/** Convert a TestScenario to the SuiteScenario format used by the test runner. */
function extractTarget(s: TestScenario): string {
  const p = s.payload;
  if (typeof p.path === "string") return p.path;
  if (typeof p.host === "string") return p.host;
  if (typeof p.command === "string") return p.command;
  if (typeof p.tool === "string") return p.tool;
  if (typeof p.text === "string") return p.text.slice(0, 120);
  return JSON.stringify(p).slice(0, 120);
}

function testScenarioToSuite(s: TestScenario): SuiteScenario {
  const suite: SuiteScenario = {
    id: s.id,
    name: s.name,
    action: s.actionType,
    target: extractTarget(s),
    description: s.description,
  };
  if (s.expectedVerdict) suite.expect = s.expectedVerdict;
  if (typeof s.payload.content === "string") suite.content = s.payload.content;
  if (s.category) suite.tags = [s.category];
  return suite;
}

interface YamlPreviewPanelProps {
  fileType?: FileType;
}

export function YamlPreviewPanel({ fileType }: YamlPreviewPanelProps) {
  const activeTabId = usePolicyTabsStore(s => s.activeTabId);
  const storeTab = usePolicyTabsStore(s => s.tabs.find(t => t.id === s.activeTabId));
  const editState = usePolicyEditStore(s => s.editStates.get(activeTabId));
  const { toast } = useToast();
  const testRunner = useTestRunnerOptional();
  const editorSyncDirection = useWorkbenchUIStore(s => s.editorSyncDirection);
  const [activeTab, setActiveTab] = useState<Tab>("preview");
  const [localYaml, setLocalYaml] = useState((editState?.yaml ?? ""));
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Sync local yaml when state changes from visual panel edits
  useEffect(() => {
    if (editorSyncDirection !== "yaml") {
      setLocalYaml((editState?.yaml ?? ""));
    }
  }, [(editState?.yaml ?? ""), editorSyncDirection]);

  const handleYamlChange = useCallback(
    (value: string) => {
      setLocalYaml(value);

      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }
      debounceRef.current = setTimeout(() => {
        usePolicyEditStore.getState().setYaml(activeTabId, value, storeTab?.fileType ?? "clawdstrike_policy", storeTab?.filePath ?? null, storeTab?.name ?? "Untitled");
      usePolicyTabsStore.getState().setDirty(activeTabId, true);
      }, 500);
    },
    [activeTabId, storeTab?.fileType]
  );

  // Cleanup debounce on unmount
  useEffect(() => {
    return () => {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }
    };
  }, []);

  // Gutter "Run Test" callback: generates scenarios for the clicked guard and imports into test runner
  const handleRunGuardTest = useCallback(
    (guardId: string) => {
      const result = generateScenariosFromPolicy((editState?.policy ?? DEFAULT_POLICY));
      const prefix = `auto-${guardId}-`;
      const guardScenarios = result.scenarios.filter((s) => s.id.startsWith(prefix));

      if (guardScenarios.length === 0) {
        toast({
          type: "info",
          title: "No scenarios generated",
          description: `No test scenarios could be generated for guard "${guardId}". Enable the guard first.`,
        });
        return;
      }

      if (testRunner) {
        const suiteScenarios: SuiteScenario[] = guardScenarios.map(testScenarioToSuite);
        testRunner.dispatch({ type: "IMPORT_SCENARIOS", scenarios: suiteScenarios });
        toast({
          type: "success",
          title: "Tests imported",
          description: `${suiteScenarios.length} scenario${suiteScenarios.length !== 1 ? "s" : ""} imported for ${guardId}`,
        });
      } else {
        toast({
          type: "info",
          title: "Test Runner not available",
          description: `Open Test Runner to execute tests for ${guardId}`,
        });
      }
    },
    [(editState?.policy ?? DEFAULT_POLICY), testRunner, toast],
  );

  const isPolicyFile = fileType === "clawdstrike_policy";

  const { errors, warnings } = (editState?.validation ?? { valid: true, errors: [], warnings: [] });
  const editLabel = fileType === "yara_rule"
    ? "Edit Source"
    : fileType === "ocsf_event"
    ? "Edit JSON"
    : "Edit YAML";

  // Show toast when new YAML parse errors appear (only while editing)
  const prevErrorCountRef = useRef(errors.length);
  useEffect(() => {
    if (activeTab === "edit" && errors.length > 0 && errors.length > prevErrorCountRef.current) {
      toast({
        type: "error",
        title: "Validation error",
        description: errors[0].message,
      });
    }
    prevErrorCountRef.current = errors.length;
  }, [errors, activeTab, toast]);

  // Map validation errors to CodeMirror editor markers
  const editorErrors = useMemo<YamlEditorError[]>(() => {
    const items: YamlEditorError[] = [];
    for (const e of errors) {
      items.push({ message: `${e.path}: ${e.message}` });
    }
    return items;
  }, [errors]);

  // Merge native validation errors (from Rust engine via the store's useNativeValidation hook)
  // with client-side issues. Native errors are authoritative.
  const nv = (editState?.nativeValidation ?? { guardErrors: {}, topLevelErrors: [], topLevelWarnings: [], loading: false, valid: null });
  const nativeIssues = useMemo(() => {
    if (nv.valid === null && !nv.loading) return [];

    const issues: Array<{ path: string; message: string; severity: "error" | "warning"; source: "native" }> = [];
    for (const msg of nv.topLevelErrors) {
      issues.push({ path: "yaml", message: msg, severity: "error", source: "native" });
    }
    for (const [guardId, msgs] of Object.entries(nv.guardErrors)) {
      for (const msg of msgs) {
        issues.push({ path: `guards.${guardId}`, message: msg, severity: "error", source: "native" });
      }
    }
    return issues;
  }, [nv]);

  const clientIssues = [...errors, ...warnings].map((i) => ({ ...i, source: "client" as const }));

  // If we have native results, show them first; then any client-only issues that
  // are not already covered by a native error at the same path.
  const allIssues = nativeIssues.length > 0
    ? [
        ...nativeIssues,
        ...clientIssues.filter(
          (ci) => !nativeIssues.some((ni) => ni.path === ci.path)
        ),
      ]
    : clientIssues;

  return (
    <div className="flex flex-col h-full bg-[#0b0d13]">
      {/* Tab bar */}
      <div className="flex items-center border-b border-[#2d3240]/60 shrink-0">
        <button
          onClick={() => setActiveTab("preview")}
          className={cn(
            "px-4 py-2.5 text-xs font-mono transition-colors relative",
            activeTab === "preview"
              ? "text-[#ece7dc]"
              : "text-[#6f7f9a] hover:text-[#ece7dc]"
          )}
        >
          Preview
          {activeTab === "preview" && (
            <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#d4a84b]" />
          )}
        </button>
        <button
          onClick={() => setActiveTab("edit")}
          className={cn(
            "px-4 py-2.5 text-xs font-mono transition-colors relative",
            activeTab === "edit"
              ? "text-[#ece7dc]"
              : "text-[#6f7f9a] hover:text-[#ece7dc]"
          )}
        >
          {editLabel}
          {activeTab === "edit" && (
            <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#d4a84b]" />
          )}
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden">
        {activeTab === "preview" ? (
          <YamlEditor
            value={(editState?.yaml ?? "")}
            onChange={() => {}}
            readOnly
            fileType={fileType}
            showDetectionGutters={isPolicyFile}
            onRunGuardTest={isPolicyFile ? handleRunGuardTest : undefined}
            filePath={storeTab?.filePath ?? null}
          />
        ) : (
          <YamlEditor
            value={localYaml}
            onChange={handleYamlChange}
            errors={editorErrors}
            fileType={fileType}
            showDetectionGutters={isPolicyFile}
            onRunGuardTest={isPolicyFile ? handleRunGuardTest : undefined}
            filePath={storeTab?.filePath ?? null}
          />
        )}
      </div>

      {/* Validation issues */}
      {(allIssues.length > 0 || nv.loading) && (
        <div className="shrink-0 border-t border-[#2d3240] max-h-40 overflow-auto">
          <div className="p-3 flex flex-col gap-1.5">
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
                Issues ({allIssues.length})
              </span>
              {nv.loading && (
                <span className="text-[9px] font-mono text-[#d4a84b]/70 animate-pulse">
                  validating...
                </span>
              )}
              {nv.valid !== null && !nv.loading && (
                <span
                  className={cn(
                    "text-[9px] font-mono px-1.5 py-0 border rounded",
                    nv.valid
                      ? "text-[#3dbf84]/70 border-[#3dbf84]/20 bg-[#3dbf84]/5"
                      : "text-[#c45c5c]/70 border-[#c45c5c]/20 bg-[#c45c5c]/5"
                  )}
                >
                  engine: {nv.valid ? "valid" : "invalid"}
                </span>
              )}
            </div>
            {allIssues.map((issue, i) => (
              <div key={i} className="flex items-start gap-2 text-xs">
                <span
                  className={cn(
                    "shrink-0 px-1.5 py-0 text-[10px] font-mono uppercase border rounded",
                    issue.severity === "error"
                      ? "bg-[#c45c5c]/10 text-[#c45c5c] border-[#c45c5c]/20"
                      : "bg-[#d4a84b]/10 text-[#d4a84b] border-[#d4a84b]/20"
                  )}
                >
                  {issue.severity}
                </span>
                {"source" in issue && issue.source === "native" && (
                  <span className="shrink-0 px-1 py-0 text-[9px] font-mono text-[#6f7f9a]/50 border border-[#2d3240] rounded">
                    rust
                  </span>
                )}
                <span className="text-[#6f7f9a] font-mono text-[10px]">
                  {issue.path}
                </span>
                <span className="text-[#ece7dc]/70">{issue.message}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
