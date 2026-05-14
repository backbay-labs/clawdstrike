/**
 * FileEditorShell -- Complete per-file editor wrapper with contextual toolbar.
 *
 * Bridges a /file/* pane route to the policy-tabs-store. Handles:
 * - Regular file paths: looks up tab by filePath match
 * - __new__ routes: looks up tab by tabId in the route (/file/__new__/{tabId})
 * - File loading: if no tab exists for the filePath, loads via Tauri bridge
 * - Toolbar: renders FileEditorToolbar with per-file state (testRunner, problems)
 * - Active tab sync: keeps policy-tabs-store.activeTabId in sync
 * - Live editing: YamlEditor (CodeMirror) wired to policy-edit-store for
 *   per-tab editing, undo/redo, validation, and dirty tracking
 */
import { useState, useEffect, useCallback } from "react";
import { useParams } from "react-router-dom";
import { YamlEditor } from "@/components/ui/yaml-editor";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { EditorVisualPanel } from "@/components/workbench/editor/editor-visual-panel";
import { TestRunnerPanel } from "@/components/workbench/editor/test-runner-panel";
import { TestRunnerProvider, useTestRunnerOptional } from "@/lib/workbench/test-store";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";
import { useNativeValidation } from "@/features/policy/use-native-validation";
import { useAutoVersion } from "@/features/policy/use-auto-version";
import { isPolicyFileType } from "@/lib/workbench/file-type-registry";
import { restoreFileRoutePath } from "@/lib/workbench/path-utils";
import { generateScenariosFromPolicy } from "@/lib/workbench/scenario-generator";
import { useToast } from "@/components/ui/toast";
import type { SuiteScenario } from "@/lib/workbench/suite-parser";
import type { TestScenario } from "@/lib/workbench/types";
import type { FileType } from "@/lib/workbench/file-type-registry";
import type { YamlEditorError } from "@/components/ui/yaml-editor";
import { DEFAULT_POLICY } from "@/features/policy/stores/policy-store";
import { FileEditorToolbar } from "./file-editor-toolbar";

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

/**
 * Inner wrapper rendered inside TestRunnerProvider so useTestRunnerOptional()
 * can access the context. FileEditorShell itself creates the provider, so
 * calling the hook at the FileEditorShell level would always return null.
 */
function GuardTestYamlEditor({
  value,
  onChange,
  fileType,
  errors,
  showDetectionGutters,
  activePolicy,
  filePath,
}: {
  value: string;
  onChange: (value: string) => void;
  fileType?: FileType;
  errors?: YamlEditorError[];
  showDetectionGutters?: boolean;
  activePolicy: import("@/lib/workbench/types").WorkbenchPolicy;
  filePath?: string;
}) {
  const { toast } = useToast();
  const testRunner = useTestRunnerOptional();

  const handleRunGuardTest = useCallback(
    (guardId: string) => {
      const result = generateScenariosFromPolicy(activePolicy);
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
    [activePolicy, testRunner, toast],
  );

  return (
    <YamlEditor
      value={value}
      onChange={onChange}
      fileType={fileType}
      errors={errors}
      showDetectionGutters={showDetectionGutters}
      onRunGuardTest={fileType === "clawdstrike_policy" ? handleRunGuardTest : undefined}
      filePath={filePath}
    />
  );
}

export function FileEditorShell() {
  const params = useParams();
  const rawParam = params["*"] ?? "";
  const filePath = restoreFileRoutePath(rawParam);
  const isNewFile = filePath.startsWith("__new__/");

  // Per-file local state for panel toggles
  const [testRunnerOpen, setTestRunnerOpen] = useState(false);
  const [showProblems, setShowProblems] = useState(false);
  const [splitActive, setSplitActive] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);

  const newTabId = isNewFile ? filePath.split("/")[1] : null;

  // Look up tab: either by __new__ tabId or by filePath match
  const tabMeta = usePolicyTabsStore((s) => {
    if (isNewFile && newTabId) {
      return s.tabs.find((t) => t.id === newTabId) ?? null;
    }
    return s.tabs.find((t) => t.filePath === filePath) ?? null;
  });

  const activeTabId = usePolicyTabsStore((s) => s.activeTabId);

  const editState = usePolicyEditStore((s) =>
    tabMeta ? s.editStates.get(tabMeta.id) : undefined,
  );

  // --- Live editing: onChange handler wired to policy-edit-store ---
  // Depend on stable scalar fields only (not the whole tabMeta object
  // which is a new reference on every store update) to avoid re-creating
  // the callback on every keystroke.
  const tabId = tabMeta?.id;
  const tabFileType = tabMeta?.fileType;
  const tabFilePath = tabMeta?.filePath;
  const tabName = tabMeta?.name;
  const handleEditorChange = useCallback(
    (newYaml: string) => {
      if (!tabId) return;
      usePolicyEditStore.getState().setYaml(
        tabId,
        newYaml,
        tabFileType!,
        tabFilePath ?? null,
        tabName ?? "File",
      );
      // Sync dirty state to policy-tabs-store (drives pane tab dirty dot)
      const isDirty = usePolicyEditStore.getState().isDirty(tabId);
      const currentDirty = usePolicyTabsStore.getState().tabs.find((t) => t.id === tabId)?.dirty;
      if (currentDirty !== isDirty) {
        usePolicyTabsStore.getState().setDirty(tabId, isDirty);
      }
    },
    [tabId, tabFileType, tabFilePath, tabName],
  );

  // --- Cmd+S save handler ---
  // Depend on scalar fields only (not the whole tabMeta/editState objects
  // which are new references on every store update) to avoid re-creating
  // the callback unnecessarily.
  const tabDirty = tabMeta?.dirty;
  const editStateYaml = editState?.yaml;
  const handleSave = useCallback(async () => {
    if (!tabId || editStateYaml === undefined) return;
    try {
      const { saveDetectionFile } = await import("@/lib/tauri-bridge");
      const savedPath = await saveDetectionFile(
        editStateYaml,
        tabFileType!,
        tabFilePath ?? null,   // null triggers Save As dialog
        tabName ?? "File",     // suggested filename for Save As
      );
      if (!savedPath) return; // user cancelled Save As

      // If file was untitled (no filePath), set the new path
      if (!tabFilePath) {
        usePolicyTabsStore.getState().setFilePath(tabId, savedPath);
      }

      // Mark clean in edit store (resets cleanSnapshot)
      usePolicyEditStore.getState().markClean(tabId);

      // Clear dirty in tabs store (drives pane tab dirty dot)
      usePolicyTabsStore.getState().setDirty(tabId, false);
    } catch (err) {
      console.error("[FileEditorShell] Save failed:", err);
    }
  }, [tabId, tabFileType, tabFilePath, tabName, tabDirty, editStateYaml]);

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "s" && !e.shiftKey) {
        e.preventDefault();
        e.stopPropagation();
        void handleSave();
      }
    }
    window.addEventListener("keydown", handleKeyDown, { capture: true });
    return () => window.removeEventListener("keydown", handleKeyDown, { capture: true });
  }, [handleSave]);

  // Map validation errors to YamlEditor error format
  const editorErrors = editState
    ? editState.validation.errors.map((e) => ({
        line: undefined as number | undefined,
        message: e.message,
      }))
    : [];

  // Load file content via Tauri bridge when no matching tab exists
  useEffect(() => {
    if (!filePath || tabMeta) return; // Already loaded or no path
    if (isNewFile) return; // Untitled file, skip loading

    setLoadFailed(false);

    async function loadFile() {
      try {
        console.debug("[FileEditorShell] Loading file from disk:", filePath);
        const { readDetectionFileByPath } = await import(
          "@/lib/tauri-bridge"
        );
        const result = await readDetectionFileByPath(filePath);
        if (result) {
          usePolicyTabsStore.getState().openTabOrSwitch(
            result.path,
            result.fileType,
            result.content,
            filePath.split("/").pop() ?? "File",
          );
        } else {
          console.warn("[FileEditorShell] readDetectionFileByPath returned null for:", filePath);
          setLoadFailed(true);
        }
      } catch (err) {
        console.warn("[FileEditorShell] Failed to load file:", filePath, err);
        setLoadFailed(true);
      }
    }
    loadFile();
  }, [filePath, tabMeta, isNewFile]);

  // Sync activeTabId when this shell mounts or filePath changes
  useEffect(() => {
    if (tabMeta && activeTabId !== tabMeta.id) {
      usePolicyTabsStore.getState().switchTab(tabMeta.id);
    }
  }, [tabMeta, activeTabId, filePath]);

  // Native validation -- runs Rust policy engine via Tauri IPC on each change
  // Auto-versioning -- creates snapshot on explicit save (dirty -> clean transition)
  // Both hooks must be called unconditionally before early returns (React rules of hooks).
  // They are safe with empty/undefined values: useNativeValidation is a no-op outside
  // Tauri, and useAutoVersion only acts when policyId is defined and dirty transitions.
  const workbenchActivePolicy = editState?.policy ?? DEFAULT_POLICY;
  const workbenchDispatch = (action: { type: "SET_NATIVE_VALIDATION"; payload: import("@/features/policy/stores/policy-store").NativeValidationState }) => {
    if (action.type === "SET_NATIVE_VALIDATION" && tabMeta) {
      usePolicyEditStore.getState().setNativeValidation(tabMeta.id, action.payload);
    }
  };

  useNativeValidation(
    editState?.yaml ?? "",
    tabMeta?.fileType ?? "clawdstrike_policy",
    workbenchDispatch,
  );

  useAutoVersion(
    tabMeta?.documentId,
    editState?.yaml ?? "",
    workbenchActivePolicy,
    tabMeta?.dirty ?? false,
  );

  if (!tabMeta || !editState) {
    // Show a loading message while the file is being fetched from disk;
    // only show "File not found" once loading has actually failed.
    if (!loadFailed && filePath && !isNewFile) {
      return (
        <div className="flex h-full items-center justify-center text-[#6f7f9a] font-mono text-sm">
          Loading…
        </div>
      );
    }
    return (
      <div className="flex h-full items-center justify-center text-[#6f7f9a] font-mono text-sm">
        File not found
      </div>
    );
  }

  // Editor content: split (Visual + YAML) or plain YAML editor.
  // Computed as a variable so TypeScript narrowing from the null guard above applies.
  const editorContent =
    splitActive && isPolicyFileType(tabMeta.fileType) ? (
      <ResizablePanelGroup direction="horizontal" className="h-full">
        <ResizablePanel defaultSize={45} minSize={25}>
          <EditorVisualPanel />
        </ResizablePanel>
        <ResizableHandle
          className="bg-[#2d3240] hover:bg-[#d4a84b]/40 transition-colors data-[resize-handle-active]:bg-[#d4a84b]"
          withHandle
        />
        <ResizablePanel defaultSize={55} minSize={25}>
          <GuardTestYamlEditor
            value={editState.yaml}
            onChange={handleEditorChange}
            fileType={tabMeta.fileType}
            errors={editorErrors}
            showDetectionGutters={tabMeta.fileType === "clawdstrike_policy"}
            activePolicy={workbenchActivePolicy}
            filePath={tabMeta.filePath ?? undefined}
          />
        </ResizablePanel>
      </ResizablePanelGroup>
    ) : (
      <GuardTestYamlEditor
        value={editState.yaml}
        onChange={handleEditorChange}
        fileType={tabMeta.fileType}
        errors={editorErrors}
        showDetectionGutters={tabMeta.fileType === "clawdstrike_policy"}
        activePolicy={workbenchActivePolicy}
        filePath={tabMeta.filePath ?? undefined}
      />
    );

  return (
    <TestRunnerProvider>
      <div className="h-full flex flex-col">
        <FileEditorToolbar
          tabMeta={tabMeta}
          editState={editState}
          onToggleTestRunner={() => setTestRunnerOpen((v) => !v)}
          onToggleProblems={() => setShowProblems((v) => !v)}
          onToggleSplit={() => setSplitActive((v) => !v)}
          testRunnerOpen={testRunnerOpen}
          problemsOpen={showProblems}
          splitActive={splitActive}
        />
        {testRunnerOpen && isPolicyFileType(tabMeta.fileType) ? (
          <ResizablePanelGroup direction="vertical" className="flex-1 min-h-0">
            <ResizablePanel defaultSize={60} minSize={20}>
              {editorContent}
            </ResizablePanel>
            <ResizableHandle
              className="bg-[#2d3240] hover:bg-[#d4a84b]/40 transition-colors data-[resize-handle-active]:bg-[#d4a84b]"
            />
            <ResizablePanel defaultSize={40} minSize={15}>
              <TestRunnerPanel />
            </ResizablePanel>
          </ResizablePanelGroup>
        ) : (
          <div className="flex-1 min-h-0">
            {editorContent}
          </div>
        )}
      </div>
    </TestRunnerProvider>
  );
}
