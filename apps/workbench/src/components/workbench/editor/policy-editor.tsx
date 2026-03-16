import { useState, useCallback, useRef, useEffect, useMemo } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { PolicyTabBar } from "@/components/workbench/editor/policy-tab-bar";
import { CommandPalette } from "@/components/workbench/editor/command-palette";
import { ProblemsPanel, type ProblemEntry } from "@/components/workbench/editor/problems-panel";
import { SplitEditor, SplitModeToggle } from "@/components/workbench/editor/split-editor";
import { EditorHomeTab } from "@/components/workbench/editor/editor-home-tab";
import { PolicyCommandCenter } from "@/components/workbench/editor/policy-command-center";
import { VersionHistoryPanel } from "@/components/workbench/editor/version-history-panel";
import { VersionDiffDialog } from "@/components/workbench/editor/version-diff-dialog";
import { TestRunnerPanel } from "@/components/workbench/editor/test-runner-panel";
import { EvidencePackPanel } from "@/components/workbench/editor/evidence-pack-panel";
import { ExplainabilityPanel } from "@/components/workbench/editor/explainability-panel";
import { PublishPanel } from "@/components/workbench/editor/publish-panel";
import { ExplorerPanel } from "@/components/workbench/explorer/explorer-panel";
import { MitreHeatmap } from "@/components/workbench/coverage/mitre-heatmap";
import { GuardsPage } from "@/components/workbench/guards/guards-page";
import { CompareLayout } from "@/components/workbench/compare/compare-layout";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { useMultiPolicy } from "@/lib/workbench/multi-policy-store";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { buildFileTree, useProject } from "@/lib/workbench/project-store";
import { useVersionHistory } from "@/lib/workbench/use-version-history";
import { useAutoVersion } from "@/lib/workbench/use-auto-version";
import type { PolicyVersion } from "@/lib/workbench/version-store";
import { getPrimaryExtension, isPolicyFileType, sanitizeFilenameStem, basenameFromPath } from "@/lib/workbench/file-type-registry";
import { isDesktop } from "@/lib/tauri-bridge";
import { policyToYaml } from "@/lib/workbench/yaml-utils";
import { triggerNativeValidation } from "@/lib/workbench/use-native-validation";
import {
  IconWand,
  IconHistory,
  IconTestPipe,
  IconPlayerPlay,
  IconChevronDown,
  IconFileCode,
  IconShieldCheck,
  IconTerminal2,
  IconWorld,
  IconShield,
  IconColumns,
  IconFolderOpen,
  IconAlertCircle,
  IconTarget,
  IconSearch,
  IconPackage,
  IconBulb,
  IconFileExport,
  IconTopologyStar3,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { ClaudeCodeHint } from "@/components/workbench/shared/claude-code-hint";
import { TestRunnerProvider, useTestRunnerOptional } from "@/lib/workbench/test-store";
import { simulatePolicy } from "@/lib/workbench/simulation-engine";
import { useLabExecution } from "@/lib/workbench/detection-workflow/use-lab-execution";
import { useSwarmLaunch } from "@/lib/workbench/detection-workflow/use-swarm-launch";
import { useDraftDetection } from "@/lib/workbench/detection-workflow/use-draft-detection";
import { useEvidencePacks } from "@/lib/workbench/detection-workflow/use-evidence-packs";
import { useCoverageGaps } from "@/lib/workbench/detection-workflow/use-coverage-gaps";
import { buildOpenDocumentCoverage } from "@/lib/workbench/detection-workflow/coverage-projection";
import { usePublishedCoverage } from "@/lib/workbench/detection-workflow/use-published-coverage";
import { usePublication } from "@/lib/workbench/detection-workflow/use-publication";
import type { CoverageGapCandidate } from "@/lib/workbench/detection-workflow/shared-types";
import type { TestActionType, Verdict } from "@/lib/workbench/types";
import type { AgentEvent } from "@/lib/workbench/hunt-types";


interface QuickTest {
  label: string;
  icon: typeof IconShieldCheck;
  action: TestActionType;
  target: string;
}

const QUICK_TESTS: QuickTest[] = [
  { label: "Quick Test: File Access", icon: IconShieldCheck, action: "file_access", target: "~/.ssh/id_rsa" },
  { label: "Quick Test: Shell Command", icon: IconTerminal2, action: "shell_command", target: "rm -rf /" },
  { label: "Quick Test: Network Egress", icon: IconWorld, action: "network_egress", target: "evil-exfil.com" },
];

function tabLabelForDiagnostics(name: string, extension: string): string {
  const stem = sanitizeFilenameStem(name, "untitled");
  return `${stem}${extension}`;
}

function RunButtonGroup({
  testRunnerOpen,
  setTestRunnerOpen,
}: {
  testRunnerOpen: boolean;
  setTestRunnerOpen: React.Dispatch<React.SetStateAction<boolean>>;
}) {
  const { state } = useWorkbench();
  const testRunner = useTestRunnerOptional();
  const [runMenuOpen, setRunMenuOpen] = useState(false);
  const [quickResult, setQuickResult] = useState<{
    label: string;
    verdict: Verdict;
  } | null>(null);
  const runMenuRef = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click or Escape; arrow key navigation
  useEffect(() => {
    if (!runMenuOpen) return;
    function handleClickOutside(e: MouseEvent) {
      if (runMenuRef.current && !runMenuRef.current.contains(e.target as Node)) {
        setRunMenuOpen(false);
      }
    }
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setRunMenuOpen(false);
        return;
      }
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const menu = runMenuRef.current?.querySelector('[role="menu"]');
        if (!menu) return;
        const items = Array.from(menu.querySelectorAll('[role="menuitem"]')) as HTMLElement[];
        if (items.length === 0) return;
        const currentIndex = items.findIndex((item) => item === document.activeElement);
        let nextIndex: number;
        if (e.key === "ArrowDown") {
          nextIndex = currentIndex < items.length - 1 ? currentIndex + 1 : 0;
        } else {
          nextIndex = currentIndex > 0 ? currentIndex - 1 : items.length - 1;
        }
        items[nextIndex].focus();
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [runMenuOpen]);

  // Clear quick result after 3 seconds
  useEffect(() => {
    if (!quickResult) return;
    const timer = setTimeout(() => setQuickResult(null), 3000);
    return () => clearTimeout(timer);
  }, [quickResult]);

  const handleRunSuite = useCallback(() => {
    // Open test runner panel (suite tab) if not already open
    if (!testRunnerOpen) {
      setTestRunnerOpen(true);
    }
  }, [testRunnerOpen, setTestRunnerOpen]);

  const handleQuickTest = useCallback(
    (qt: QuickTest) => {
      setRunMenuOpen(false);

      // Open test runner if not open
      if (!testRunnerOpen) {
        setTestRunnerOpen(true);
      }

      // Run quick simulation inline — build payload based on action type
      const payload: Record<string, string> = {};
      switch (qt.action) {
        case "file_access":
        case "file_write":
          payload.path = qt.target;
          break;
        case "shell_command":
          payload.command = qt.target;
          break;
        case "network_egress":
          payload.host = qt.target;
          break;
        case "mcp_tool_call":
          payload.tool = qt.target;
          break;
        default:
          payload.path = qt.target;
          payload.command = qt.target;
          payload.host = qt.target;
          payload.tool = qt.target;
          payload.text = qt.target;
          break;
      }
      const sim = simulatePolicy(state.activePolicy, {
        id: crypto.randomUUID(),
        name: qt.label,
        description: "",
        category: "benign",
        actionType: qt.action,
        payload,
      });

      // Show flash result
      setQuickResult({ label: qt.label, verdict: sim.overallVerdict });

      // Push results to test store if available
      if (testRunner) {
        const resultMap = new Map<string, import("@/lib/workbench/test-store").TestResult>();
        resultMap.set(qt.label, {
          scenarioName: qt.label,
          verdict: sim.overallVerdict,
          guard: sim.guardResults.find((g) => g.verdict === "deny")?.guardName ?? null,
          passed: null,
          durationMs: 0,
          guardResults: sim.guardResults.map((gr) => ({
            guard: gr.guardName,
            verdict: gr.verdict,
            message: gr.message,
          })),
        });
        testRunner.dispatch({ type: "SET_RESULTS", results: resultMap });
      }
    },
    [state.activePolicy, testRunnerOpen, setTestRunnerOpen, testRunner],
  );

  const isRunning = testRunner?.state.isRunning ?? false;

  return (
    <div className="relative" ref={runMenuRef}>
      <div className="flex items-center">
        {/* Primary run button */}
        <button
          type="button"
          onClick={handleRunSuite}
          disabled={isRunning}
          className={cn(
            "inline-flex items-center justify-center gap-1 px-2.5 h-6 text-[9px] font-mono font-semibold rounded-l transition-colors",
            isRunning
              ? "bg-[#d4a84b]/50 text-[#0b0d13]/60 cursor-wait"
              : "bg-[#d4a84b] text-[#0b0d13] hover:bg-[#e0b85c]",
          )}
          title="Run test suite"
        >
          <IconPlayerPlay size={10} stroke={1.5} />
          <span>Run</span>
        </button>
        {/* Dropdown caret */}
        <button
          type="button"
          onClick={() => setRunMenuOpen((prev) => !prev)}
          className={cn(
            "inline-flex items-center justify-center w-6 h-6 text-[9px] rounded-r border-l border-[#0b0d13]/20 transition-colors",
            isRunning
              ? "bg-[#d4a84b]/50 text-[#0b0d13]/60 cursor-wait"
              : "bg-[#d4a84b] text-[#0b0d13] hover:bg-[#e0b85c]",
          )}
          aria-label="Run options"
        >
          <IconChevronDown size={10} stroke={2} />
        </button>
      </div>

      {/* Quick result flash */}
      {quickResult && (
        <div
          className={cn(
            "absolute top-full left-0 mt-1 px-2 py-1 text-[9px] font-mono rounded shadow-lg z-50 whitespace-nowrap",
            quickResult.verdict === "allow" && "bg-[#3dbf84]/20 text-[#3dbf84] border border-[#3dbf84]/30",
            quickResult.verdict === "deny" && "bg-[#c45c5c]/20 text-[#c45c5c] border border-[#c45c5c]/30",
            quickResult.verdict === "warn" && "bg-[#d4a84b]/20 text-[#d4a84b] border border-[#d4a84b]/30",
          )}
        >
          {quickResult.verdict.toUpperCase()}: {quickResult.label}
        </div>
      )}

      {/* Dropdown menu */}
      {runMenuOpen && (
        <div role="menu" className="absolute top-full right-0 mt-1 w-52 bg-[#131721] border border-[#2d3240] rounded shadow-lg z-50 overflow-hidden">
          {/* Run suite / open test runner */}
          <button
            type="button"
            role="menuitem"
            className="flex items-center gap-2 w-full px-3 py-1.5 text-[9px] font-mono text-[#ece7dc] hover:bg-[#2d3240]/50 hover:text-[#d4a84b] transition-colors text-left"
            onClick={() => {
              setRunMenuOpen(false);
              handleRunSuite();
            }}
          >
            <IconFileCode size={12} stroke={1.5} />
            Run Current Suite
          </button>
          <button
            type="button"
            role="menuitem"
            className="flex items-center gap-2 w-full px-3 py-1.5 text-[9px] font-mono text-[#ece7dc] hover:bg-[#2d3240]/50 hover:text-[#d4a84b] transition-colors text-left"
            onClick={() => {
              setRunMenuOpen(false);
              setTestRunnerOpen((prev) => !prev);
            }}
          >
            <IconTestPipe size={12} stroke={1.5} />
            {testRunnerOpen ? "Close Test Runner" : "Open Test Runner"}
          </button>

          {/* Separator */}
          <div className="h-px bg-[#2d3240] my-1" />

          {/* Quick tests */}
          {QUICK_TESTS.map((qt) => {
            const Icon = qt.icon;
            return (
              <button
                key={qt.label}
                type="button"
                role="menuitem"
                className="flex items-center gap-2 w-full px-3 py-1.5 text-[9px] font-mono text-[#ece7dc] hover:bg-[#2d3240]/50 hover:text-[#d4a84b] transition-colors text-left"
                onClick={() => handleQuickTest(qt)}
              >
                <Icon size={12} stroke={1.5} />
                {qt.label}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}


export function PolicyEditor() {
  const { tabs, activeTab, multiDispatch } = useMultiPolicy();
  const { state, dispatch, openFile, openFileByPath } = useWorkbench();
  const {
    state: projectState,
    toggleDir,
    setFilter,
    setFormatFilter,
    expandAll,
    collapseAll,
    setProject,
  } = useProject();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const panelParam = searchParams.get("panel");
  const [showCommandCenter, setShowCommandCenter] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [testRunnerOpen, setTestRunnerOpen] = useState(false);
  const [diffDialogOpen, setDiffDialogOpen] = useState(false);
  const [diffFromId, setDiffFromId] = useState<string | undefined>();
  const [diffToId, setDiffToId] = useState<string | undefined>();
  const [showHome, setShowHome] = useState(false);
  const [showGuards, setShowGuards] = useState(false);
  const [showCompare, setShowCompare] = useState(false);
  const [showCoverage, setShowCoverage] = useState(false);
  const [showExplorer, setShowExplorer] = useState(false);
  const [showProblems, setShowProblems] = useState(false);
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const [explainOpen, setExplainOpen] = useState(false);
  const [publishOpen, setPublishOpen] = useState(false);
  const isPolicyTab = activeTab ? isPolicyFileType(activeTab.fileType) : true;
  const publishedCoverage = usePublishedCoverage();
  const openDocumentCoverage = useMemo(
    () => buildOpenDocumentCoverage(tabs),
    [tabs],
  );

  // Lab execution hook for explainability traces
  const labExecution = useLabExecution(activeTab?.documentId, activeTab?.fileType);
  const {
    packs: evidencePacks,
    selectedPackId,
  } = useEvidencePacks(activeTab?.documentId, activeTab?.fileType);
  const { draftFromEvents } = useDraftDetection({
    dispatch: multiDispatch,
    onNavigateToEditor: () => navigate("/editor"),
  });
  const selectedEvidencePack = useMemo(
    () =>
      evidencePacks.find((pack) => pack.id === selectedPackId) ??
      evidencePacks[0] ??
      null,
    [evidencePacks, selectedPackId],
  );
  const { latestManifest } = usePublication(activeTab?.documentId, activeTab?.fileType, {
    validationValid: state.validation.valid && state.nativeValidation.valid !== false,
    currentSource: state.yaml,
    lastLabRun: labExecution.lastRun,
  });

  // Swarm launch hook — creates detection nodes on the SwarmBoard
  const swarmLaunch = useSwarmLaunch({
    documentId: activeTab?.documentId,
    fileType: activeTab?.fileType,
    tabId: activeTab?.id,
    name: activeTab?.name,
    filePath: activeTab?.filePath,
    evidencePack: selectedEvidencePack,
    labRun: labExecution.lastRun,
    publicationManifest: latestManifest,
    onNavigate: (path) => navigate(path),
  });

  const coverageObservedEvents = useMemo<AgentEvent[]>(() => {
    if (!activeTab) return [];

    return evidencePacks.flatMap((pack) =>
      [...pack.datasets.positive, ...pack.datasets.regression].flatMap((item) => {
        if (item.kind !== "structured_event" && item.kind !== "ocsf_event") {
          return [];
        }

        const payload = item.payload as Record<string, unknown>;
        const actionType =
          typeof payload.actionType === "string"
            ? (payload.actionType as TestActionType)
            : "CommandLine" in payload || "process" in payload
              ? "shell_command"
              : "TargetFilename" in payload || "file" in payload
                ? "file_access"
                : "DestinationHostname" in payload || "dst_endpoint" in payload
                  ? "network_egress"
                  : "file_access";
        const target =
          typeof payload.target === "string"
            ? payload.target
            : typeof payload.CommandLine === "string"
              ? payload.CommandLine
              : typeof payload.TargetFilename === "string"
                ? payload.TargetFilename
                : typeof payload.DestinationHostname === "string"
                  ? payload.DestinationHostname
                  : typeof payload.message === "string"
                    ? payload.message
                    : item.sourceEventId ?? item.id;

        return [
          {
            id: item.id,
            timestamp: new Date().toISOString(),
            agentId: item.sourceEventId ?? activeTab.documentId,
            agentName: "Evidence Pack",
            sessionId: activeTab.documentId,
            actionType,
            target,
            content: JSON.stringify(payload),
            verdict: item.expected === "no_match" ? "allow" : "deny",
            guardResults: [],
            policyVersion: "detection-lab",
            flags: [],
          } satisfies AgentEvent,
        ];
      }),
    );
  }, [activeTab, evidencePacks]);

  const coverageGaps = useCoverageGaps(
    {
      events: coverageObservedEvents,
      openDocumentCoverage,
      publishedCoverage,
    },
    {
      onDraftFromGap: (gap: CoverageGapCandidate) => {
        if (coverageObservedEvents.length === 0) return;
        void draftFromEvents(coverageObservedEvents, gap);
      },
      persistenceKey: `clawdstrike_gap_dismissals_editor_${activeTab?.documentId ?? "none"}`,
    },
  );

  // Activate panels based on URL search params on mount
  useEffect(() => {
    if (panelParam === "guards") {
      setShowGuards(true);
      setShowHome(false);
      setShowCommandCenter(false);
      setShowCompare(false);
      setShowCoverage(false);
    } else if (panelParam === "compare") {
      setShowCompare(true);
      setShowHome(false);
      setShowCommandCenter(false);
      setShowGuards(false);
      setShowCoverage(false);
    } else if (panelParam === null) {
      setShowGuards(false);
      setShowCompare(false);
    }
  }, [panelParam]);

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setCommandPaletteOpen((prev) => !prev);
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  useEffect(() => {
    if (isPolicyTab) return;
    setShowCommandCenter(false);
    setShowGuards(false);
    setShowCompare(false);
    setHistoryOpen(false);
    setTestRunnerOpen(false);
  }, [isPolicyTab]);

  const explorerEntries = useMemo(() => {
    const usedPaths = new Set<string>();
    return tabs.map((tab, index) => {
      const ext = getPrimaryExtension(tab.fileType);
      const directoryPrefix = tab.fileType === "sigma_rule"
        ? "sigma"
        : tab.fileType === "clawdstrike_policy"
        ? "policies"
        : tab.fileType === "yara_rule"
        ? "yara"
        : "ocsf";
      const baseName = tab.filePath
        ? tab.filePath.replace(/\\/g, "/").split("/").pop() ?? `${index + 1}${ext}`
        : `${sanitizeFilenameStem(tab.name, `untitled_${index + 1}`)}${ext}`;
      let relativePath = `${directoryPrefix}/${baseName}`;

      while (usedPaths.has(relativePath)) {
        const stem = relativePath.replace(/\.[^.]+$/, "");
        relativePath = `${stem}_${index + 1}${ext}`;
      }

      usedPaths.add(relativePath);
      return { tab, relativePath };
    });
  }, [tabs]);

  const explorerProject = useMemo(() => {
    const defaultExpanded = new Set<string>(
      explorerEntries
        .map((entry) => {
          const slashIndex = entry.relativePath.indexOf("/");
          return slashIndex > 0 ? entry.relativePath.slice(0, slashIndex) : null;
        })
        .filter((value): value is string => Boolean(value)),
    );

    return {
      rootPath: "workspace",
      name: "Workspace",
      files: buildFileTree("workspace", explorerEntries.map((entry) => entry.relativePath)),
      expandedDirs: projectState.project?.expandedDirs ?? defaultExpanded,
    };
  }, [explorerEntries, projectState.project]);

  const explorerSyncKey = useMemo(
    () => explorerEntries.map((entry) => `${entry.tab.id}:${entry.relativePath}`).join("|"),
    [explorerEntries],
  );
  const explorerSyncRef = useRef<string>("");

  useEffect(() => {
    if (explorerSyncRef.current === explorerSyncKey) return;
    explorerSyncRef.current = explorerSyncKey;
    setProject(explorerProject);
  }, [explorerProject, explorerSyncKey, setProject]);

  const relativePathByTabId = useMemo(
    () => new Map(explorerEntries.map((entry) => [entry.tab.id, entry.relativePath])),
    [explorerEntries],
  );

  const problems = useMemo<ProblemEntry[]>(() => {
    return tabs.flatMap((tab) => {
      const file = basenameFromPath(tab.filePath)
        ?? tabLabelForDiagnostics(tab.name, getPrimaryExtension(tab.fileType));
      const clientIssues = [
        ...tab.validation.errors.map((issue) => ({
          severity: "error" as const,
          message: issue.message,
          file,
          fileType: tab.fileType,
        })),
        ...tab.validation.warnings.map((issue) => ({
          severity: "warning" as const,
          message: issue.message,
          file,
          fileType: tab.fileType,
        })),
      ];

      const nativeTopLevel = tab.nativeValidation.topLevelErrors.map((message) => ({
        severity: "error" as const,
        message,
        file,
        fileType: tab.fileType,
      }));
      const nativeTopLevelWarnings = (tab.nativeValidation.topLevelWarnings ?? []).map((message) => ({
        severity: "warning" as const,
        message,
        file,
        fileType: tab.fileType,
      }));
      const nativeGuardIssues = Object.entries(tab.nativeValidation.guardErrors).flatMap(
        ([guardId, messages]) =>
          messages.map((message) => ({
            severity: "error" as const,
            message: `${guardId}: ${message}`,
            file,
            fileType: tab.fileType,
          })),
      );

      return [...clientIssues, ...nativeTopLevel, ...nativeTopLevelWarnings, ...nativeGuardIssues];
    });
  }, [tabs]);

  const versionDocumentId = activeTab?.documentId;
  const { versions } = useVersionHistory(versionDocumentId);

  // Auto-create versions on explicit save (dirty -> clean transition)
  useAutoVersion(
    isPolicyTab ? versionDocumentId : undefined,
    state.yaml,
    state.activePolicy,
    isPolicyTab && state.dirty,
  );

  // Rollback handler: load a version's policy into the editor
  const handleRollback = useCallback(
    (version: PolicyVersion) => {
      dispatch({ type: "SET_POLICY", policy: version.policy });
    },
    [dispatch],
  );

  // Compare handler: open diff dialog
  const handleCompare = useCallback(
    (fromId: string, toId: string) => {
      setDiffFromId(fromId);
      setDiffToId(toId);
      setDiffDialogOpen(true);
    },
    [],
  );

  const handleOpenExplorerFile = useCallback(
    async (relativePath: string) => {
      const existing = explorerEntries.find((entry) => entry.relativePath === relativePath);
      if (!existing) return;

      multiDispatch({ type: "SWITCH_TAB", tabId: existing.tab.id });
      if (existing.tab.filePath) {
        await openFileByPath(existing.tab.filePath);
      }
      navigate("/editor");
    },
    [explorerEntries, multiDispatch, navigate, openFileByPath],
  );

  const handleValidateCurrentFile = useCallback(() => {
    if (!activeTab) return;
    const source = isPolicyFileType(activeTab.fileType)
      ? policyToYaml(state.activePolicy)
      : state.yaml;
    const shouldSyncYaml = isPolicyFileType(activeTab.fileType)
      && (state.dirty || source !== state.yaml);

    if (shouldSyncYaml) {
      dispatch({ type: "SET_YAML", yaml: source });
    }

    if (isDesktop()) {
      void triggerNativeValidation(activeTab.fileType, source, dispatch);
    }

    setShowProblems(true);
  }, [activeTab, state.activePolicy, state.yaml, state.dirty, dispatch]);

  return (
    <TestRunnerProvider key={activeTab?.id ?? "no-active-tab"}>
      <div className="h-full w-full flex flex-col">
        <div className="flex items-center bg-[#0b0d13] border-b border-[#2d3240]">
          <div className="flex-1 min-w-0">
            <PolicyTabBar
              isHomeActive={showHome}
              onHomeClick={() => {
                setShowHome(true);
                setShowCommandCenter(false);
                setShowGuards(false);
                setShowCompare(false);
                setShowCoverage(false);
              }}
              onTabSwitch={() => {
                setShowHome(false);
                setShowCommandCenter(false);
                setShowGuards(false);
                setShowCompare(false);
                setShowCoverage(false);
              }}
            />
          </div>
          <div className="flex items-center gap-1 px-2 shrink-0">
            {isPolicyTab && (
              <RunButtonGroup
                testRunnerOpen={testRunnerOpen}
                setTestRunnerOpen={setTestRunnerOpen}
              />
            )}
            <SplitModeToggle />
            <button
              type="button"
              onClick={() => setCommandPaletteOpen(true)}
              className="inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent hover:border-[#2d3240] rounded transition-colors"
              title="Command palette"
              aria-label="Command palette"
            >
              <IconSearch size={12} stroke={1.5} />
            </button>
            <button
              type="button"
              onClick={() => setShowExplorer((prev) => !prev)}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono rounded transition-colors",
                showExplorer
                  ? "bg-[#d4a84b]/15 text-[#d4a84b] border border-[#d4a84b]/30"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent hover:border-[#2d3240]",
              )}
              title="Explorer"
              aria-label="Explorer"
            >
              <IconFolderOpen size={12} stroke={1.5} />
            </button>
            <button
              type="button"
              onClick={() => setShowProblems((prev) => !prev)}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono rounded transition-colors",
                showProblems
                  ? "bg-[#c45c5c]/15 text-[#c45c5c] border border-[#c45c5c]/30"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent hover:border-[#2d3240]",
              )}
              title="Problems"
              aria-label="Problems"
            >
              <IconAlertCircle size={12} stroke={1.5} />
            </button>
            <button
              type="button"
              onClick={() => {
                setShowCoverage((prev) => !prev);
                setShowHome(false);
                setShowCommandCenter(false);
                setShowGuards(false);
                setShowCompare(false);
              }}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono rounded transition-colors",
                showCoverage
                  ? "bg-[#7c9aef]/15 text-[#7c9aef] border border-[#7c9aef]/30"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent hover:border-[#2d3240]",
              )}
              title="ATT&CK coverage"
              aria-label="ATT&CK coverage"
            >
              <IconTarget size={12} stroke={1.5} />
            </button>
            <button
              type="button"
              onClick={() => {
                if (!isPolicyTab) return;
                setShowCommandCenter(true);
                setShowHome(false);
                setShowGuards(false);
                setShowCompare(false);
                setShowCoverage(false);
              }}
              disabled={!isPolicyTab}
              className="inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono text-[#6f7f9a] hover:text-[#d4a84b] border border-transparent hover:border-[#2d3240] rounded transition-colors disabled:opacity-40 disabled:hover:text-[#6f7f9a] disabled:hover:border-transparent"
              title={isPolicyTab ? "Policy command center" : "Policy-only surface"}
              aria-label="Policy command center"
            >
              <IconWand size={12} stroke={1.5} />
            </button>
            <button
              type="button"
              onClick={() => {
                if (!isPolicyTab) return;
                setShowGuards((prev) => {
                  if (!prev) {
                    setShowHome(false);
                    setShowCommandCenter(false);
                    setShowCompare(false);
                    setShowCoverage(false);
                  }
                  return !prev;
                });
              }}
              disabled={!isPolicyTab}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono rounded transition-colors disabled:opacity-40 disabled:hover:text-[#6f7f9a] disabled:hover:border-transparent",
                showGuards
                  ? "bg-[#d4a84b]/15 text-[#d4a84b] border border-[#d4a84b]/30"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent hover:border-[#2d3240]",
              )}
              title="Guards"
              aria-label="Guards"
            >
              <IconShield size={12} stroke={1.5} />
            </button>
            <button
              type="button"
              onClick={() => {
                if (!isPolicyTab) return;
                setShowCompare((prev) => {
                  if (!prev) {
                    setShowHome(false);
                    setShowCommandCenter(false);
                    setShowGuards(false);
                    setShowCoverage(false);
                  }
                  return !prev;
                });
              }}
              disabled={!isPolicyTab}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono rounded transition-colors disabled:opacity-40 disabled:hover:text-[#6f7f9a] disabled:hover:border-transparent",
                showCompare
                  ? "bg-[#d4a84b]/15 text-[#d4a84b] border border-[#d4a84b]/30"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent hover:border-[#2d3240]",
              )}
              title="Compare"
              aria-label="Compare"
            >
              <IconColumns size={12} stroke={1.5} />
            </button>
            <button
              type="button"
              onClick={() => setTestRunnerOpen((prev) => !prev)}
              disabled={!isPolicyTab}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono rounded transition-colors disabled:opacity-40 disabled:hover:text-[#6f7f9a] disabled:hover:border-transparent",
                testRunnerOpen
                  ? "bg-[#d4a84b]/15 text-[#d4a84b] border border-[#d4a84b]/30"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent hover:border-[#2d3240]",
              )}
              title="Toggle test runner"
              aria-label="Toggle test runner"
            >
              <IconTestPipe size={12} stroke={1.5} />
            </button>
            <button
              type="button"
              onClick={() => setHistoryOpen((prev) => !prev)}
              disabled={!isPolicyTab}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono rounded transition-colors disabled:opacity-40 disabled:hover:text-[#6f7f9a] disabled:hover:border-transparent",
                historyOpen
                  ? "bg-[#d4a84b]/15 text-[#d4a84b] border border-[#d4a84b]/30"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent hover:border-[#2d3240]",
              )}
              title="Toggle version history"
              aria-label="Version history"
            >
              <IconHistory size={12} stroke={1.5} />
            </button>
            <button
              type="button"
              onClick={() => setEvidenceOpen((prev) => !prev)}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono rounded transition-colors",
                evidenceOpen
                  ? "bg-[#d4a84b]/15 text-[#d4a84b] border border-[#d4a84b]/30"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent hover:border-[#2d3240]",
              )}
              title="Evidence packs"
              aria-label="Evidence packs"
            >
              <IconPackage size={12} stroke={1.5} />
            </button>
            <button
              type="button"
              onClick={() => setExplainOpen((prev) => !prev)}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono rounded transition-colors",
                explainOpen
                  ? "bg-[#d4a84b]/15 text-[#d4a84b] border border-[#d4a84b]/30"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent hover:border-[#2d3240]",
              )}
              title="Explainability traces"
              aria-label="Explain"
            >
              <IconBulb size={12} stroke={1.5} />
            </button>
            <button
              type="button"
              onClick={() => setPublishOpen((prev) => !prev)}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono rounded transition-colors",
                publishOpen
                  ? "bg-[#3dbf84]/15 text-[#3dbf84] border border-[#3dbf84]/30"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent hover:border-[#2d3240]",
              )}
              title="Publish"
              aria-label="Publish"
            >
              <IconFileExport size={12} stroke={1.5} />
            </button>
            <button
              type="button"
              onClick={() => swarmLaunch.openReviewSwarm()}
              disabled={!swarmLaunch.canLaunch}
              className="inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono text-[#6f7f9a] hover:text-[#d4a84b] border border-transparent hover:border-[#2d3240] rounded transition-colors disabled:opacity-40 disabled:hover:text-[#6f7f9a] disabled:hover:border-transparent"
              title="Open Review Swarm"
              aria-label="Open Review Swarm"
            >
              <IconTopologyStar3 size={12} stroke={1.5} />
            </button>
          </div>
        </div>

        <div className="flex-1 min-h-0 flex relative">
          {showExplorer && (
            <div className="w-[280px] shrink-0 border-r border-[#2d3240]">
              <ExplorerPanel
                project={explorerProject}
                onToggleDir={toggleDir}
                onOpenFile={(file) => { void handleOpenExplorerFile(file.path); }}
                onExpandAll={expandAll}
                onCollapseAll={collapseAll}
                filter={projectState.filter}
                onFilterChange={setFilter}
                formatFilter={projectState.formatFilter}
                onFormatFilterChange={setFormatFilter}
                activeFilePath={activeTab ? relativePathByTabId.get(activeTab.id) ?? null : null}
              />
            </div>
          )}

          <div className="flex-1 min-w-0">
            {showCommandCenter ? (
              <PolicyCommandCenter onClose={() => setShowCommandCenter(false)} />
            ) : showHome ? (
              <EditorHomeTab onNavigateToTab={() => setShowHome(false)} />
            ) : showGuards ? (
              <GuardsPage onNavigateToEditor={() => setShowGuards(false)} />
            ) : showCompare ? (
              <CompareLayout />
            ) : showCoverage ? (
              <MitreHeatmap
                tabs={tabs}
                inferredGaps={coverageGaps.gaps}
                onDraftFromGap={coverageGaps.draftFromGap}
                onDismissGap={coverageGaps.dismiss}
              />
            ) : isPolicyTab && testRunnerOpen ? (
              <ResizablePanelGroup direction="vertical" className="h-full">
                <ResizablePanel defaultSize={65} minSize={30}>
                  <div className="h-full flex flex-col">
                    <div className="flex-1 min-h-0">
                      <SplitEditor />
                    </div>
                    {showProblems && (
                      <div className="h-[180px] shrink-0">
                        <ProblemsPanel diagnostics={problems} className="h-full" />
                      </div>
                    )}
                  </div>
                </ResizablePanel>
                <ResizableHandle
                  className="bg-[#2d3240] hover:bg-[#d4a84b]/40 transition-colors data-[resize-handle-active]:bg-[#d4a84b]"
                  withHandle
                />
                <ResizablePanel defaultSize={35} minSize={15}>
                  <TestRunnerPanel />
                </ResizablePanel>
              </ResizablePanelGroup>
            ) : (
              <div className="h-full flex flex-col">
                <div className="flex-1 min-h-0">
                  <SplitEditor />
                </div>
                {showProblems && (
                  <div className="h-[180px] shrink-0">
                    <ProblemsPanel diagnostics={problems} className="h-full" />
                  </div>
                )}
              </div>
            )}
          </div>

          {historyOpen && !showHome && isPolicyTab && (
            <div className="w-[280px] shrink-0">
              <VersionHistoryPanel
                policyId={versionDocumentId}
                currentYaml={state.yaml}
                currentPolicy={state.activePolicy}
                onRollback={handleRollback}
                onCompare={handleCompare}
              />
            </div>
          )}

          {evidenceOpen && !showHome && (
            <div className="w-[280px] shrink-0">
              <EvidencePackPanel
                documentId={activeTab?.documentId}
                fileType={activeTab?.fileType}
              />
            </div>
          )}

          {explainOpen && !showHome && (
            <div className="w-[280px] shrink-0">
              <ExplainabilityPanel
                documentId={activeTab?.documentId}
                lastRun={labExecution.lastRun}
                baselineRun={labExecution.runHistory.length > 1 ? labExecution.runHistory[1] : null}
                onJumpToLine={(line) => {
                  window.dispatchEvent(
                    new CustomEvent("workbench:jump-to-line", { detail: { line } }),
                  );
                }}
              />
            </div>
          )}

          {publishOpen && !showHome && (
            <div className="w-[280px] shrink-0 border-l border-[#2d3240]">
              <PublishPanel
                documentId={activeTab?.documentId}
                fileType={activeTab?.fileType}
                source={state.yaml}
                validationValid={state.validation.valid && state.nativeValidation.valid !== false}
                lastLabRun={labExecution.lastRun}
              />
            </div>
          )}

          <ClaudeCodeHint hintId="editor.validate" />
        </div>

        <CommandPalette
          open={commandPaletteOpen}
          onClose={() => setCommandPaletteOpen(false)}
          onNewTab={(fileType) => {
            multiDispatch({ type: "NEW_TAB", fileType });
            navigate("/editor");
          }}
          onNavigate={(path) => navigate(path)}
          onOpenFile={() => {
            void openFile().then(() => navigate("/editor"));
          }}
          onValidate={handleValidateCurrentFile}
          onToggleCoverage={() => setShowCoverage((prev) => !prev)}
        />

        <VersionDiffDialog
          open={diffDialogOpen}
          onOpenChange={setDiffDialogOpen}
          versions={versions}
          currentPolicy={state.activePolicy}
          currentYaml={state.yaml}
          initialFromId={diffFromId}
          initialToId={diffToId}
          onRollback={handleRollback}
        />
      </div>
    </TestRunnerProvider>
  );
}
