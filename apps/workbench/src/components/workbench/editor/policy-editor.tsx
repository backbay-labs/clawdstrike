import { useState, useCallback, useRef, useEffect } from "react";
import { PolicyTabBar } from "@/components/workbench/editor/policy-tab-bar";
import { SplitEditor, SplitModeToggle } from "@/components/workbench/editor/split-editor";
import { EditorHomeTab } from "@/components/workbench/editor/editor-home-tab";
import { PolicyCommandCenter } from "@/components/workbench/editor/policy-command-center";
import { VersionHistoryPanel } from "@/components/workbench/editor/version-history-panel";
import { VersionDiffDialog } from "@/components/workbench/editor/version-diff-dialog";
import { TestRunnerPanel } from "@/components/workbench/editor/test-runner-panel";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { useMultiPolicy } from "@/lib/workbench/multi-policy-store";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { useVersionHistory } from "@/lib/workbench/use-version-history";
import { useAutoVersion } from "@/lib/workbench/use-auto-version";
import type { PolicyVersion } from "@/lib/workbench/version-store";
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
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { ClaudeCodeHint } from "@/components/workbench/shared/claude-code-hint";
import { TestRunnerProvider, useTestRunnerOptional } from "@/lib/workbench/test-store";
import { simulatePolicy } from "@/lib/workbench/simulation-engine";
import type { TestActionType, Verdict } from "@/lib/workbench/types";

// ---------------------------------------------------------------------------
// Quick test definitions for the Run dropdown
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Run Button (with dropdown) -- must live inside TestRunnerProvider
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// PolicyEditor
// ---------------------------------------------------------------------------

export function PolicyEditor() {
  const { tabs, activeTab } = useMultiPolicy();
  const { state, dispatch } = useWorkbench();
  const [showCommandCenter, setShowCommandCenter] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [testRunnerOpen, setTestRunnerOpen] = useState(false);
  const [diffDialogOpen, setDiffDialogOpen] = useState(false);
  const [diffFromId, setDiffFromId] = useState<string | undefined>();
  const [diffToId, setDiffToId] = useState<string | undefined>();
  const [showHome, setShowHome] = useState(false);

  // Use the active tab's ID as the policyId for version tracking
  const policyId = activeTab?.id;
  const { versions } = useVersionHistory(policyId);

  // Auto-create versions on explicit save (dirty -> clean transition)
  useAutoVersion(policyId, state.yaml, state.activePolicy, state.dirty);

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

  return (
    <TestRunnerProvider key={activeTab?.id ?? "no-active-tab"}>
    <div className="h-full w-full flex flex-col">
      {/* Tab bar + toolbar */}
      <div className="flex items-center bg-[#0b0d13] border-b border-[#2d3240]">
        <div className="flex-1 min-w-0">
          <PolicyTabBar
            isHomeActive={showHome}
            onHomeClick={() => { setShowHome(true); setShowCommandCenter(false); }}
            onTabSwitch={() => { setShowHome(false); setShowCommandCenter(false); }}
          />
        </div>
        <div className="flex items-center gap-1 px-2 shrink-0">
          <RunButtonGroup
            testRunnerOpen={testRunnerOpen}
            setTestRunnerOpen={setTestRunnerOpen}
          />
          <SplitModeToggle />
          <button
            type="button"
            onClick={() => { setShowCommandCenter(true); setShowHome(false); }}
            className="inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono text-[#6f7f9a] hover:text-[#d4a84b] border border-transparent hover:border-[#2d3240] rounded transition-colors"
            title="Policy command center"
            aria-label="Policy command center"
          >
            <IconWand size={12} stroke={1.5} />
          </button>
          <button
            type="button"
            onClick={() => setTestRunnerOpen((prev) => !prev)}
            className={cn(
              "inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono rounded transition-colors",
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
            className={cn(
              "inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono rounded transition-colors",
              historyOpen
                ? "bg-[#d4a84b]/15 text-[#d4a84b] border border-[#d4a84b]/30"
                : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent hover:border-[#2d3240]",
            )}
            title="Toggle version history"
            aria-label="Version history"
          >
            <IconHistory size={12} stroke={1.5} />
          </button>
        </div>
      </div>

      {/* Claude Code hint strip */}
      <ClaudeCodeHint
        hintId="editor.validate"
        className="mx-2 mt-1.5 mb-0.5"
      />

      {/* Editor content + optional test runner + version history sidebar */}
      <div className="flex-1 min-h-0 flex">
        <div className="flex-1 min-w-0">
          {showCommandCenter ? (
            <PolicyCommandCenter onClose={() => setShowCommandCenter(false)} />
          ) : showHome ? (
            <EditorHomeTab onNavigateToTab={() => setShowHome(false)} />
          ) : testRunnerOpen ? (
            <ResizablePanelGroup direction="vertical" className="h-full">
              <ResizablePanel defaultSize={65} minSize={30}>
                <SplitEditor />
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
            <SplitEditor />
          )}
        </div>

        {/* Version history panel (collapsible right sidebar) */}
        {historyOpen && !showHome && (
          <div className="w-[280px] shrink-0">
            <VersionHistoryPanel
              policyId={policyId}
              currentYaml={state.yaml}
              currentPolicy={state.activePolicy}
              onRollback={handleRollback}
              onCompare={handleCompare}
            />
          </div>
        )}
      </div>

      {/* Version diff dialog */}
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
