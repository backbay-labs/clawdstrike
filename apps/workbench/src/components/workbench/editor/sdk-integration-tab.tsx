import {
  useState,
  useCallback,
  useEffect,
  useRef,
  useMemo,
} from "react";
import { EditorView, keymap, lineNumbers, drawSelection, highlightActiveLine } from "@codemirror/view";
import { EditorState, Compartment, type Extension } from "@codemirror/state";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { syntaxHighlighting, HighlightStyle, foldGutter, bracketMatching } from "@codemirror/language";
import { tags } from "@lezer/highlight";
import { searchKeymap, highlightSelectionMatches } from "@codemirror/search";
import { python } from "@codemirror/lang-python";
import { javascript } from "@codemirror/lang-javascript";
import { useWorkbench, useMultiPolicy } from "@/lib/workbench/multi-policy-store";
import { useToast } from "@/components/ui/toast";
import { policyToYaml } from "@/lib/workbench/yaml-utils";
import { isDesktop, savePolicyFile } from "@/lib/tauri-bridge";
import { cn } from "@/lib/utils";
import {
  IconCopy,
  IconCheck,
  IconDownload,
  IconTrash,
  IconPlus,
  IconDeviceFloppy,
  IconPlayerPlay,
  IconChevronDown,
  IconExternalLink,
  IconX,
  IconFlask,
  IconCircleCheck,
  IconAlertTriangle,
} from "@tabler/icons-react";
import {
  sdkScriptStore,
  DEFAULT_SCRIPTS,
  type SdkFramework,
  type StoredScript,
} from "@/lib/workbench/sdk-script-store";
import {
  dryRunScript,
  type DryRunOutput,
} from "@/lib/workbench/script-dry-runner";

// ---------------------------------------------------------------------------
// Framework metadata
// ---------------------------------------------------------------------------

interface FrameworkMeta {
  label: string;
  language: "python" | "typescript";
  languageBadge: string;
  installCmd: string;
  runCmd: string;
  docsUrl: string;
}

const FRAMEWORK_META: Record<SdkFramework, FrameworkMeta> = {
  "python-sdk": {
    label: "Python SDK",
    language: "python",
    languageBadge: "PY",
    installCmd: "pip install clawdstrike",
    runCmd: "python test-policy.py",
    docsUrl: "https://docs.clawdstrike.dev/sdk/python",
  },
  claude: {
    label: "Claude",
    language: "python",
    languageBadge: "PY",
    installCmd: "pip install clawdstrike anthropic",
    runCmd: "python test-claude.py",
    docsUrl: "https://docs.clawdstrike.dev/adapters/claude",
  },
  openai: {
    label: "OpenAI",
    language: "python",
    languageBadge: "PY",
    installCmd: "pip install clawdstrike openai-agents",
    runCmd: "python test-openai.py",
    docsUrl: "https://docs.clawdstrike.dev/adapters/openai",
  },
  langchain: {
    label: "LangChain",
    language: "typescript",
    languageBadge: "TS",
    installCmd: "npm install @clawdstrike/sdk @clawdstrike/langchain @langchain/core",
    runCmd: "npx tsx test-langchain.ts",
    docsUrl: "https://docs.clawdstrike.dev/adapters/langchain",
  },
  "vercel-ai": {
    label: "Vercel AI",
    language: "typescript",
    languageBadge: "TS",
    installCmd: "npm install @clawdstrike/sdk @clawdstrike/vercel-ai ai",
    runCmd: "npx tsx test-vercel.ts",
    docsUrl: "https://docs.clawdstrike.dev/adapters/vercel-ai",
  },
  "typescript-sdk": {
    label: "TypeScript SDK",
    language: "typescript",
    languageBadge: "TS",
    installCmd: "npm install @clawdstrike/sdk",
    runCmd: "npx tsx test-sdk.ts",
    docsUrl: "https://docs.clawdstrike.dev/sdk/typescript",
  },
};

const FRAMEWORK_ORDER: SdkFramework[] = [
  "python-sdk",
  "claude",
  "openai",
  "langchain",
  "vercel-ai",
  "typescript-sdk",
];

// ---------------------------------------------------------------------------
// CodeMirror theme (matches ClawdStrike dark theme from yaml-editor.tsx)
// ---------------------------------------------------------------------------

const clawdCodeTheme = EditorView.theme(
  {
    "&": {
      backgroundColor: "#0b0d13",
      color: "#ece7dc",
      fontSize: "12px",
      fontFamily:
        "'JetBrains Mono', ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace",
      height: "100%",
    },
    "&.cm-focused": {
      outline: "none",
    },
    ".cm-scroller": {
      overflow: "auto",
      lineHeight: "1.6",
    },
    ".cm-content": {
      caretColor: "#d4a84b",
      padding: "8px 0",
    },
    ".cm-cursor, .cm-dropCursor": {
      borderLeftColor: "#d4a84b",
      borderLeftWidth: "2px",
    },
    ".cm-selectionBackground": {
      backgroundColor: "#2d324060 !important",
    },
    "&.cm-focused .cm-selectionBackground": {
      backgroundColor: "#2d324080 !important",
    },
    ".cm-activeLine": {
      backgroundColor: "#131721",
    },
    ".cm-activeLineGutter": {
      backgroundColor: "#131721",
    },
    ".cm-gutters": {
      backgroundColor: "#0b0d13",
      color: "#6f7f9a",
      border: "none",
      borderRight: "1px solid #2d3240",
    },
    ".cm-lineNumbers .cm-gutterElement": {
      padding: "0 8px 0 16px",
      minWidth: "40px",
      fontSize: "11px",
    },
    ".cm-foldGutter .cm-gutterElement": {
      padding: "0 4px",
      cursor: "pointer",
      color: "#6f7f9a",
      fontSize: "11px",
    },
    ".cm-foldGutter .cm-gutterElement:hover": {
      color: "#d4a84b",
    },
    ".cm-panels": {
      backgroundColor: "#131721",
      color: "#ece7dc",
      borderBottom: "1px solid #2d3240",
    },
    ".cm-searchMatch": {
      backgroundColor: "#d4a84b30",
      outline: "1px solid #d4a84b50",
    },
    ".cm-searchMatch.cm-searchMatch-selected": {
      backgroundColor: "#d4a84b50",
    },
    ".cm-panel input": {
      backgroundColor: "#0b0d13",
      color: "#ece7dc",
      border: "1px solid #2d3240",
      borderRadius: "3px",
      padding: "2px 6px",
      fontSize: "12px",
      outline: "none",
    },
    ".cm-panel input:focus": {
      borderColor: "#d4a84b",
    },
    ".cm-panel button": {
      backgroundColor: "#2d3240",
      color: "#ece7dc",
      border: "none",
      borderRadius: "3px",
      padding: "2px 8px",
      cursor: "pointer",
      fontSize: "11px",
    },
    ".cm-panel button:hover": {
      backgroundColor: "#3d4250",
    },
    ".cm-panel label": {
      fontSize: "11px",
      color: "#6f7f9a",
    },
    ".cm-matchingBracket": {
      backgroundColor: "#d4a84b20",
      outline: "1px solid #d4a84b40",
      color: "#d4a84b",
    },
    ".cm-scroller::-webkit-scrollbar": {
      width: "8px",
      height: "8px",
    },
    ".cm-scroller::-webkit-scrollbar-track": {
      backgroundColor: "#0b0d13",
    },
    ".cm-scroller::-webkit-scrollbar-thumb": {
      backgroundColor: "#2d3240",
      borderRadius: "4px",
      border: "2px solid #0b0d13",
    },
    ".cm-scroller::-webkit-scrollbar-thumb:hover": {
      backgroundColor: "#3d4250",
    },
    ".cm-scroller::-webkit-scrollbar-corner": {
      backgroundColor: "#0b0d13",
    },
  },
  { dark: true },
);

const clawdCodeHighlightStyle = HighlightStyle.define([
  { tag: tags.keyword, color: "#d4a84b" },
  { tag: tags.definition(tags.propertyName), color: "#d4a84b" },
  { tag: tags.propertyName, color: "#d4a84b" },
  { tag: tags.string, color: "#3dbf84" },
  { tag: tags.number, color: "#6f7f9a" },
  { tag: tags.integer, color: "#6f7f9a" },
  { tag: tags.float, color: "#6f7f9a" },
  { tag: tags.bool, color: "#d4a84b", fontStyle: "italic" },
  { tag: tags.null, color: "#6f7f9a", fontStyle: "italic" },
  { tag: tags.comment, color: "#6f7f9a80", fontStyle: "italic" },
  { tag: tags.lineComment, color: "#6f7f9a80", fontStyle: "italic" },
  { tag: tags.blockComment, color: "#6f7f9a80", fontStyle: "italic" },
  { tag: tags.operator, color: "#6f7f9a" },
  { tag: tags.punctuation, color: "#6f7f9a" },
  { tag: tags.atom, color: "#d4a84b", fontStyle: "italic" },
  { tag: tags.meta, color: "#6f7f9a" },
  { tag: tags.variableName, color: "#ece7dc" },
  { tag: tags.function(tags.variableName), color: "#d4a84b" },
  { tag: tags.typeName, color: "#d4a84b" },
  { tag: tags.className, color: "#d4a84b" },
]);

// ---------------------------------------------------------------------------
// useCodeEditor hook
// ---------------------------------------------------------------------------

function useCodeEditor(
  containerRef: React.RefObject<HTMLDivElement | null>,
  value: string,
  onChange: (value: string) => void,
  language: "python" | "typescript",
): EditorView | null {
  const viewRef = useRef<EditorView | null>(null);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  // Compartment for language extension — allows reconfiguring without destroying the view
  const languageCompartmentRef = useRef<Compartment>(new Compartment());

  // Create the editor once (runs only on mount)
  useEffect(() => {
    if (!containerRef.current) return;

    const languageCompartment = languageCompartmentRef.current;
    const initialLangExt = language === "python" ? python() : javascript({ typescript: true });

    const state = EditorState.create({
      doc: value,
      extensions: [
        clawdCodeTheme,
        syntaxHighlighting(clawdCodeHighlightStyle),
        syntaxHighlighting(HighlightStyle.define([])), // fallback
        highlightActiveLine(),
        drawSelection(),
        bracketMatching(),
        languageCompartment.of(initialLangExt),
        highlightSelectionMatches(),
        lineNumbers(),
        foldGutter({
          openText: "\u25BE",
          closedText: "\u25B8",
        }),
        history(),
        keymap.of([
          ...defaultKeymap,
          ...historyKeymap,
          ...searchKeymap,
        ]),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) {
            onChangeRef.current(update.state.doc.toString());
          }
        }),
      ],
    });

    const view = new EditorView({
      state,
      parent: containerRef.current,
    });

    viewRef.current = view;

    return () => {
      view.destroy();
      viewRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Reconfigure language extension in-place when language changes (preserves undo history + cursor)
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;

    const newLangExt = language === "python" ? python() : javascript({ typescript: true });
    view.dispatch({
      effects: languageCompartmentRef.current.reconfigure(newLangExt),
    });
  }, [language]);

  // Sync external value changes without losing cursor position
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;

    const currentDoc = view.state.doc.toString();
    if (currentDoc !== value) {
      view.dispatch({
        changes: {
          from: 0,
          to: currentDoc.length,
          insert: value,
        },
        selection: view.hasFocus ? undefined : { anchor: 0 },
      });
    }
  }, [value]);

  return viewRef.current;
}

// ---------------------------------------------------------------------------
// SdkIntegrationTab
// ---------------------------------------------------------------------------

export function SdkIntegrationTab() {
  const { state } = useWorkbench();
  const { activeTab } = useMultiPolicy();
  const { toast } = useToast();

  // Framework tab state
  const [activeFramework, setActiveFramework] = useState<SdkFramework>("python-sdk");
  const meta = FRAMEWORK_META[activeFramework];

  // Script management state
  const [savedScripts, setSavedScripts] = useState<StoredScript[]>([]);
  const [activeScriptId, setActiveScriptId] = useState<string | null>(null);
  const [content, setContent] = useState(DEFAULT_SCRIPTS[activeFramework].content);
  const [scriptName, setScriptName] = useState(DEFAULT_SCRIPTS[activeFramework].name);
  const [storeReady, setStoreReady] = useState(false);
  const [showDropdown, setShowDropdown] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Dry run state
  const [dryRunOutput, setDryRunOutput] = useState<DryRunOutput | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [showTerminal, setShowTerminal] = useState(true);

  // Copy states
  const [copiedInstall, setCopiedInstall] = useState(false);
  const [copiedRun, setCopiedRun] = useState(false);

  // Auto-save debounce
  const autoSaveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Editor ref
  const editorContainerRef = useRef<HTMLDivElement>(null);

  // Get policy ID for script storage
  const policyId = activeTab?.id || state.activePolicy.name || "default";
  const legacyPolicyId = state.activePolicy.name || "";
  const policyStorageIds = useMemo(
    () => Array.from(new Set([policyId, legacyPolicyId].filter(Boolean))),
    [legacyPolicyId, policyId],
  );

  // ---- Initialize IndexedDB store ----
  useEffect(() => {
    let cancelled = false;
    async function initStore() {
      try {
        await sdkScriptStore.init();
        if (!cancelled) {
          setStoreReady(true);
        }
      } catch {
        // IndexedDB may not be available
      }
    }
    void initStore();
    return () => {
      cancelled = true;
    };
  }, []);

  // ---- Load scripts for current policy + framework ----
  useEffect(() => {
    if (!storeReady) return;
    let cancelled = false;
    async function loadScripts() {
      try {
        const scripts = await sdkScriptStore.getScriptsByFrameworkForPolicies(
          policyStorageIds,
          activeFramework,
        );
        if (!cancelled) {
          setSavedScripts(scripts);
        }
      } catch {
        // Ignore
      }
    }
    void loadScripts();
    return () => {
      cancelled = true;
    };
  }, [storeReady, policyStorageIds, activeFramework]);

  // ---- Reset content when framework changes ----
  useEffect(() => {
    const defaults = DEFAULT_SCRIPTS[activeFramework];
    setContent(defaults.content);
    setScriptName(defaults.name);
    setActiveScriptId(null);
  }, [activeFramework]);

  // ---- Auto-save debounce ----
  useEffect(() => {
    if (!storeReady || !activeScriptId) return;

    if (autoSaveTimerRef.current) {
      clearTimeout(autoSaveTimerRef.current);
    }

    autoSaveTimerRef.current = setTimeout(() => {
      const script: StoredScript = {
        id: activeScriptId,
        policyId,
        framework: activeFramework,
        name: scriptName,
        content,
        language: meta.language,
        createdAt: "", // Will be preserved from existing
        updatedAt: new Date().toISOString(),
      };

      // Find existing to preserve createdAt
      const existing = savedScripts.find((s) => s.id === activeScriptId);
      if (existing) {
        script.createdAt = existing.createdAt;
      } else {
        script.createdAt = script.updatedAt;
      }

      void sdkScriptStore.saveScript(script).then(() => {
        setSavedScripts((prev) => {
          const filtered = prev.filter((s) => s.id !== activeScriptId);
          return [script, ...filtered];
        });
      });
    }, 2000);

    return () => {
      if (autoSaveTimerRef.current) {
        clearTimeout(autoSaveTimerRef.current);
      }
    };
    // content changes trigger auto-save when there's an active saved script
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [content, activeScriptId, storeReady]);

  // ---- Close dropdown on outside click ----
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setShowDropdown(false);
      }
    }
    if (showDropdown) {
      document.addEventListener("mousedown", handleClick);
      return () => document.removeEventListener("mousedown", handleClick);
    }
  }, [showDropdown]);

  // ---- CodeMirror editor ----
  useCodeEditor(editorContainerRef, content, setContent, meta.language);

  // ---- Script management callbacks ----

  const handleNewScript = useCallback(() => {
    const defaults = DEFAULT_SCRIPTS[activeFramework];
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const name = `${defaults.name} (${savedScripts.length + 1})`;

    setContent(defaults.content);
    setScriptName(name);
    setActiveScriptId(id);

    if (storeReady) {
      const script: StoredScript = {
        id,
        policyId,
        framework: activeFramework,
        name,
        content: defaults.content,
        language: meta.language,
        createdAt: now,
        updatedAt: now,
      };
      void sdkScriptStore.saveScript(script).then(() => {
        setSavedScripts((prev) => [script, ...prev]);
      });
    }
  }, [activeFramework, savedScripts.length, storeReady, policyId, meta.language]);

  const handleSaveScript = useCallback(() => {
    const now = new Date().toISOString();
    const id = activeScriptId || crypto.randomUUID();

    const existing = savedScripts.find((s) => s.id === id);

    const script: StoredScript = {
      id,
      policyId,
      framework: activeFramework,
      name: scriptName,
      content,
      language: meta.language,
      createdAt: existing?.createdAt || now,
      updatedAt: now,
    };

    setActiveScriptId(id);

    if (storeReady) {
      void sdkScriptStore.saveScript(script).then(() => {
        setSavedScripts((prev) => {
          const filtered = prev.filter((s) => s.id !== id);
          return [script, ...filtered];
        });
        toast({
          type: "success",
          title: "Script saved",
          description: scriptName,
        });
      });
    }
  }, [activeScriptId, policyId, activeFramework, scriptName, content, meta.language, storeReady, savedScripts, toast]);

  const handleDeleteScript = useCallback(() => {
    if (!activeScriptId) return;

    if (storeReady) {
      void sdkScriptStore.deleteScript(activeScriptId).then(() => {
        setSavedScripts((prev) => prev.filter((s) => s.id !== activeScriptId));
        const defaults = DEFAULT_SCRIPTS[activeFramework];
        setContent(defaults.content);
        setScriptName(defaults.name);
        setActiveScriptId(null);
        toast({
          type: "success",
          title: "Script deleted",
        });
      });
    }
  }, [activeScriptId, storeReady, activeFramework, toast]);

  const handleLoadScript = useCallback(
    (script: StoredScript) => {
      setContent(script.content);
      setScriptName(script.name);
      setActiveScriptId(script.id);
      setShowDropdown(false);
    },
    [],
  );

  const handleLoadDefault = useCallback(() => {
    const defaults = DEFAULT_SCRIPTS[activeFramework];
    setContent(defaults.content);
    setScriptName(defaults.name);
    setActiveScriptId(null);
    setShowDropdown(false);
  }, [activeFramework]);

  const handleSaveToFile = useCallback(async () => {
    const ext = meta.language === "python" ? ".py" : ".ts";
    const filename = `test-${activeFramework}${ext}`;

    if (isDesktop()) {
      try {
        const path = await savePolicyFile(content, undefined, meta.language === "python" ? "yaml" : "yaml");
        if (path) {
          toast({
            type: "success",
            title: "Script exported",
            description: `Saved to ${path}`,
          });
        }
      } catch (err) {
        toast({
          type: "error",
          title: "Export failed",
          description: String(err),
        });
      }
    } else {
      // Web fallback: download as file
      const blob = new Blob([content], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      toast({
        type: "success",
        title: "Script downloaded",
        description: `${filename} — check your downloads folder`,
      });
    }
  }, [content, meta.language, activeFramework, toast]);

  // ---- Bottom bar actions ----

  const policyYaml = useMemo(
    () => policyToYaml(state.activePolicy),
    [state.activePolicy],
  );

  const copyInstallCmd = useCallback(() => {
    void navigator.clipboard.writeText(meta.installCmd);
    setCopiedInstall(true);
    setTimeout(() => setCopiedInstall(false), 2000);
  }, [meta.installCmd]);

  const copyRunCmd = useCallback(() => {
    void navigator.clipboard.writeText(meta.runCmd);
    setCopiedRun(true);
    setTimeout(() => setCopiedRun(false), 2000);
  }, [meta.runCmd]);

  const handleSavePolicyAndCopy = useCallback(async () => {
    if (isDesktop()) {
      try {
        const path = await savePolicyFile(policyYaml);
        if (path) {
          const cmd = meta.runCmd.replace(
            /my-policy\.yaml/g,
            path,
          );
          void navigator.clipboard.writeText(cmd);
          toast({
            type: "success",
            title: "Policy saved & command copied",
            description: `Policy at ${path}`,
          });
        }
      } catch (err) {
        toast({
          type: "error",
          title: "Save failed",
          description: String(err),
        });
      }
    } else {
      // Web: download policy and copy run command
      const blob = new Blob([policyYaml], { type: "text/yaml" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${state.activePolicy.name || "policy"}.yaml`;
      a.click();
      URL.revokeObjectURL(url);
      void navigator.clipboard.writeText(meta.runCmd);
      toast({
        type: "success",
        title: "Policy downloaded & command copied",
        description: "Check your downloads folder",
      });
    }
  }, [policyYaml, meta.runCmd, state.activePolicy.name, toast]);

  // ---- Script validation badge ----

  const scriptValid = useMemo(() => {
    if (meta.language === "python") {
      return /(?:import|from)\s+clawdstrike/.test(content);
    }
    return /@clawdstrike|clawdstrike/.test(content);
  }, [content, meta.language]);

  // ---- Dry run ----

  const handleDryRun = useCallback(() => {
    setIsRunning(true);
    setShowTerminal(true);

    // Use setTimeout to allow UI to update with the loading state
    setTimeout(() => {
      try {
        const output = dryRunScript(content, state.activePolicy, meta.language);
        setDryRunOutput(output);

        if (output.total === 0) {
          toast({
            type: "warning",
            title: "No scenarios found",
            description: "Could not extract test scenarios from the script",
          });
        } else if (output.failed > 0) {
          toast({
            type: "error",
            title: `Dry run: ${output.failed} failed`,
            description: `${output.passed}/${output.total} passed, ${output.failed} failed`,
          });
        } else {
          toast({
            type: "success",
            title: `Dry run: ${output.passed}/${output.total} passed`,
            description: `All checked scenarios matched expectations (${output.durationMs}ms)`,
          });
        }
      } catch (err) {
        toast({
          type: "error",
          title: "Dry run failed",
          description: String(err),
        });
      } finally {
        setIsRunning(false);
      }
    }, 16);
  }, [content, state.activePolicy, meta.language, toast]);

  // ---- Render ----

  return (
    <div className="h-full flex flex-col bg-[#05060a]">
      {/* Framework tab bar */}
      <div className="flex items-center border-b border-[#2d3240] bg-[#0b0d13] shrink-0 overflow-x-auto">
        {FRAMEWORK_ORDER.map((fw) => {
          const fwMeta = FRAMEWORK_META[fw];
          return (
            <button
              key={fw}
              onClick={() => setActiveFramework(fw)}
              className={cn(
                "flex items-center gap-1 px-2.5 py-2 text-[10px] font-mono transition-colors border-b-2 -mb-px shrink-0 whitespace-nowrap",
                activeFramework === fw
                  ? "text-[#d4a84b] border-[#d4a84b]"
                  : "text-[#6f7f9a] border-transparent hover:text-[#ece7dc] hover:border-[#2d3240]",
              )}
            >
              <span
                className={cn(
                  "inline-flex items-center justify-center w-4 h-3.5 rounded text-[7px] font-bold leading-none",
                  activeFramework === fw
                    ? "bg-[#d4a84b]/20 text-[#d4a84b]"
                    : "bg-[#2d3240] text-[#6f7f9a]",
                )}
              >
                {fwMeta.languageBadge}
              </span>
              {fwMeta.label}
            </button>
          );
        })}
      </div>

      {/* Script management bar */}
      <div className="flex items-center gap-1.5 px-3 py-1.5 border-b border-[#2d3240] bg-[#0b0d13] shrink-0">
        {/* Script selector dropdown */}
        <div className="relative" ref={dropdownRef}>
          <button
            onClick={() => setShowDropdown(!showDropdown)}
            className="inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono text-[#ece7dc] bg-[#131721] border border-[#2d3240] rounded transition-colors hover:border-[#d4a84b]/40 max-w-[200px]"
          >
            <span className="truncate">
              {activeScriptId
                ? scriptName
                : `Default: ${DEFAULT_SCRIPTS[activeFramework].name}`}
            </span>
            <IconChevronDown size={10} stroke={1.5} className="shrink-0 text-[#6f7f9a]" />
          </button>

          {showDropdown && (
            <div className="absolute top-full left-0 mt-1 w-64 bg-[#131721] border border-[#2d3240] rounded shadow-lg z-50 overflow-hidden">
              {/* Default template */}
              <button
                onClick={handleLoadDefault}
                className={cn(
                  "w-full text-left px-3 py-1.5 text-[9px] font-mono transition-colors hover:bg-[#2d3240]/50",
                  !activeScriptId
                    ? "text-[#d4a84b] bg-[#d4a84b]/5"
                    : "text-[#ece7dc]",
                )}
              >
                <div className="truncate">{DEFAULT_SCRIPTS[activeFramework].name}</div>
                <div className="text-[8px] text-[#6f7f9a]/60">Default template</div>
              </button>

              {/* Saved scripts */}
              {savedScripts.length > 0 && (
                <div className="border-t border-[#2d3240]">
                  <div className="px-3 py-1 text-[8px] font-mono text-[#6f7f9a]/50 uppercase tracking-wider">
                    Saved Scripts
                  </div>
                  {savedScripts.map((script) => (
                    <button
                      key={script.id}
                      onClick={() => handleLoadScript(script)}
                      className={cn(
                        "w-full text-left px-3 py-1.5 text-[9px] font-mono transition-colors hover:bg-[#2d3240]/50",
                        activeScriptId === script.id
                          ? "text-[#d4a84b] bg-[#d4a84b]/5"
                          : "text-[#ece7dc]",
                      )}
                    >
                      <div className="truncate">{script.name}</div>
                      <div className="text-[8px] text-[#6f7f9a]/60">
                        {new Date(script.updatedAt).toLocaleString()}
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="flex-1" />

        {/* Script validation badge */}
        {scriptValid ? (
          <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[8px] font-mono text-[#3dbf84] bg-[#3dbf84]/10 border border-[#3dbf84]/20 rounded" title="SDK import detected">
            <IconCircleCheck size={9} stroke={1.5} />
            SDK
          </span>
        ) : (
          <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[8px] font-mono text-[#d4a84b] bg-[#d4a84b]/10 border border-[#d4a84b]/20 rounded" title="No clawdstrike import detected">
            <IconAlertTriangle size={9} stroke={1.5} />
            No SDK
          </span>
        )}

        {/* Script name edit (only shown for saved scripts) */}
        {activeScriptId && (
          <input
            type="text"
            value={scriptName}
            onChange={(e) => setScriptName(e.target.value)}
            className="bg-[#131721] text-[#ece7dc] border border-[#2d3240] rounded px-2 py-0.5 text-[9px] font-mono w-40 focus:border-[#d4a84b] outline-none transition-colors"
            placeholder="Script name"
          />
        )}

        {/* Action buttons */}
        <button
          onClick={handleNewScript}
          className="inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono text-[#6f7f9a] hover:text-[#d4a84b] border border-[#2d3240] rounded transition-colors"
          title="New script from template"
        >
          <IconPlus size={10} stroke={1.5} />
          New
        </button>
        <button
          onClick={handleSaveScript}
          className="inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono text-[#6f7f9a] hover:text-[#3dbf84] border border-[#2d3240] rounded transition-colors"
          title="Save script to browser storage"
        >
          <IconDeviceFloppy size={10} stroke={1.5} />
          Save
        </button>
        <button
          onClick={() => void handleSaveToFile()}
          className="inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono text-[#6f7f9a] hover:text-[#d4a84b] border border-[#2d3240] rounded transition-colors"
          title="Export script as file"
        >
          <IconDownload size={10} stroke={1.5} />
          File
        </button>
        {activeScriptId && (
          <button
            onClick={handleDeleteScript}
            className="inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono text-[#6f7f9a] hover:text-[#c45c5c] border border-[#2d3240] rounded transition-colors"
            title="Delete saved script"
          >
            <IconTrash size={10} stroke={1.5} />
          </button>
        )}
      </div>

      {/* Editor + terminal area */}
      <div className="flex-1 min-h-0 overflow-hidden flex flex-col">
        {/* Code editor */}
        <div className={cn("w-full overflow-hidden", dryRunOutput && showTerminal ? "h-[60%]" : "h-full")}>
          <div
            ref={editorContainerRef}
            className="h-full w-full overflow-hidden"
          />
        </div>

        {/* Dry run terminal output */}
        {dryRunOutput && showTerminal && (
          <div className="h-[40%] flex flex-col border-t border-[#2d3240] bg-[#0a0a0a] min-h-0">
            {/* Terminal header */}
            <div className="flex items-center gap-2 px-3 py-1 border-b border-[#2d3240]/50 bg-[#0b0d13] shrink-0">
              <span className="text-[9px] font-mono text-[#6f7f9a]">Dry Run Output</span>
              <div className="flex-1" />
              {dryRunOutput.failed > 0 ? (
                <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[8px] font-mono text-[#c45c5c] bg-[#c45c5c]/10 border border-[#c45c5c]/20 rounded">
                  {dryRunOutput.failed} failed
                </span>
              ) : (
                <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[8px] font-mono text-[#3dbf84] bg-[#3dbf84]/10 border border-[#3dbf84]/20 rounded">
                  {dryRunOutput.passed}/{dryRunOutput.total} passed
                </span>
              )}
              <button
                onClick={() => setShowTerminal(false)}
                className="text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
                title="Close terminal"
              >
                <IconX size={10} stroke={1.5} />
              </button>
            </div>
            {/* Terminal body */}
            <div role="log" aria-live="polite" aria-label="Dry-run output" className="flex-1 min-h-0 overflow-auto p-3 font-mono text-[10px] leading-[1.6]">
              {dryRunOutput.terminalOutput.split("\n").map((line, i) => {
                let lineColor = "text-[#6f7f9a]";
                if (line.includes("\u2713")) lineColor = "text-[#3dbf84]";
                else if (line.includes("\u2717")) lineColor = "text-[#c45c5c]";
                else if (line.includes("?") && line.startsWith("  ")) lineColor = "text-[#6f7f9a]/70";
                else if (line.startsWith("Policy:") || line.startsWith("Engine:") || line.startsWith("Date:")) lineColor = "text-[#ece7dc]/60";
                else if (line.startsWith("Results:") || line.startsWith("Duration:")) lineColor = "text-[#d4a84b]";
                else if (line.startsWith("===")) lineColor = "text-[#2d3240]";
                else if (line.startsWith("ClawdStrike") || line.startsWith("Running")) lineColor = "text-[#ece7dc]";

                return (
                  <div key={i} className={lineColor}>
                    {line || "\u00A0"}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Bottom bar: install + run commands */}
      <div className="shrink-0 border-t border-[#2d3240] bg-[#0b0d13]">
        {/* Install command */}
        <div className="flex items-center gap-2 px-3 py-1.5 border-b border-[#2d3240]/50">
          <span className="text-[8px] font-mono text-[#6f7f9a]/60 uppercase tracking-wider shrink-0">
            Install
          </span>
          <code className="flex-1 text-[10px] font-mono text-[#3dbf84] truncate">
            $ {meta.installCmd}
          </code>
          <button
            onClick={copyInstallCmd}
            className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[8px] font-mono text-[#6f7f9a] hover:text-[#d4a84b] transition-colors shrink-0"
            title="Copy install command"
          >
            {copiedInstall ? (
              <IconCheck size={9} stroke={1.5} className="text-[#3dbf84]" />
            ) : (
              <IconCopy size={9} stroke={1.5} />
            )}
          </button>
        </div>

        {/* Run command + actions */}
        <div className="flex items-center gap-2 px-3 py-1.5">
          <span className="text-[8px] font-mono text-[#6f7f9a]/60 uppercase tracking-wider shrink-0">
            Run
          </span>
          <code className="flex-1 text-[10px] font-mono text-[#d4a84b] truncate">
            $ {meta.runCmd}
          </code>

          <button
            onClick={copyRunCmd}
            className="inline-flex items-center gap-1 px-2 py-0.5 text-[8px] font-mono text-[#6f7f9a] hover:text-[#d4a84b] border border-[#2d3240] rounded transition-colors shrink-0"
            title="Copy run command"
          >
            {copiedRun ? (
              <>
                <IconCheck size={9} stroke={1.5} className="text-[#3dbf84]" />
                <span className="text-[#3dbf84]">Copied</span>
              </>
            ) : (
              <>
                <IconCopy size={9} stroke={1.5} />
                Copy
              </>
            )}
          </button>

          <button
            onClick={() => void handleSavePolicyAndCopy()}
            className="inline-flex items-center gap-1 px-2 py-0.5 text-[8px] font-mono text-[#6f7f9a] hover:text-[#3dbf84] border border-[#2d3240] rounded transition-colors shrink-0"
            title="Save current policy to file and copy run command"
          >
            <IconDeviceFloppy size={9} stroke={1.5} />
            Save Policy & Copy
          </button>

          <button
            onClick={handleDryRun}
            disabled={isRunning}
            className={cn(
              "inline-flex items-center gap-1 px-2 py-0.5 text-[8px] font-mono border rounded transition-colors shrink-0",
              isRunning
                ? "text-[#d4a84b]/50 border-[#2d3240]/40 cursor-wait"
                : "text-[#d4a84b] border-[#d4a84b]/30 hover:bg-[#d4a84b]/10 hover:border-[#d4a84b]/50",
            )}
            title="Simulate script scenarios against current policy"
          >
            <IconFlask size={9} stroke={1.5} />
            {isRunning ? "Running..." : "Dry Run"}
          </button>

          {isDesktop() && (
            <button
              disabled
              className="inline-flex items-center gap-1 px-2 py-0.5 text-[8px] font-mono text-[#6f7f9a]/30 border border-[#2d3240]/40 rounded cursor-not-allowed shrink-0"
              title="Requires local runtime"
            >
              <IconPlayerPlay size={9} stroke={1.5} />
              Run Script
            </button>
          )}

          <a
            href={meta.docsUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[8px] font-mono text-[#6f7f9a] hover:text-[#d4a84b] transition-colors shrink-0"
            title="Open documentation"
          >
            <IconExternalLink size={9} stroke={1.5} />
            Docs
          </a>
        </div>
      </div>
    </div>
  );
}
