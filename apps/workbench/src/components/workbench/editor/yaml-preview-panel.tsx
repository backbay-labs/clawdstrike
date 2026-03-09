import { useState, useCallback, useRef, useEffect, useMemo } from "react";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { useToast } from "@/components/ui/toast";
import { YamlEditor, type YamlEditorError } from "@/components/ui/yaml-editor";
import { cn } from "@/lib/utils";

type Tab = "preview" | "edit";

export function YamlPreviewPanel() {
  const { state, dispatch } = useWorkbench();
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState<Tab>("preview");
  const [localYaml, setLocalYaml] = useState(state.yaml);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Sync local yaml when state changes from visual panel edits
  useEffect(() => {
    if (state.ui.editorSyncDirection !== "yaml") {
      setLocalYaml(state.yaml);
    }
  }, [state.yaml, state.ui.editorSyncDirection]);

  const handleYamlChange = useCallback(
    (value: string) => {
      setLocalYaml(value);

      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }
      debounceRef.current = setTimeout(() => {
        dispatch({ type: "SET_YAML", yaml: value });
      }, 500);
    },
    [dispatch]
  );

  // Cleanup debounce on unmount
  useEffect(() => {
    return () => {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }
    };
  }, []);

  const { errors, warnings } = state.validation;

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
  const nv = state.nativeValidation;
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
          Edit YAML
          {activeTab === "edit" && (
            <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#d4a84b]" />
          )}
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden">
        {activeTab === "preview" ? (
          <YamlEditor
            value={state.yaml}
            onChange={() => {}}
            readOnly
          />
        ) : (
          <YamlEditor
            value={localYaml}
            onChange={handleYamlChange}
            errors={editorErrors}
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
