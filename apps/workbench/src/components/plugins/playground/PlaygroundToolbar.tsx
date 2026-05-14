import { Play, Trash2, AlertCircle } from "lucide-react";
import { usePlaygroundStore, clearConsole } from "@/lib/plugins/playground/playground-store";
import { runPlaygroundPlugin } from "@/lib/plugins/playground/playground-runner";

export function PlaygroundToolbar() {
  const { isRunning, runCount, errors } = usePlaygroundStore();
  const hasErrors = errors.length > 0;

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 bg-[#1a1f2e] border-b border-[#2a3142] text-[#c8d1e0] text-sm shrink-0">
      <button
        onClick={() => void runPlaygroundPlugin()}
        disabled={isRunning}
        className="flex items-center gap-1.5 px-3 py-1 rounded text-xs font-medium transition-colors
          bg-[#2a6e3f]/80 hover:bg-[#2a6e3f] text-[#c8d1e0]
          disabled:opacity-50 disabled:cursor-not-allowed"
        title="Run plugin (transpile and load)"
      >
        {isRunning ? (
          <span className="w-3.5 h-3.5 border-2 border-[#c8d1e0]/30 border-t-[#c8d1e0] rounded-full animate-spin" />
        ) : (
          <Play className="w-3.5 h-3.5" />
        )}
        Run
      </button>

      <button
        onClick={() => clearConsole()}
        className="flex items-center gap-1.5 px-2 py-1 rounded text-xs transition-colors
          hover:bg-[#2a3142] text-[#6f7f9a] hover:text-[#c8d1e0]"
        title="Clear console"
      >
        <Trash2 className="w-3.5 h-3.5" />
        Clear Console
      </button>

      <div className="flex-1" />

      {hasErrors && (
        <span className="flex items-center gap-1 text-xs text-[#c45c5c]">
          <AlertCircle className="w-3.5 h-3.5" />
          {errors.length} error{errors.length !== 1 ? "s" : ""}
        </span>
      )}

      {runCount > 0 && (
        <span className="text-xs text-[#6f7f9a] tabular-nums">
          Run #{runCount}
        </span>
      )}
    </div>
  );
}

export default PlaygroundToolbar;
