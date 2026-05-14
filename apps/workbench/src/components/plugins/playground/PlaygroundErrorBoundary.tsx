import { useState } from "react";
import { X, ChevronLeft, ChevronRight, AlertCircle } from "lucide-react";
import {
  usePlaygroundErrors,
  usePlaygroundSource,
  clearErrors,
} from "@/lib/plugins/playground/playground-store";
import {
  mapStackTrace,
  extractErrorLocation,
} from "@/lib/plugins/playground/playground-source-map";

export function PlaygroundErrorBoundary() {
  const errors = usePlaygroundErrors();
  const source = usePlaygroundSource();
  const [currentIndex, setCurrentIndex] = useState(0);

  if (errors.length === 0) return null;

  const safeIndex = Math.min(currentIndex, errors.length - 1);
  const error = errors[safeIndex];
  const sourceLines = source.split("\n");

  const mappedStack = error.stack
    ? mapStackTrace(error.stack, sourceLines)
    : null;

  const location = error.stack
    ? extractErrorLocation(error.stack)
    : error.line != null
      ? { line: error.line, column: error.column ?? 0 }
      : null;

  return (
    <div className="absolute inset-x-0 top-0 z-10 mx-2 mt-2">
      <div className="bg-[#1a0000]/95 border border-[#f87171]/30 rounded-lg p-4 shadow-lg">
        <div className="flex items-start justify-between gap-2 mb-2">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-[#f87171] shrink-0" />
            <span className="text-[#f87171] font-medium text-sm">
              Runtime Error
            </span>
          </div>

          <button
            onClick={() => {
              clearErrors();
              setCurrentIndex(0);
            }}
            className="text-[#6f7f9a] hover:text-[#c8d1e0] transition-colors p-0.5 rounded hover:bg-[#2a3142]"
            title="Dismiss"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-[#f87171] font-medium text-sm mb-2">
          {error.message}
        </p>

        {location && (
          <p className="text-[#fbbf24] text-xs mb-2">
            Error at line {location.line}, column {location.column}
          </p>
        )}

        {mappedStack && (
          <pre className="text-[#c8d1e0]/70 text-xs font-mono whitespace-pre-wrap overflow-x-auto max-h-40 overflow-y-auto bg-[#0d1117]/50 rounded p-2 mt-2">
            <code>{mappedStack}</code>
          </pre>
        )}

        {errors.length > 1 && (
          <div className="flex items-center justify-center gap-3 mt-3 pt-2 border-t border-[#f87171]/10">
            <button
              onClick={() =>
                setCurrentIndex(
                  safeIndex > 0 ? safeIndex - 1 : errors.length - 1,
                )
              }
              className="text-[#6f7f9a] hover:text-[#c8d1e0] transition-colors"
              title="Previous error"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-xs text-[#6f7f9a] tabular-nums">
              {safeIndex + 1} of {errors.length} errors
            </span>
            <button
              onClick={() =>
                setCurrentIndex(
                  safeIndex < errors.length - 1 ? safeIndex + 1 : 0,
                )
              }
              className="text-[#6f7f9a] hover:text-[#c8d1e0] transition-colors"
              title="Next error"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default PlaygroundErrorBoundary;
