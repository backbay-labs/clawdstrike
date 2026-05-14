/**
 * PlaygroundEditorPane - Wrapper combining toolbar, editor, and error boundary.
 *
 * Arranges PlaygroundToolbar (top) and PlaygroundEditor (fills remaining space)
 * in a flex-col layout. The PlaygroundErrorBoundary renders as an overlay
 * above the editor when errors are present, so the editor remains interactive
 * underneath when there are no errors.
 *
 * Exported as default for lazy loading from the playground plugin registration.
 */
import { PlaygroundToolbar } from "./PlaygroundToolbar";
import { PlaygroundEditor } from "./PlaygroundEditor";
import { PlaygroundErrorBoundary } from "./PlaygroundErrorBoundary";

export function PlaygroundEditorPane() {
  return (
    <div className="flex flex-col h-full w-full bg-[#0d1117]">
      <PlaygroundToolbar />
      <div className="flex-1 min-h-0 relative">
        <PlaygroundErrorBoundary />
        <PlaygroundEditor />
      </div>
    </div>
  );
}

export default PlaygroundEditorPane;
