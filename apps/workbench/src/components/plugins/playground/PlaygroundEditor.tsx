import { useRef, useEffect } from "react";
import { EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter } from "@codemirror/view";
import { EditorState } from "@codemirror/state";
import { javascript } from "@codemirror/lang-javascript";
import { oneDark } from "@codemirror/theme-one-dark";
import { autocompletion } from "@codemirror/autocomplete";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { usePlaygroundSource, setSource } from "@/lib/plugins/playground/playground-store";

const fullHeightTheme = EditorView.theme({
  "&": { height: "100%" },
  ".cm-scroller": { overflow: "auto" },
});

export function PlaygroundEditor() {
  const containerRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  const initialSource = usePlaygroundSource();

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const state = EditorState.create({
      doc: initialSource,
      extensions: [
        javascript({ typescript: true }),
        oneDark,
        fullHeightTheme,
        lineNumbers(),
        highlightActiveLine(),
        highlightActiveLineGutter(),
        autocompletion(),
        history(),
        keymap.of([...defaultKeymap, ...historyKeymap]),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) {
            setSource(update.state.doc.toString());
          }
        }),
      ],
    });

    const view = new EditorView({ state, parent: container });
    viewRef.current = view;

    return () => {
      view.destroy();
      viewRef.current = null;
    };
    // Only create the editor once on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div
      ref={containerRef}
      className="h-full w-full overflow-hidden"
      data-testid="playground-editor"
    />
  );
}

export default PlaygroundEditor;
