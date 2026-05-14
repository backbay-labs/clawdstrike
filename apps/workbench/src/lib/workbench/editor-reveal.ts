export interface EditorRevealTarget {
  filePath: string;
  lineNumber: number;
  startColumn?: number;
  endColumn?: number;
}

const EDITOR_REVEAL_EVENT = "clawdstrike:editor-reveal";

let pendingReveal: EditorRevealTarget | null = null;

export function requestEditorReveal(target: EditorRevealTarget): void {
  pendingReveal = target;

  if (typeof window !== "undefined") {
    window.dispatchEvent(
      new CustomEvent<EditorRevealTarget>(EDITOR_REVEAL_EVENT, { detail: target }),
    );
  }
}

export function consumePendingEditorReveal(
  filePath: string | null | undefined,
): EditorRevealTarget | null {
  if (!filePath || !pendingReveal || pendingReveal.filePath !== filePath) {
    return null;
  }

  const target = pendingReveal;
  pendingReveal = null;
  return target;
}

export function listenForEditorReveal(
  listener: (target: EditorRevealTarget) => void,
): () => void {
  if (typeof window === "undefined") {
    return () => {};
  }

  const handleEvent = (event: Event) => {
    const customEvent = event as CustomEvent<EditorRevealTarget>;
    if (customEvent.detail) {
      listener(customEvent.detail);
    }
  };

  window.addEventListener(EDITOR_REVEAL_EVENT, handleEvent);
  return () => window.removeEventListener(EDITOR_REVEAL_EVENT, handleEvent);
}
