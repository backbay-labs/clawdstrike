import { afterEach, describe, expect, it, vi } from "vitest";
import { EditorState } from "@codemirror/state";
import { EditorView } from "@codemirror/view";
import { presenceCursors, presenceFilePath } from "../presence-cursors";
import { usePresenceStore } from "@/features/presence/stores/presence-store";

vi.mock("@/features/presence/use-presence-connection", () => ({
  getPresenceSocket: vi.fn(() => null),
}));

describe("presence-cursors", () => {
  afterEach(() => {
    usePresenceStore.getState().actions.reset();
    document.body.innerHTML = "";
  });

  it("renders existing remote cursors when an editor opens", () => {
    usePresenceStore.setState({
      localAnalystId: "local",
      analysts: new Map([
        [
          "remote-1",
          {
            fingerprint: "remote-1",
            displayName: "Remote Analyst",
            sigil: "R",
            color: "#5b8def",
            activeFile: "/tmp/rules/policy.yaml",
            cursor: { line: 1, ch: 5 },
            selection: {
              anchorLine: 1,
              anchorCh: 1,
              headLine: 1,
              headCh: 8,
            },
            lastSeen: Date.now(),
          },
        ],
      ]),
    });

    const parent = document.createElement("div");
    document.body.appendChild(parent);

    const view = new EditorView({
      parent,
      state: EditorState.create({
        doc: "allow rule\n",
        extensions: [
          presenceFilePath.of("/tmp/rules/policy.yaml"),
          ...presenceCursors(),
        ],
      }),
    });

    expect(parent.querySelector(".cm-remote-caret")).not.toBeNull();
    expect(parent.querySelector(".cm-remote-caret-label")?.textContent).toBe(
      "Remote Analyst",
    );
    expect(parent.querySelector(".cm-remote-selection")).not.toBeNull();

    view.destroy();
  });
});
