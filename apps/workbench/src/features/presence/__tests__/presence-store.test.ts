import { beforeEach, describe, expect, it } from "vitest";
import { usePresenceStore } from "../stores/presence-store";

describe("presence-store", () => {
  beforeEach(() => {
    usePresenceStore.getState().actions.reset();
  });

  it("clears stale cursor state when an analyst switches files", () => {
    const { handleServerMessage } = usePresenceStore.getState().actions;

    handleServerMessage({
      type: "welcome",
      analyst_id: "local",
      color: "#5b8def",
      roster: [
        {
          fingerprint: "remote-1",
          display_name: "Remote Analyst",
          sigil: "R",
          color: "#e06c75",
          active_file: "rules/policy-a.yaml",
        },
      ],
    });
    handleServerMessage({
      type: "analyst_cursor",
      fingerprint: "remote-1",
      file_path: "rules/policy-a.yaml",
      line: 7,
      ch: 3,
    });
    handleServerMessage({
      type: "analyst_selection",
      fingerprint: "remote-1",
      file_path: "rules/policy-a.yaml",
      anchor_line: 7,
      anchor_ch: 1,
      head_line: 7,
      head_ch: 9,
    });
    handleServerMessage({
      type: "analyst_viewing",
      fingerprint: "remote-1",
      file_path: "rules/policy-b.yaml",
    });

    const analyst = usePresenceStore.getState().analysts.get("remote-1");
    expect(analyst?.activeFile).toBe("rules/policy-b.yaml");
    expect(analyst?.cursor).toBeNull();
    expect(analyst?.selection).toBeNull();
  });

  it("clears cursor state when an analyst leaves a file", () => {
    const { handleServerMessage } = usePresenceStore.getState().actions;

    handleServerMessage({
      type: "welcome",
      analyst_id: "local",
      color: "#5b8def",
      roster: [
        {
          fingerprint: "remote-1",
          display_name: "Remote Analyst",
          sigil: "R",
          color: "#e06c75",
          active_file: "rules/policy-a.yaml",
        },
      ],
    });
    handleServerMessage({
      type: "analyst_cursor",
      fingerprint: "remote-1",
      file_path: "rules/policy-a.yaml",
      line: 4,
      ch: 2,
    });
    handleServerMessage({
      type: "analyst_selection",
      fingerprint: "remote-1",
      file_path: "rules/policy-a.yaml",
      anchor_line: 4,
      anchor_ch: 2,
      head_line: 4,
      head_ch: 6,
    });
    handleServerMessage({
      type: "analyst_left_file",
      fingerprint: "remote-1",
      file_path: "rules/policy-a.yaml",
    });

    const analyst = usePresenceStore.getState().analysts.get("remote-1");
    expect(analyst?.activeFile).toBeNull();
    expect(analyst?.cursor).toBeNull();
    expect(analyst?.selection).toBeNull();
  });
});
