import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { usePaneStore } from "@/features/panes/pane-store";
import { usePresenceStore } from "../stores/presence-store";

const send = vi.fn();

vi.mock("../use-presence-connection", () => ({
  getPresenceSocket: () => ({ send }),
}));

const {
  getTrackedPresenceFilePath,
  usePresenceFileTracking,
} = await import("../use-presence-file-tracking");

describe("getTrackedPresenceFilePath", () => {
  beforeEach(() => {
    send.mockReset();
    usePaneStore.getState()._reset();
    usePresenceStore.getState().actions.reset();
  });

  it("ignores draft file routes by prefix only", () => {
    expect(getTrackedPresenceFilePath("/file/__new__/draft-1")).toBeNull();
  });

  it("keeps real file paths that happen to contain __new__", () => {
    expect(getTrackedPresenceFilePath("/file/rules/__new__/policy.yaml")).toBe(
      "rules/__new__/policy.yaml",
    );
  });

  it("sends a single view_file when the socket reconnects", async () => {
    usePaneStore.getState().syncRoute("/file/rules/policy.yaml");
    renderHook(() => usePresenceFileTracking());

    act(() => {
      usePresenceStore.getState().actions.setConnectionState("connected");
    });

    await waitFor(() => {
      expect(send).toHaveBeenCalledWith({
        type: "view_file",
        file_path: "rules/policy.yaml",
      });
    });

    act(() => {
      usePresenceStore.getState().actions.setConnectionState("reconnecting");
    });

    act(() => {
      usePresenceStore.getState().actions.setConnectionState("connected");
    });

    await waitFor(() => {
      const viewFileMessages = send.mock.calls
        .map(([message]) => message)
        .filter((message) => message.type === "view_file");
      expect(viewFileMessages).toEqual([
        { type: "view_file", file_path: "rules/policy.yaml" },
        { type: "view_file", file_path: "rules/policy.yaml" },
      ]);
    });
  });
});
