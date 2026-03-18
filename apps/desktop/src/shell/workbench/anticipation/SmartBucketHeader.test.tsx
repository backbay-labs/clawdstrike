// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createInitialHuntStore } from "../huntTypes";
import { createHuntSpiritState } from "../spirit";
import { SmartBucketHeader } from "./SmartBucketHeader";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

describe("SmartBucketHeader spirit actions", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => {
      root.unmount();
    });
    container.remove();
    vi.restoreAllMocks();
  });

  it("dispatches chamber re-entry from the header spirit affordance", async () => {
    const store = createInitialHuntStore();
    const hunt = {
      ...store.hunts.hunt_demo_1,
      spirit: createHuntSpiritState({
        kind: "forge",
        bindSource: "reconfigure",
        liveMood: "focused",
        confidenceScore: 82,
      }),
    };
    const eventSpy = vi.fn();
    window.addEventListener("huntronomer:spirit-chamber-request", eventSpy as EventListener);

    await act(async () => {
      root.render(
        <SmartBucketHeader
          hunt={hunt}
          huntStore={store}
          collapsed={false}
          onToggleCollapse={() => {}}
          isDragOver={false}
          draggedKind={null}
          dropRoles={[]}
          defaultDropRole={null}
          onSemanticDrop={() => {}}
        />,
      );
    });

    const reenter = container.querySelector(
      '[data-testid="smart-bucket-spirit-open"]',
    ) as HTMLButtonElement | null;

    expect(reenter).toBeTruthy();

    await act(async () => {
      reenter?.click();
    });

    expect(eventSpy).toHaveBeenCalledTimes(1);
    const event = eventSpy.mock.calls[0][0] as CustomEvent<{ huntId: string; source: string }>;
    expect(event.detail).toMatchObject({
      huntId: store.hunts.hunt_demo_1.id,
      source: "smart-bucket",
    });

    window.removeEventListener("huntronomer:spirit-chamber-request", eventSpy as EventListener);
  });
});
