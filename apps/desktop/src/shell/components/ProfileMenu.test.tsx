// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProfileMenu } from "./ProfileMenu";

vi.mock("@/services/tauri", () => ({
  isTauri: () => false,
}));

(
  globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }
).IS_REACT_ACT_ENVIRONMENT = true;

describe("ProfileMenu", () => {
  let container: HTMLDivElement;
  let root: Root;

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it("opens menu and invokes actions", () => {
    const onOpenOperations = vi.fn();
    const onOpenConnectionSettings = vi.fn();

    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    act(() => {
      root.render(
        <ProfileMenu
          connectionStatus="connected"
          onOpenOperations={onOpenOperations}
          onOpenConnectionSettings={onOpenConnectionSettings}
          onOpenCommandPalette={vi.fn()}
        />,
      );
    });

    const trigger = container.querySelector(
      "button[aria-label='Open profile menu']",
    ) as HTMLButtonElement;
    expect(trigger).toBeTruthy();

    act(() => {
      trigger.click();
    });

    const operations = Array.from(container.querySelectorAll("button")).find(
      (button) => button.textContent?.trim() === "Open Operations",
    ) as HTMLButtonElement;

    act(() => {
      operations.click();
    });

    expect(onOpenOperations).toHaveBeenCalledTimes(1);

    act(() => {
      trigger.click();
    });

    const connection = Array.from(container.querySelectorAll("button")).find(
      (button) => button.textContent?.trim() === "Connection Settings",
    ) as HTMLButtonElement;

    act(() => {
      connection.click();
    });

    expect(onOpenConnectionSettings).toHaveBeenCalledTimes(1);
  });
});
