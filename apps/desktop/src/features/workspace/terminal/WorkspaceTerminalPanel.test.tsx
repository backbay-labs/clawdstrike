// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WorkspaceTerminalPanel } from "./WorkspaceTerminalPanel";
import { createMockWorkspaceTerminalService } from "./workspaceTerminalService";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

describe("WorkspaceTerminalPanel", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement("div");
    container.style.width = "900px";
    container.style.height = "480px";
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => {
      root.unmount();
    });
    container.remove();
  });

  it("opens shell sessions and runs mocked task sessions", async () => {
    const service = createMockWorkspaceTerminalService();

    await act(async () => {
      root.render(
        <WorkspaceTerminalPanel rootId="root-1" rootName="hunt-root" initialCwd="." service={service} />,
      );
    });

    const buttons = Array.from(container.querySelectorAll("button"));
    const openShell = buttons.find((button) => button.textContent?.includes("Open shell"));
    const runGit = buttons.find((button) => button.textContent?.includes("git status"));
    if (!openShell || !runGit) {
      throw new Error("Terminal controls did not render");
    }

    await act(async () => {
      openShell.click();
    });

    expect(container.querySelector('[data-testid="workspace-terminal-output"]')?.textContent).toContain(
      "shell ready for hunt-root",
    );

    await act(async () => {
      runGit.click();
    });

    expect(container.querySelector('[data-testid="workspace-terminal-output"]')?.textContent).toContain(
      "git status --short",
    );
    expect(container.querySelector('[data-testid="workspace-terminal-tabs"]')?.textContent).toContain(
      "hunt-root shell",
    );
  });

  it("sends commands to the active shell session", async () => {
    const service = createMockWorkspaceTerminalService();

    await act(async () => {
      root.render(<WorkspaceTerminalPanel rootId="root-1" rootName="hunt-root" service={service} />);
    });

    const openShell = Array.from(container.querySelectorAll("button")).find((button) =>
      button.textContent?.includes("Open shell"),
    );
    if (!openShell) {
      throw new Error("Missing shell button");
    }

    await act(async () => {
      openShell.click();
    });

    const input = container.querySelector("input") as HTMLInputElement;
    const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    if (!valueSetter) {
      throw new Error("Missing input value setter");
    }

    await act(async () => {
      valueSetter.call(input, "rg --files");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });

    const send = Array.from(container.querySelectorAll("button")).find((button) =>
      button.textContent?.includes("Send"),
    );
    if (!send) {
      throw new Error("Missing send button");
    }

    await act(async () => {
      send.click();
    });

    expect(container.querySelector('[data-testid="workspace-terminal-output"]')?.textContent).toContain(
      "rules/sigma/outbound-spike.yml",
    );
  });
});
