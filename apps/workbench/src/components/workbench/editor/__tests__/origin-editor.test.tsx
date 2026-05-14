import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { OriginMatch, OriginProfile, OriginsConfig, WorkbenchPolicy } from "@/lib/workbench/types";
import { OriginEditor } from "../origin-editor";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";

vi.mock("@/features/policy/stores/policy-store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/features/policy/stores/policy-store")>();
  return { ...actual };
});

function makeProfile(
  metadata?: Record<string, unknown>,
  match_rules: OriginMatch = { provider: "slack" },
): OriginProfile {
  return {
    id: "profile-alpha",
    explanation: "fixture profile",
    match_rules,
    metadata,
  };
}

function makeV14Policy(origins: OriginsConfig): WorkbenchPolicy {
  return {
    version: "1.4.0",
    name: "Test v1.4 Policy",
    description: "",
    guards: {},
    settings: { fail_fast: false, verbose_logging: false, session_timeout_secs: 3600 },
    origins,
  };
}

/** Set up the Zustand stores with a v1.4.0 policy containing the given origins. */
function setupStoreWithOrigins(origins: OriginsConfig): string {
  const policy = makeV14Policy(origins);
  const tabId = usePolicyTabsStore.getState().newTab({ policy })!;
  return tabId;
}

/** Read the current origins from the edit store for the active tab. */
function getStoredOrigins(): OriginsConfig | undefined {
  const activeTabId = usePolicyTabsStore.getState().activeTabId;
  const editState = usePolicyEditStore.getState().editStates.get(activeTabId);
  return editState?.policy.origins;
}

/** Update the origins directly in the edit store (simulates upstream changes). */
function updateStoreOrigins(origins: OriginsConfig): void {
  const activeTabId = usePolicyTabsStore.getState().activeTabId;
  const activeTab = usePolicyTabsStore.getState().tabs.find(t => t.id === activeTabId);
  usePolicyEditStore.getState().updateOrigins(
    activeTabId,
    origins,
    activeTab?.fileType ?? "clawdstrike_policy",
  );
}

describe("OriginEditor", () => {
  beforeEach(() => {
    usePolicyTabsStore.getState()._reset();
  });

  it("resyncs profile metadata text when the selected profile changes upstream", async () => {
    const user = userEvent.setup();
    setupStoreWithOrigins({
      default_behavior: "deny",
      profiles: [makeProfile({ region: "us-east-1" })],
    });

    const { rerender } = render(<OriginEditor />);

    await user.click(screen.getByText("profile-alpha"));

    const textarea = await screen.findByPlaceholderText('{"key": "value"}');
    expect(textarea).toHaveValue(
      JSON.stringify({ region: "us-east-1" }, null, 2),
    );

    act(() => {
      updateStoreOrigins({
        default_behavior: "deny",
        profiles: [makeProfile({ region: "eu-west-1", posture: "restricted" })],
      });
    });

    rerender(<OriginEditor />);

    await waitFor(() => {
      expect(textarea).toHaveValue(
        JSON.stringify(
          { region: "eu-west-1", posture: "restricted" },
          null,
          2,
        ),
      );
    });
  });

  it("preserves in-progress metadata edits across unrelated profile updates", async () => {
    const user = userEvent.setup();
    setupStoreWithOrigins({
      default_behavior: "deny",
      profiles: [makeProfile({ region: "us-east-1" })],
    });

    const { rerender } = render(<OriginEditor />);

    await user.click(screen.getByText("profile-alpha"));

    const textarea = await screen.findByPlaceholderText('{"key": "value"}');
    fireEvent.change(textarea, {
      target: { value: '{\n  "region": "draft"\n}' },
    });

    act(() => {
      updateStoreOrigins({
        default_behavior: "deny",
        profiles: [
          {
            ...makeProfile({ region: "us-east-1" }),
            explanation: "updated elsewhere",
          },
        ],
      });
    });

    rerender(<OriginEditor />);

    expect(textarea).toHaveValue('{\n  "region": "draft"\n}');
  });

  it("keeps custom provider inputs in custom mode when cleared", async () => {
    const user = userEvent.setup();
    setupStoreWithOrigins({
      default_behavior: "deny",
      profiles: [makeProfile(undefined, { provider: "custom-provider" })],
    });

    const { rerender } = render(<OriginEditor />);

    await user.click(screen.getByText("profile-alpha"));

    const providerInput = await screen.findByPlaceholderText(
      "e.g. my-custom-provider",
    );
    await user.clear(providerInput);
    expect(providerInput).toHaveValue("");

    // Verify the store was updated: provider should have been cleared
    const origins = getStoredOrigins();
    expect(origins?.profiles[0].match_rules.provider).toBeUndefined();

    act(() => {
      updateStoreOrigins({
        default_behavior: "deny",
        profiles: [makeProfile(undefined, {})],
      });
    });

    rerender(<OriginEditor />);

    expect(
      await screen.findByPlaceholderText("e.g. my-custom-provider"),
    ).toHaveValue("");
  });

  it("clears the stored provider when switching an existing provider to custom mode", async () => {
    const user = userEvent.setup();
    setupStoreWithOrigins({
      default_behavior: "deny",
      profiles: [makeProfile(undefined, { provider: "slack" })],
    });

    render(<OriginEditor />);

    await user.click(screen.getByText("profile-alpha"));
    await user.click(screen.getAllByRole("combobox")[1]);
    await user.click(await screen.findByRole("option", { name: "Custom..." }));

    await waitFor(() => {
      expect(
        screen.getByPlaceholderText("e.g. my-custom-provider"),
      ).toHaveValue("slack");
    });

    // Verify the store was updated: provider should have been cleared
    const origins = getStoredOrigins();
    expect(origins?.profiles[0].match_rules.provider).toBeUndefined();
  });

  it("keeps custom space type inputs in custom mode when cleared", async () => {
    const user = userEvent.setup();
    setupStoreWithOrigins({
      default_behavior: "deny",
      profiles: [makeProfile(undefined, { space_type: "custom-space" })],
    });

    const { rerender } = render(<OriginEditor />);

    await user.click(screen.getByText("profile-alpha"));

    const spaceTypeInput = await screen.findByPlaceholderText(
      "e.g. my-custom-space",
    );
    await user.clear(spaceTypeInput);
    expect(spaceTypeInput).toHaveValue("");

    // Verify the store was updated: space_type should have been cleared
    const origins = getStoredOrigins();
    expect(origins?.profiles[0].match_rules.space_type).toBeUndefined();

    act(() => {
      updateStoreOrigins({
        default_behavior: "deny",
        profiles: [makeProfile(undefined, {})],
      });
    });

    rerender(<OriginEditor />);

    expect(
      await screen.findByPlaceholderText("e.g. my-custom-space"),
    ).toHaveValue("");
  });

  it("clears the stored space type when switching an existing space type to custom mode", async () => {
    const user = userEvent.setup();
    setupStoreWithOrigins({
      default_behavior: "deny",
      profiles: [makeProfile(undefined, { provider: "slack", space_type: "channel" })],
    });

    render(<OriginEditor />);

    await user.click(screen.getByText("profile-alpha"));
    await user.click(screen.getAllByRole("combobox")[2]);
    await user.click(await screen.findByRole("option", { name: "Custom..." }));

    await waitFor(() => {
      expect(
        screen.getByPlaceholderText("e.g. my-custom-space"),
      ).toHaveValue("channel");
    });

    // Verify the store was updated: space_type should have been cleared
    const origins = getStoredOrigins();
    expect(origins?.profiles[0].match_rules.space_type).toBeUndefined();
  });
});
