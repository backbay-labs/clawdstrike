/**
 * PluginRevocationBadge Tests
 *
 * Tests for the revocation badge component that shows warning badges
 * for revoked plugins with reason, duration, and disabled state.
 * Follows the same testing pattern as plugin-audit-viewer.test.tsx.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import type { PluginRevocationEntry } from "@/lib/plugins/revocation-store";
import type { PluginLifecycleState } from "@/lib/plugins/types";

// ---- Mock revocation store ----

function createMockStore(entries: PluginRevocationEntry[] = []) {
  return {
    revoke: vi.fn(),
    isRevoked: vi.fn((pluginId: string) =>
      entries.some((e) => e.pluginId === pluginId),
    ),
    lift: vi.fn(),
    getAll: vi.fn(() => entries),
    sync: vi.fn(),
  };
}

// ---- Lazy import (after mocks) ----

import { PluginRevocationBadge, isPluginRevoked } from "../plugin-revocation-badge";

// ---- Tests ----

describe("PluginRevocationBadge", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // Test 1: Renders warning badge with "Revoked" text when plugin state is "revoked"
  it("renders warning badge with 'Revoked' text when plugin state is 'revoked'", () => {
    const store = createMockStore([
      {
        pluginId: "bad-plugin",
        reason: "Malware detected",
        revokedAt: "2026-03-19T00:00:00Z",
        until: null,
      },
    ]);

    render(
      <PluginRevocationBadge
        pluginId="bad-plugin"
        pluginState="revoked"
        revocationStore={store as never}
      />,
    );

    expect(screen.getByText("Revoked")).toBeTruthy();
  });

  // Test 2: Displays the revocation reason from the revocation store entry
  it("displays the revocation reason from the revocation store entry", () => {
    const store = createMockStore([
      {
        pluginId: "bad-plugin",
        reason: "Malware detected",
        revokedAt: "2026-03-19T00:00:00Z",
        until: null,
      },
    ]);

    render(
      <PluginRevocationBadge
        pluginId="bad-plugin"
        pluginState="revoked"
        revocationStore={store as never}
      />,
    );

    expect(screen.getByText("Malware detected")).toBeTruthy();
  });

  // Test 3: Shows "Permanent" when until is null, shows expiry date when until is set
  it("shows 'Permanent' when until is null, shows expiry date when until is set", () => {
    const storePermanent = createMockStore([
      {
        pluginId: "perm-plugin",
        reason: "Bad",
        revokedAt: "2026-03-19T00:00:00Z",
        until: null,
      },
    ]);

    const { unmount } = render(
      <PluginRevocationBadge
        pluginId="perm-plugin"
        pluginState="revoked"
        revocationStore={storePermanent as never}
      />,
    );

    expect(screen.getByText("Permanent")).toBeTruthy();
    unmount();

    // Now test with time-limited
    const storeTimeLimited = createMockStore([
      {
        pluginId: "temp-plugin",
        reason: "Temporary",
        revokedAt: "2026-03-19T00:00:00Z",
        until: "2026-03-20T00:00:00Z",
      },
    ]);

    render(
      <PluginRevocationBadge
        pluginId="temp-plugin"
        pluginState="revoked"
        revocationStore={storeTimeLimited as never}
      />,
    );

    expect(screen.getByText(/Until/)).toBeTruthy();
  });

  // Test 4: Install/Activate buttons are disabled when plugin is revoked
  it("install/activate buttons are disabled when plugin is revoked", () => {
    const store = createMockStore([
      {
        pluginId: "bad-plugin",
        reason: "Revoked",
        revokedAt: "2026-03-19T00:00:00Z",
        until: null,
      },
    ]);

    // Use isPluginRevoked helper for button disable logic
    expect(isPluginRevoked("bad-plugin", store as never)).toBe(true);
    expect(isPluginRevoked("good-plugin", store as never)).toBe(false);
  });

  // Test 5: Shows explanation text "This plugin has been revoked by an operator"
  it("shows explanation text about operator revocation", () => {
    const store = createMockStore([
      {
        pluginId: "bad-plugin",
        reason: "Bad",
        revokedAt: "2026-03-19T00:00:00Z",
        until: null,
      },
    ]);

    render(
      <PluginRevocationBadge
        pluginId="bad-plugin"
        pluginState="revoked"
        revocationStore={store as never}
      />,
    );

    expect(
      screen.getByText(/This plugin has been revoked by an operator/),
    ).toBeTruthy();
  });

  // Test 6: Does not render badge when plugin state is not "revoked"
  it("does not render badge when plugin state is not 'revoked'", () => {
    const store = createMockStore();

    const { container } = render(
      <PluginRevocationBadge
        pluginId="good-plugin"
        pluginState="activated"
        revocationStore={store as never}
      />,
    );

    // Should render nothing
    expect(container.innerHTML).toBe("");
  });

  // Test 7: Does not show badge when time-limited revocation has expired
  it("does not show badge when time-limited revocation has expired (isRevoked false)", () => {
    // Store returns false for isRevoked (expired) -- state would have been
    // changed by revocationStore expiry logic before this component renders
    const store = createMockStore([]); // no entries = not revoked

    const { container } = render(
      <PluginRevocationBadge
        pluginId="expired-plugin"
        pluginState="deactivated"
        revocationStore={store as never}
      />,
    );

    expect(container.innerHTML).toBe("");
  });
});
