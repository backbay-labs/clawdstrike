/**
 * Permission System Tests
 *
 * Tests for the PluginPermission type, METHOD_TO_PERMISSION mapping,
 * and checkPermission function. Validates that every bridge method
 * has a corresponding permission entry and that the permission check
 * is fail-closed (unknown methods are denied).
 */

import { describe, it, expect } from "vitest";
import { BRIDGE_METHODS } from "../types";
import {
  METHOD_TO_PERMISSION,
  checkPermission,
  checkNetworkPermission,
  extractNetworkPermissions,
  KNOWN_PERMISSIONS,
} from "../permissions";
import type {
  PluginPermission,
  NetworkPermission,
  PluginManifest,
} from "../../types";

// ---- PluginPermission type shape ----

describe("PluginPermission", () => {
  it("includes all expected permission strings", () => {
    // Compile-time check: if any of these are not assignable to PluginPermission,
    // the test file won't compile.
    const perms: PluginPermission[] = [
      "guards:register",
      "guards:read",
      "commands:register",
      "commands:execute",
      "fileTypes:register",
      "statusBar:register",
      "sidebar:register",
      "storage:read",
      "storage:write",
      "policy:read",
      "policy:write",
      "network:fetch",
      "clipboard:read",
      "clipboard:write",
      "notifications:show",
    ];
    expect(new Set(perms).size).toBe(15);
  });

  it("PluginManifest accepts a permissions array of PluginPermission values", () => {
    const manifest = {
      id: "test.plugin",
      name: "test",
      displayName: "Test",
      description: "A test plugin",
      version: "1.0.0",
      publisher: "test",
      categories: ["guards"],
      trust: "community" as const,
      activationEvents: ["onStartup"],
      permissions: [
        "guards:register" as PluginPermission,
        "storage:read" as PluginPermission,
      ],
    } satisfies PluginManifest;
    expect(manifest.permissions).toHaveLength(2);
  });
});

// ---- NetworkPermission ----

describe("NetworkPermission", () => {
  it("is accepted in the permissions array alongside PluginPermission strings", () => {
    const netPerm: NetworkPermission = {
      type: "network:fetch",
      allowedDomains: ["api.example.com", "cdn.example.com"],
    };
    const manifest = {
      id: "test.plugin",
      name: "test",
      displayName: "Test",
      description: "A test plugin",
      version: "1.0.0",
      publisher: "test",
      categories: ["guards"],
      trust: "community" as const,
      activationEvents: ["onStartup"],
      permissions: [
        "guards:register" as PluginPermission,
        netPerm,
      ],
    } satisfies PluginManifest;
    expect(manifest.permissions).toHaveLength(2);
    expect((manifest.permissions[1] as NetworkPermission).allowedDomains).toEqual([
      "api.example.com",
      "cdn.example.com",
    ]);
  });
});

// ---- METHOD_TO_PERMISSION ----

describe("METHOD_TO_PERMISSION", () => {
  it("maps every BRIDGE_METHODS value to a PluginPermission string", () => {
    const allMethods: string[] = [];
    for (const ns of Object.values(BRIDGE_METHODS)) {
      for (const m of Object.values(ns as Record<string, string>)) {
        allMethods.push(m);
      }
    }

    for (const method of allMethods) {
      expect(METHOD_TO_PERMISSION).toHaveProperty(method);
    }
  });

  it('maps "guards.register" to "guards:register"', () => {
    expect(METHOD_TO_PERMISSION["guards.register"]).toBe("guards:register");
  });

  it('maps "storage.get" to "storage:read"', () => {
    expect(METHOD_TO_PERMISSION["storage.get"]).toBe("storage:read");
  });

  it('maps "storage.set" to "storage:write"', () => {
    expect(METHOD_TO_PERMISSION["storage.set"]).toBe("storage:write");
  });

  it('maps "commands.register" to "commands:register"', () => {
    expect(METHOD_TO_PERMISSION["commands.register"]).toBe("commands:register");
  });

  it('maps "fileTypes.register" to "fileTypes:register"', () => {
    expect(METHOD_TO_PERMISSION["fileTypes.register"]).toBe("fileTypes:register");
  });

  it('maps "statusBar.register" to "statusBar:register"', () => {
    expect(METHOD_TO_PERMISSION["statusBar.register"]).toBe("statusBar:register");
  });

  it('maps "sidebar.register" to "sidebar:register"', () => {
    expect(METHOD_TO_PERMISSION["sidebar.register"]).toBe("sidebar:register");
  });
});

// ---- checkPermission ----

describe("checkPermission", () => {
  it("returns true when the permission set contains the required permission", () => {
    const granted = new Set(["guards:register", "storage:read"]);
    expect(checkPermission(granted, "guards.register")).toBe(true);
  });

  it("returns false when the permission set does not contain the required permission", () => {
    const granted = new Set(["guards:register"]);
    expect(checkPermission(granted, "storage.set")).toBe(false);
  });

  it("returns false for a method not in METHOD_TO_PERMISSION (unknown method)", () => {
    const granted = new Set(["guards:register", "storage:read", "storage:write"]);
    expect(checkPermission(granted, "unknown.method")).toBe(false);
  });

  it("returns false for an empty permission set", () => {
    const granted = new Set<string>();
    expect(checkPermission(granted, "guards.register")).toBe(false);
  });

  it("returns true when multiple permissions are granted and method matches one", () => {
    const granted = new Set([
      "guards:register",
      "storage:read",
      "storage:write",
      "commands:register",
    ]);
    expect(checkPermission(granted, "storage.get")).toBe(true);
    expect(checkPermission(granted, "storage.set")).toBe(true);
    expect(checkPermission(granted, "commands.register")).toBe(true);
  });
});

// ---- KNOWN_PERMISSIONS ----

describe("KNOWN_PERMISSIONS", () => {
  it("is a Set containing all 15 PluginPermission values", () => {
    expect(KNOWN_PERMISSIONS).toBeInstanceOf(Set);
    expect(KNOWN_PERMISSIONS.size).toBe(15);
    expect(KNOWN_PERMISSIONS.has("guards:register")).toBe(true);
    expect(KNOWN_PERMISSIONS.has("network:fetch")).toBe(true);
    expect(KNOWN_PERMISSIONS.has("notifications:show")).toBe(true);
  });

  it("does not contain non-existent permissions", () => {
    expect(KNOWN_PERMISSIONS.has("filesystem:write")).toBe(false);
    expect(KNOWN_PERMISSIONS.has("unknown:perm")).toBe(false);
  });
});

// ---- checkNetworkPermission ----

describe("checkNetworkPermission", () => {
  it("returns true for exact domain match", () => {
    expect(
      checkNetworkPermission("https://api.virustotal.com/v3/files", [
        "api.virustotal.com",
      ]),
    ).toBe(true);
  });

  it("returns false when domain is not in allowed list", () => {
    expect(
      checkNetworkPermission("https://evil.com/steal", [
        "api.virustotal.com",
      ]),
    ).toBe(false);
  });

  it("supports wildcard subdomain matching", () => {
    expect(
      checkNetworkPermission("https://sub.api.virustotal.com/v3", [
        "*.virustotal.com",
      ]),
    ).toBe(true);
  });

  it("wildcard does not match the base domain itself", () => {
    expect(
      checkNetworkPermission("https://virustotal.com/v3", [
        "*.virustotal.com",
      ]),
    ).toBe(false);
  });

  it("returns false for empty domain list (fail-closed)", () => {
    expect(
      checkNetworkPermission("https://evil.com", []),
    ).toBe(false);
  });

  it("returns false for invalid URL (fail-closed)", () => {
    expect(
      checkNetworkPermission("not-a-valid-url", ["example.com"]),
    ).toBe(false);
  });
});

// ---- extractNetworkPermissions ----

describe("extractNetworkPermissions", () => {
  it("filters out NetworkPermission objects from a mixed permissions array", () => {
    const permissions: (PluginPermission | NetworkPermission)[] = [
      "guards:register",
      { type: "network:fetch", allowedDomains: ["api.example.com"] },
      "storage:read",
      { type: "network:fetch", allowedDomains: ["cdn.example.com"] },
    ];
    const result = extractNetworkPermissions(permissions);
    expect(result).toHaveLength(2);
    expect(result[0].allowedDomains).toEqual(["api.example.com"]);
    expect(result[1].allowedDomains).toEqual(["cdn.example.com"]);
  });

  it("returns empty array when no NetworkPermission objects present", () => {
    const permissions: (PluginPermission | NetworkPermission)[] = ["guards:register", "storage:read"];
    const result = extractNetworkPermissions(permissions);
    expect(result).toHaveLength(0);
  });

  it("returns empty array for empty permissions array", () => {
    const result = extractNetworkPermissions([]);
    expect(result).toHaveLength(0);
  });
});
