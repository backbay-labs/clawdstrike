import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { PluginSecretsSettings } from "../plugin-secrets-settings";
import type { RegisteredPlugin } from "@/lib/plugins/types";

// ---- Mocks ----

const mockSecureStore = vi.hoisted(() => ({
  set: vi.fn().mockResolvedValue(undefined),
  get: vi.fn().mockResolvedValue(null),
  has: vi.fn().mockResolvedValue(false),
  delete: vi.fn().mockResolvedValue(undefined),
  isSecure: vi.fn().mockResolvedValue(false),
  init: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("@/lib/workbench/secure-store", () => ({
  secureStore: mockSecureStore,
}));

const mockPluginRegistry = vi.hoisted(() => ({
  getAll: vi.fn((): RegisteredPlugin[] => []),
}));

vi.mock("@/lib/plugins/plugin-registry", () => ({
  pluginRegistry: mockPluginRegistry,
}));

const mockThreatIntelCatalog = vi.hoisted(() => ({
  getBuiltinThreatIntelDescriptor: vi.fn(() => undefined),
}));

vi.mock("@/lib/plugins/threat-intel/catalog", () => mockThreatIntelCatalog);

const mockThreatIntelRegistry = vi.hoisted(() => ({
  getThreatIntelSource: vi.fn(() => undefined),
}));

vi.mock("@/lib/workbench/threat-intel-registry", () => mockThreatIntelRegistry);

// ---- Fixtures ----

function makeIntelPlugin(
  id: string,
  displayName: string,
  requiredSecrets: Array<{ key: string; label: string; description: string }>,
) {
  return {
    manifest: {
      id,
      name: id,
      displayName,
      description: `${displayName} plugin`,
      version: "1.0.0",
      publisher: "test",
      categories: ["intel"],
      trust: "internal" as const,
      activationEvents: ["onStartup"],
      contributions: {
        threatIntelSources: [
          {
            id: `${id}.source`,
            name: displayName,
            description: `${displayName} source`,
            entrypoint: "./source.ts",
          },
        ],
      },
      requiredSecrets,
    },
    state: "activated" as const,
  };
}

const VT_PLUGIN = makeIntelPlugin("virustotal", "VirusTotal", [
  { key: "api_key", label: "VirusTotal API Key", description: "Get from virustotal.com" },
]);

const GN_PLUGIN = makeIntelPlugin("greynoise", "GreyNoise", [
  { key: "api_key", label: "GreyNoise API Key", description: "Get from greynoise.io" },
]);

const MISP_PLUGIN = makeIntelPlugin("misp", "MISP", [
  { key: "api_key", label: "MISP API Key", description: "Get from your MISP instance" },
  { key: "base_url", label: "MISP Base URL", description: "The URL of your MISP instance" },
]);

const UI_ONLY_PLUGIN = {
  manifest: {
    id: "theme-plugin",
    name: "theme-plugin",
    displayName: "Dark Theme",
    description: "A UI theme plugin",
    version: "1.0.0",
    publisher: "test",
    categories: ["ui"],
    trust: "community" as const,
    activationEvents: ["onStartup"],
    contributions: {},
  },
  state: "activated" as const,
};

// ---- Tests ----

describe("PluginSecretsSettings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSecureStore.has.mockResolvedValue(false);
    mockSecureStore.get.mockResolvedValue(null);
    mockThreatIntelCatalog.getBuiltinThreatIntelDescriptor.mockReturnValue(undefined);
    mockThreatIntelRegistry.getThreatIntelSource.mockReturnValue(undefined);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("renders a section for each registered threat intel plugin", () => {
    mockPluginRegistry.getAll.mockReturnValue([VT_PLUGIN, GN_PLUGIN, UI_ONLY_PLUGIN]);

    render(<PluginSecretsSettings />);

    expect(screen.getByText("VirusTotal")).toBeInTheDocument();
    expect(screen.getByText("GreyNoise")).toBeInTheDocument();
    // UI-only plugin should not appear
    expect(screen.queryByText("Dark Theme")).not.toBeInTheDocument();
  });

  it("shows input fields for each entry in requiredSecrets array", () => {
    mockPluginRegistry.getAll.mockReturnValue([VT_PLUGIN]);

    render(<PluginSecretsSettings />);

    expect(screen.getByLabelText("VirusTotal API Key")).toBeInTheDocument();
  });

  it("renders password-type fields with show/hide toggle", async () => {
    const user = userEvent.setup();
    mockPluginRegistry.getAll.mockReturnValue([VT_PLUGIN]);

    render(<PluginSecretsSettings />);

    const input = screen.getByLabelText("VirusTotal API Key");
    expect(input).toHaveAttribute("type", "password");

    // Find the toggle button (eye icon)
    const toggleButton = screen.getByTestId("toggle-virustotal-api_key");
    await user.click(toggleButton);

    expect(input).toHaveAttribute("type", "text");
  });

  it("persists key via secure store with plugin:{pluginId}: prefix on Save", async () => {
    const user = userEvent.setup();
    mockPluginRegistry.getAll.mockReturnValue([VT_PLUGIN]);

    render(<PluginSecretsSettings />);

    const input = screen.getByLabelText("VirusTotal API Key");
    await user.type(input, "test-api-key-123");

    const saveButton = screen.getByTestId("save-virustotal-api_key");
    await user.click(saveButton);

    expect(mockSecureStore.set).toHaveBeenCalledWith(
      "plugin:virustotal:api_key",
      "test-api-key-123",
    );
  });

  it("shows masked dots with Change button when key already saved", async () => {
    mockPluginRegistry.getAll.mockReturnValue([VT_PLUGIN]);
    mockSecureStore.has.mockImplementation(async (key: string) =>
      key === "plugin:virustotal:api_key",
    );

    render(<PluginSecretsSettings />);

    // Wait for the async has() call to resolve
    const changeButton = await screen.findByTestId("change-virustotal-api_key");
    expect(changeButton).toBeInTheDocument();
    expect(changeButton).toHaveTextContent("Change");
  });

  it("calls healthCheck and shows success on Test Connection", async () => {
    const user = userEvent.setup();
    mockPluginRegistry.getAll.mockReturnValue([VT_PLUGIN]);
    mockSecureStore.get.mockImplementation(async (key: string) =>
      key === "plugin:virustotal:api_key" ? "test-api-key-123" : null,
    );
    const healthCheck = vi.fn().mockResolvedValue({
      healthy: true,
      message: "VirusTotal credentials are valid",
    });
    mockThreatIntelCatalog.getBuiltinThreatIntelDescriptor.mockReturnValue({
      secretKeys: ["api_key"],
      create: vi.fn(() => ({ healthCheck })),
    } as never);

    render(<PluginSecretsSettings />);

    await user.click(screen.getByTestId("test-virustotal"));

    expect(healthCheck).toHaveBeenCalledTimes(1);
    expect(
      await screen.findByText("VirusTotal credentials are valid"),
    ).toBeInTheDocument();
  });

  it("shows empty state message when no threat intel plugins are registered", () => {
    mockPluginRegistry.getAll.mockReturnValue([UI_ONLY_PLUGIN]);

    render(<PluginSecretsSettings />);

    expect(
      screen.getByText(/no threat intelligence plugins installed/i),
    ).toBeInTheDocument();
  });

  it("shows both api_key and base_url fields for MISP plugin", () => {
    mockPluginRegistry.getAll.mockReturnValue([MISP_PLUGIN]);

    render(<PluginSecretsSettings />);

    expect(screen.getByLabelText("MISP API Key")).toBeInTheDocument();
    expect(screen.getByLabelText("MISP Base URL")).toBeInTheDocument();
  });
});
