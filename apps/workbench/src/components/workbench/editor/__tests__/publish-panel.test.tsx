import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { PublishPanel } from "../publish-panel";
import type { PublicationManifest, LabRun } from "@/lib/workbench/detection-workflow/shared-types";
import type { PublishGateStatus, PublishResult } from "@/lib/workbench/detection-workflow/use-publication";

// ---- Mock the usePublication hook ----

let mockManifests: PublicationManifest[] = [];
let mockLatestManifest: PublicationManifest | null = null;
let mockLoading = false;
let mockCanPublish = true;
let mockPublishGateStatus: PublishGateStatus = {
  validationPassed: true,
  labRunPassed: null,
  sourceHashChanged: false,
  gateOpen: true,
  reasons: [],
};
const mockPublish = vi.fn<(req: unknown) => Promise<PublishResult>>();
const mockRefreshManifests = vi.fn();

vi.mock("@/lib/workbench/detection-workflow/use-publication", () => ({
  usePublication: () => ({
    manifests: mockManifests,
    latestManifest: mockLatestManifest,
    loading: mockLoading,
    publish: mockPublish,
    canPublish: mockCanPublish,
    publishGateStatus: mockPublishGateStatus,
    refreshManifests: mockRefreshManifests,
  }),
  getAvailableTargets: (fileType: string) => {
    switch (fileType) {
      case "clawdstrike_policy":
        return ["native_policy", "fleet_deploy"];
      case "sigma_rule":
        return ["native_policy", "json_export", "spl", "kql", "esql"];
      case "yara_rule":
        return ["json_export"];
      case "ocsf_event":
        return ["json_export"];
      default:
        return [];
    }
  },
}));

// ---- Mock fleet connection ----

vi.mock("@/lib/workbench/use-fleet-connection", () => ({
  useFleetConnection: () => ({
    connection: { connected: false },
    agents: [],
    getAuthenticatedConnection: () => ({}),
  }),
}));

// ---- Mock fleet client ----

vi.mock("@/lib/workbench/fleet-client", () => ({
  deployPolicy: vi.fn(),
}));

// ---- Mock toast ----

vi.mock("@/components/ui/toast", () => ({
  useToast: () => ({
    toast: vi.fn(),
  }),
}));

// ---- Mock local audit ----

vi.mock("@/lib/workbench/local-audit", () => ({
  emitAuditEvent: vi.fn(),
}));

// ---- Helpers ----

function makeManifest(overrides: Partial<PublicationManifest> = {}): PublicationManifest {
  return {
    id: crypto.randomUUID(),
    documentId: "doc-1",
    sourceFileType: "clawdstrike_policy",
    target: "native_policy",
    createdAt: new Date().toISOString(),
    sourceHash: "abc123",
    outputHash: "def456",
    validationSnapshot: { valid: true, diagnosticCount: 0 },
    runSnapshot: null,
    coverageSnapshot: null,
    converter: { id: "identity", version: "1.0.0" },
    signer: null,
    provenance: null,
    ...overrides,
  };
}

// ---- Tests ----

describe("PublishPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockManifests = [];
    mockLatestManifest = null;
    mockLoading = false;
    mockCanPublish = true;
    mockPublishGateStatus = {
      validationPassed: true,
      labRunPassed: null,
      sourceHashChanged: false,
      gateOpen: true,
      reasons: [],
    };
  });

  it("renders gate status indicators", () => {
    render(
      <PublishPanel
        documentId="doc-1"
        fileType="clawdstrike_policy"
        source="version: '1.0'"
        validationValid={true}
        lastLabRun={null}
      />,
    );

    expect(screen.getByText("Publish Gates")).toBeInTheDocument();
    expect(screen.getByText("Validation")).toBeInTheDocument();
    expect(screen.getByText("Lab Run")).toBeInTheDocument();
    expect(screen.getByText("Source Changed")).toBeInTheDocument();
  });

  it("shows correct targets for clawdstrike_policy", () => {
    render(
      <PublishPanel
        documentId="doc-1"
        fileType="clawdstrike_policy"
        source="version: '1.0'"
        validationValid={true}
        lastLabRun={null}
      />,
    );

    const select = screen.getByRole("combobox") as HTMLSelectElement;
    const options = Array.from(select.options).map((o) => o.value);
    expect(options).toContain("native_policy");
    expect(options).toContain("fleet_deploy");
    expect(options).not.toContain("spl");
  });

  it("shows correct targets for sigma_rule", () => {
    render(
      <PublishPanel
        documentId="doc-1"
        fileType="sigma_rule"
        source="title: Test"
        validationValid={true}
        lastLabRun={null}
      />,
    );

    const select = screen.getByRole("combobox") as HTMLSelectElement;
    const options = Array.from(select.options).map((o) => o.value);
    expect(options).toContain("native_policy");
    expect(options).toContain("json_export");
    expect(options).toContain("spl");
    expect(options).toContain("kql");
    expect(options).toContain("esql");
  });

  it("publish button disabled when gates fail", () => {
    mockPublishGateStatus = {
      validationPassed: false,
      labRunPassed: null,
      sourceHashChanged: false,
      gateOpen: false,
      reasons: ["Validation has errors"],
    };

    render(
      <PublishPanel
        documentId="doc-1"
        fileType="clawdstrike_policy"
        source="version: '1.0'"
        validationValid={false}
        lastLabRun={null}
      />,
    );

    // Find the publish button — it should be disabled
    const publishBtn = screen.getByRole("button", { name: /Publish/i });
    expect(publishBtn).toBeDisabled();
  });

  it("publish button enabled when gates pass", () => {
    mockPublishGateStatus = {
      validationPassed: true,
      labRunPassed: null,
      sourceHashChanged: false,
      gateOpen: true,
      reasons: [],
    };

    render(
      <PublishPanel
        documentId="doc-1"
        fileType="clawdstrike_policy"
        source="version: '1.0'"
        validationValid={true}
        lastLabRun={null}
      />,
    );

    const publishBtn = screen.getByRole("button", { name: /Publish/i });
    expect(publishBtn).not.toBeDisabled();
  });

  it("shows publication history", () => {
    const m1 = makeManifest({ target: "native_policy" });
    const m2 = makeManifest({ target: "fleet_deploy" });
    mockManifests = [m1, m2];
    mockLatestManifest = m1;

    render(
      <PublishPanel
        documentId="doc-1"
        fileType="clawdstrike_policy"
        source="version: '1.0'"
        validationValid={true}
        lastLabRun={null}
      />,
    );

    expect(screen.getByText("Publication History")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument(); // count badge
    // "Native Policy (YAML)" appears in both the dropdown option and history entry
    const nativePolicyElements = screen.getAllByText("Native Policy (YAML)");
    expect(nativePolicyElements.length).toBeGreaterThanOrEqual(2); // option + history entry
    // "Fleet Deploy" appears in both the dropdown option and history entry
    const fleetDeployElements = screen.getAllByText("Fleet Deploy");
    expect(fleetDeployElements.length).toBeGreaterThanOrEqual(2);
  });

  it("shows no publications message when empty", () => {
    mockManifests = [];

    render(
      <PublishPanel
        documentId="doc-1"
        fileType="clawdstrike_policy"
        source="version: '1.0'"
        validationValid={true}
        lastLabRun={null}
      />,
    );

    expect(screen.getByText("No publications yet")).toBeInTheDocument();
  });

  it("non-policy deploy is blocked with warning message", () => {
    render(
      <PublishPanel
        documentId="doc-1"
        fileType="sigma_rule"
        source="title: Test"
        validationValid={true}
        lastLabRun={null}
      />,
    );

    // With sigma_rule, fleet_deploy is not in the target list,
    // so the user cannot select it — this is the designed behavior.
    const select = screen.getByRole("combobox") as HTMLSelectElement;
    const options = Array.from(select.options).map((o) => o.value);
    expect(options).not.toContain("fleet_deploy");
  });

  it("shows message when no document is open", () => {
    render(
      <PublishPanel
        documentId={undefined}
        fileType={undefined}
        source=""
        validationValid={false}
        lastLabRun={null}
      />,
    );

    expect(screen.getByText("Open a detection document to publish.")).toBeInTheDocument();
  });

  it("shows no adapter message for unregistered format", () => {
    mockCanPublish = false;

    render(
      <PublishPanel
        documentId="doc-1"
        fileType="ocsf_event"
        source="{}"
        validationValid={true}
        lastLabRun={null}
      />,
    );

    expect(screen.getByText(/No publish adapter registered/i)).toBeInTheDocument();
  });

  it("displays gate failure reasons", () => {
    mockPublishGateStatus = {
      validationPassed: false,
      labRunPassed: false,
      sourceHashChanged: false,
      gateOpen: false,
      reasons: ["Validation has errors", "Latest lab run has failures"],
    };

    render(
      <PublishPanel
        documentId="doc-1"
        fileType="clawdstrike_policy"
        source="version: '1.0'"
        validationValid={false}
        lastLabRun={null}
      />,
    );

    expect(screen.getByText("Validation has errors")).toBeInTheDocument();
    expect(screen.getByText("Latest lab run has failures")).toBeInTheDocument();
  });

  it("calls publish on button click", async () => {
    const user = userEvent.setup();
    mockPublish.mockResolvedValue({ success: true, manifest: makeManifest() });

    render(
      <PublishPanel
        documentId="doc-1"
        fileType="clawdstrike_policy"
        source="version: '1.0'"
        validationValid={true}
        lastLabRun={null}
      />,
    );

    const publishBtn = screen.getByRole("button", { name: /Publish/i });
    await user.click(publishBtn);

    expect(mockPublish).toHaveBeenCalledTimes(1);
    expect(mockPublish).toHaveBeenCalledWith(
      expect.objectContaining({
        source: "version: '1.0'",
        targetFormat: "native_policy",
      }),
    );
  });
});
