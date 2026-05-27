import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConsoleStatus } from "../../hooks/useConsoleStatus";

// Mutable state shared across tests — must be declared before the vi.mock factory
const focusedId = { current: null as string | null };
const instances = {
  current: [] as Array<{ windowId: string; processId: string }>,
};

vi.mock("@backbay/glia-desktop", () => ({
  useDesktopOS: () => ({
    processes: {
      instances: instances.current,
      launch: vi.fn(),
      getDefinition: (processId: string) => ({ description: `desc:${processId}` }),
    },
    windows: { focusedId: focusedId.current },
  }),
}));

// Import after mock registration
import { HeaderBar } from "./HeaderBar";

const STATUS_LIVE: ConsoleStatus = {
  sseLive: true,
  violations: 0,
  uptime: "01:23:45",
  build: "0.2.0",
};

const STATUS_DOWN: ConsoleStatus = {
  sseLive: false,
  violations: 3,
  uptime: "00:00:00",
  build: "0.2.0",
};

beforeEach(() => {
  focusedId.current = null;
  instances.current = [];
});

describe("HeaderBar — breadcrumb", () => {
  it("renders CLAWDSTRIKE when no active process", () => {
    render(
      <HeaderBar
        variant="rail"
        activeProcessId={undefined}
        status={STATUS_LIVE}
        onCmdK={() => {}}
      />,
    );
    expect(screen.getByText("CLAWDSTRIKE")).toBeTruthy();
  });

  it("only shows CLAWDSTRIKE segment when activeProcessId is undefined", () => {
    render(
      <HeaderBar
        variant="rail"
        activeProcessId={undefined}
        status={STATUS_LIVE}
        onCmdK={() => {}}
      />,
    );
    // No group label or leaf name rendered
    expect(screen.queryByText("Operations")).toBeNull();
  });

  it("shows CLAWDSTRIKE / group-label / leaf-name when active process is in core group", () => {
    instances.current = [{ windowId: "w1", processId: "monitor" }];
    focusedId.current = "w1";
    render(
      <HeaderBar variant="rail" activeProcessId="monitor" status={STATUS_LIVE} onCmdK={() => {}} />,
    );
    expect(screen.getByText("CLAWDSTRIKE")).toBeTruthy();
    expect(screen.getByText("Operations")).toBeTruthy();
    expect(screen.getByText("Monitor")).toBeTruthy();
  });

  it("shows the correct group label for a policy-ops app", () => {
    instances.current = [{ windowId: "w2", processId: "policy" }];
    focusedId.current = "w2";
    render(
      <HeaderBar variant="rail" activeProcessId="policy" status={STATUS_LIVE} onCmdK={() => {}} />,
    );
    expect(screen.getByText("Policy + Runtime")).toBeTruthy();
    expect(screen.getByText("Policies")).toBeTruthy();
  });

  it("shows the correct group label for an advanced group app", () => {
    instances.current = [{ windowId: "w3", processId: "receipt-verifier" }];
    focusedId.current = "w3";
    render(
      <HeaderBar
        variant="rail"
        activeProcessId="receipt-verifier"
        status={STATUS_LIVE}
        onCmdK={() => {}}
      />,
    );
    expect(screen.getByText("Tools")).toBeTruthy();
    expect(screen.getByText("Receipts")).toBeTruthy();
  });
});

describe("HeaderBar — rail variant shows search pill + status chips", () => {
  it("renders the ⌘K search pill for rail variant", () => {
    render(
      <HeaderBar
        variant="rail"
        activeProcessId={undefined}
        status={STATUS_LIVE}
        onCmdK={() => {}}
      />,
    );
    expect(screen.getByRole("button", { name: /search apps/i })).toBeTruthy();
  });

  it("renders SSE, Violations, Uptime chips for rail variant", () => {
    render(
      <HeaderBar
        variant="rail"
        activeProcessId={undefined}
        status={STATUS_LIVE}
        onCmdK={() => {}}
      />,
    );
    expect(screen.getByText("SSE")).toBeTruthy();
    expect(screen.getByText("Violations")).toBeTruthy();
    expect(screen.getByText("Uptime")).toBeTruthy();
  });

  it("search pill and status chips are ABSENT for expanded variant", () => {
    render(
      <HeaderBar
        variant="expanded"
        activeProcessId={undefined}
        status={STATUS_LIVE}
        onCmdK={() => {}}
      />,
    );
    expect(screen.queryByRole("button", { name: /search apps/i })).toBeNull();
    expect(screen.queryByText("SSE")).toBeNull();
    expect(screen.queryByText("Violations")).toBeNull();
    expect(screen.queryByText("Uptime")).toBeNull();
  });

  it("search pill and status chips are ABSENT for twopane variant", () => {
    render(
      <HeaderBar
        variant="twopane"
        activeProcessId={undefined}
        status={STATUS_LIVE}
        onCmdK={() => {}}
      />,
    );
    expect(screen.queryByRole("button", { name: /search apps/i })).toBeNull();
    expect(screen.queryByText("SSE")).toBeNull();
    expect(screen.queryByText("Violations")).toBeNull();
    expect(screen.queryByText("Uptime")).toBeNull();
  });
});

describe("HeaderBar — SSE chip state", () => {
  it("shows LIVE and teal tone when sseLive=true", () => {
    render(
      <HeaderBar
        variant="rail"
        activeProcessId={undefined}
        status={STATUS_LIVE}
        onCmdK={() => {}}
      />,
    );
    const liveValue = screen.getByText("LIVE");
    expect(liveValue.style.color).toBe("var(--teal)");
  });

  it("shows DOWN and crimson tone when sseLive=false", () => {
    render(
      <HeaderBar
        variant="rail"
        activeProcessId={undefined}
        status={STATUS_DOWN}
        onCmdK={() => {}}
      />,
    );
    const downValue = screen.getByText("DOWN");
    expect(downValue.style.color).toBe("var(--crimson)");
  });

  it("renders a pulse dot when SSE is LIVE", () => {
    render(
      <HeaderBar
        variant="rail"
        activeProcessId={undefined}
        status={STATUS_LIVE}
        onCmdK={() => {}}
      />,
    );
    expect(screen.getByTestId("pulse-dot")).toBeTruthy();
  });

  it("does NOT render a pulse dot when SSE is DOWN", () => {
    render(
      <HeaderBar
        variant="rail"
        activeProcessId={undefined}
        status={STATUS_DOWN}
        onCmdK={() => {}}
      />,
    );
    expect(document.querySelectorAll("[data-testid='pulse-dot']").length).toBe(0);
  });
});

describe("HeaderBar — Violations chip tone", () => {
  it("uses gold tone when violations = 0", () => {
    render(
      <HeaderBar
        variant="rail"
        activeProcessId={undefined}
        status={{ ...STATUS_LIVE, violations: 0 }}
        onCmdK={() => {}}
      />,
    );
    const violationValue = screen.getByText("0");
    expect(violationValue.style.color).toBe("var(--gold)");
  });

  it("uses crimson tone when violations > 0", () => {
    render(
      <HeaderBar
        variant="rail"
        activeProcessId={undefined}
        status={{ ...STATUS_LIVE, violations: 5 }}
        onCmdK={() => {}}
      />,
    );
    const violationValue = screen.getByText("5");
    expect(violationValue.style.color).toBe("var(--crimson)");
  });
});

describe("HeaderBar — ⌘K callback", () => {
  it("calls onCmdK when the search pill is clicked", () => {
    const onCmdK = vi.fn();
    render(
      <HeaderBar variant="rail" activeProcessId={undefined} status={STATUS_LIVE} onCmdK={onCmdK} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /search apps/i }));
    expect(onCmdK).toHaveBeenCalledTimes(1);
  });
});
