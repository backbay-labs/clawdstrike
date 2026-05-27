import { fireEvent, render, screen } from "@testing-library/react";
import { useRef } from "react";
import { describe, expect, it, vi } from "vitest";
import { NavIconButton, NavRowButton, Tooltip } from "./NavItem";

// Size-aware stub sigil — mirrors the real PROCESS_ICONS component shape.
const Sigil = ({ size = 20 }: { size?: number }) => (
  <svg data-testid="sigil" width={size} height={size} />
);

describe("NavRowButton", () => {
  it("renders the label and is a real button", () => {
    render(
      <NavRowButton
        label="Monitor"
        Sigil={Sigil}
        tone="gold"
        active={false}
        running={false}
        onClick={() => {}}
      />,
    );
    const button = screen.getByRole("button", { name: /monitor/i });
    expect(button.tagName).toBe("BUTTON");
  });

  it("calls onClick when clicked", () => {
    const onClick = vi.fn();
    render(
      <NavRowButton
        label="Monitor"
        Sigil={Sigil}
        tone="gold"
        active={false}
        running={false}
        onClick={onClick}
      />,
    );
    fireEvent.click(screen.getByRole("button"));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it("activates via click (native button Enter/Space activation works in real browsers)", () => {
    const onClick = vi.fn();
    render(
      <NavRowButton
        label="Monitor"
        Sigil={Sigil}
        tone="gold"
        active={false}
        running={false}
        onClick={onClick}
      />,
    );
    const button = screen.getByRole("button");
    fireEvent.click(button);
    fireEvent.click(button);
    expect(onClick).toHaveBeenCalledTimes(2);
  });

  it("sets aria-current=page and renders the 2px active indicator when active", () => {
    render(
      <NavRowButton
        label="Monitor"
        Sigil={Sigil}
        tone="gold"
        active={true}
        running={false}
        onClick={() => {}}
      />,
    );
    const button = screen.getByRole("button");
    expect(button.getAttribute("aria-current")).toBe("page");
    const indicator = screen.getByTestId("nav-active-indicator");
    expect(indicator.style.width).toBe("2px");
    expect(indicator.style.background).toBe("var(--gold)");
  });

  it("does not set aria-current when inactive", () => {
    render(
      <NavRowButton
        label="Monitor"
        Sigil={Sigil}
        tone="gold"
        active={false}
        running={false}
        onClick={() => {}}
      />,
    );
    expect(screen.getByRole("button").getAttribute("aria-current")).toBeNull();
    expect(screen.queryByTestId("nav-active-indicator")).toBeNull();
  });

  it("renders the running dot (teal when not active)", () => {
    render(
      <NavRowButton
        label="Monitor"
        Sigil={Sigil}
        tone="gold"
        active={false}
        running={true}
        onClick={() => {}}
      />,
    );
    const dot = screen.getByTestId("nav-running-dot");
    expect(dot.style.background).toBe("var(--teal)");
  });

  it("running dot turns gold when active", () => {
    render(
      <NavRowButton
        label="Monitor"
        Sigil={Sigil}
        tone="gold"
        active={true}
        running={true}
        onClick={() => {}}
      />,
    );
    expect(screen.getByTestId("nav-running-dot").style.background).toBe("var(--gold)");
  });
});

describe("NavRowButton — collapsed (icon-only morph)", () => {
  it("keeps an accessible name via aria-label when the visible label is folded", () => {
    render(
      <NavRowButton
        label="Monitor"
        Sigil={Sigil}
        tone="gold"
        active={false}
        running={false}
        onClick={() => {}}
        collapsed
      />,
    );
    // The label text node is aria-hidden; the button itself carries aria-label.
    const button = screen.getByRole("button", { name: "Monitor" });
    expect(button.getAttribute("aria-label")).toBe("Monitor");
  });

  it("still launches on click when collapsed", () => {
    const onClick = vi.fn();
    render(
      <NavRowButton
        label="Monitor"
        Sigil={Sigil}
        tone="gold"
        active={false}
        running={false}
        onClick={onClick}
        collapsed
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Monitor" }));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it("preserves the active-state aria-current when collapsed", () => {
    render(
      <NavRowButton
        label="Monitor"
        Sigil={Sigil}
        tone="gold"
        active={true}
        running={false}
        onClick={() => {}}
        collapsed
      />,
    );
    expect(screen.getByRole("button", { name: "Monitor" }).getAttribute("aria-current")).toBe(
      "page",
    );
  });
});

describe("NavIconButton", () => {
  it("renders an accessible button labeled by the app and fires onClick", () => {
    const onClick = vi.fn();
    render(
      <NavIconButton
        label="Settings"
        Sigil={Sigil}
        tone="muted"
        active={false}
        running={false}
        onClick={onClick}
      />,
    );
    const button = screen.getByRole("button", { name: "Settings" });
    fireEvent.click(button);
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it("sets aria-current=page when active", () => {
    render(
      <NavIconButton
        label="Monitor"
        Sigil={Sigil}
        tone="gold"
        active={true}
        running={false}
        onClick={() => {}}
      />,
    );
    expect(screen.getByRole("button").getAttribute("aria-current")).toBe("page");
  });

  it("renders the running edge bar (teal when not active)", () => {
    render(
      <NavIconButton
        label="Monitor"
        Sigil={Sigil}
        tone="gold"
        active={false}
        running={true}
        onClick={() => {}}
      />,
    );
    const bar = screen.getByTestId("nav-running-indicator");
    expect(bar.style.background).toBe("var(--teal)");
    expect(bar.style.height).toBe("16px");
  });

  it("shows a tooltip on hover", () => {
    render(
      <NavIconButton
        label="Monitor"
        Sigil={Sigil}
        tone="gold"
        active={false}
        running={false}
        onClick={() => {}}
      />,
    );
    expect(screen.queryByRole("tooltip")).toBeNull();
    const wrapper = screen.getByRole("button").parentElement as HTMLElement;
    fireEvent.mouseEnter(wrapper);
    expect(screen.getByRole("tooltip").textContent).toContain("Monitor");
  });

  it("shows a tooltip on keyboard focus", () => {
    render(
      <NavIconButton
        label="Monitor"
        Sigil={Sigil}
        tone="gold"
        active={false}
        running={false}
        onClick={() => {}}
      />,
    );
    fireEvent.focus(screen.getByRole("button"));
    expect(screen.getByRole("tooltip").textContent).toContain("Monitor");
  });

  it("renders the tooltip in a body portal (outside the nav item) so it escapes clipping", () => {
    const { container } = render(
      <NavIconButton
        label="Monitor"
        Sigil={Sigil}
        tone="gold"
        active={false}
        running={false}
        onClick={() => {}}
      />,
    );
    fireEvent.focus(screen.getByRole("button"));
    const tip = screen.getByRole("tooltip");
    // The clip-proof fix: the tooltip is NOT a descendant of the rendered nav
    // item subtree; it is portaled to document.body and positioned fixed.
    expect(container.contains(tip)).toBe(false);
    expect(tip.style.position).toBe("fixed");
  });
});

describe("Tooltip", () => {
  it("renders the label and optional kbd hint (inline fallback, no anchor)", () => {
    render(<Tooltip label="Search" kbd="⌘ K" />);
    const tip = screen.getByRole("tooltip");
    expect(tip.textContent).toContain("Search");
    expect(tip.textContent).toContain("⌘ K");
    // No anchor → inline, absolutely-positioned within the relative parent.
    expect(tip.style.position).toBe("absolute");
  });

  it("portals to document.body with position:fixed when given an anchorRef", () => {
    function Harness() {
      const ref = useRef<HTMLButtonElement>(null);
      return (
        <div data-testid="harness">
          <button ref={ref} type="button">
            anchor
          </button>
          <Tooltip label="Expand sidebar" kbd="⌘\" anchorRef={ref} />
        </div>
      );
    }
    const { getByTestId } = render(<Harness />);
    const tip = screen.getByRole("tooltip");
    expect(tip.textContent).toContain("Expand sidebar");
    expect(tip.style.position).toBe("fixed");
    // Escapes the harness subtree (rendered to document.body).
    expect(getByTestId("harness").contains(tip)).toBe(false);
  });
});
