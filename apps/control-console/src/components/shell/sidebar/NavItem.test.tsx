import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { NavIconButton, NavRowButton, Tooltip } from "./NavItem";

const sigil = <svg data-testid="sigil" />;

describe("NavRowButton", () => {
  it("renders the label and is a real button", () => {
    render(
      <NavRowButton
        label="Monitor"
        sigil={sigil}
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
        sigil={sigil}
        tone="gold"
        active={false}
        running={false}
        onClick={onClick}
      />,
    );
    fireEvent.click(screen.getByRole("button"));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it("activates on Enter and Space", () => {
    const onClick = vi.fn();
    render(
      <NavRowButton
        label="Monitor"
        sigil={sigil}
        tone="gold"
        active={false}
        running={false}
        onClick={onClick}
      />,
    );
    const button = screen.getByRole("button");
    fireEvent.keyDown(button, { key: "Enter" });
    fireEvent.keyDown(button, { key: " " });
    expect(onClick).toHaveBeenCalledTimes(2);
  });

  it("sets aria-current=page and renders the 2px active indicator when active", () => {
    render(
      <NavRowButton
        label="Monitor"
        sigil={sigil}
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
        sigil={sigil}
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
        sigil={sigil}
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
        sigil={sigil}
        tone="gold"
        active={true}
        running={true}
        onClick={() => {}}
      />,
    );
    expect(screen.getByTestId("nav-running-dot").style.background).toBe("var(--gold)");
  });
});

describe("NavIconButton", () => {
  it("renders an accessible button labeled by the app and fires onClick", () => {
    const onClick = vi.fn();
    render(
      <NavIconButton
        label="Settings"
        sigil={sigil}
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
        sigil={sigil}
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
        sigil={sigil}
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
        sigil={sigil}
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
        sigil={sigil}
        tone="gold"
        active={false}
        running={false}
        onClick={() => {}}
      />,
    );
    fireEvent.focus(screen.getByRole("button"));
    expect(screen.getByRole("tooltip").textContent).toContain("Monitor");
  });
});

describe("Tooltip", () => {
  it("renders the label and optional kbd hint", () => {
    render(<Tooltip label="Search" kbd="⌘ K" />);
    const tip = screen.getByRole("tooltip");
    expect(tip.textContent).toContain("Search");
    expect(tip.textContent).toContain("⌘ K");
  });
});
