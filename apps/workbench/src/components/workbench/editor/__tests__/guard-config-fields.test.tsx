import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { GuardConfigFields } from "../guard-config-fields";

describe("GuardConfigFields pattern list editor", () => {
  it("accepts glob-style entries for path-based guards", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();

    render(
      <GuardConfigFields
        guardId="forbidden_path"
        config={{ patterns: [] }}
        onChange={onChange}
      />,
    );

    await user.type(screen.getByLabelText("Add forbidden patterns..."), "**/*.pem{enter}");

    expect(onChange).toHaveBeenCalledWith("patterns", ["**/*.pem"]);
  });

  it("preserves intermediate invalid regex states for regex-backed pattern lists", async () => {
    const onChange = vi.fn();

    render(
      <GuardConfigFields
        guardId="shell_command"
        config={{ forbidden_patterns: [] }}
        onChange={onChange}
      />,
    );

    const input = screen.getByLabelText("Add forbidden patterns...");
    fireEvent.change(input, { target: { value: "[unterminated" } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(onChange).toHaveBeenCalledWith("forbidden_patterns", ["[unterminated"]);
  });
});
