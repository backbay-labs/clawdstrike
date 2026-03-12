import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { OriginMatch, OriginProfile } from "@/lib/workbench/types";
import { OriginEditor } from "../origin-editor";

const dispatch = vi.fn();

let activePolicy: {
  version: string;
  origins: {
    default_behavior: "deny";
    profiles: OriginProfile[];
  };
};

vi.mock("@/lib/workbench/multi-policy-store", () => ({
  useWorkbench: () => ({
    state: { activePolicy },
    dispatch,
  }),
}));

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

describe("OriginEditor", () => {
  beforeEach(() => {
    dispatch.mockReset();
    activePolicy = {
      version: "1.4.0",
      origins: {
        default_behavior: "deny",
        profiles: [makeProfile({ region: "us-east-1" })],
      },
    };
  });

  it("resyncs profile metadata text when the selected profile changes upstream", async () => {
    const user = userEvent.setup();
    const { rerender } = render(<OriginEditor />);

    await user.click(screen.getByText("profile-alpha"));

    const textarea = await screen.findByPlaceholderText('{"key": "value"}');
    expect(textarea).toHaveValue(
      JSON.stringify({ region: "us-east-1" }, null, 2),
    );

    activePolicy = {
      ...activePolicy,
      origins: {
        ...activePolicy.origins,
        profiles: [makeProfile({ region: "eu-west-1", posture: "restricted" })],
      },
    };

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
    const { rerender } = render(<OriginEditor />);

    await user.click(screen.getByText("profile-alpha"));

    const textarea = await screen.findByPlaceholderText('{"key": "value"}');
    fireEvent.change(textarea, {
      target: { value: '{\n  "region": "draft"\n}' },
    });

    activePolicy = {
      ...activePolicy,
      origins: {
        ...activePolicy.origins,
        profiles: [
          {
            ...activePolicy.origins.profiles[0],
            explanation: "updated elsewhere",
          },
        ],
      },
    };

    rerender(<OriginEditor />);

    expect(textarea).toHaveValue('{\n  "region": "draft"\n}');
  });

  it("keeps custom provider inputs in custom mode when cleared", async () => {
    const user = userEvent.setup();
    activePolicy = {
      ...activePolicy,
      origins: {
        ...activePolicy.origins,
        profiles: [makeProfile(undefined, { provider: "custom-provider" })],
      },
    };

    const { rerender } = render(<OriginEditor />);

    await user.click(screen.getByText("profile-alpha"));

    const providerInput = await screen.findByPlaceholderText(
      "e.g. my-custom-provider",
    );
    await user.clear(providerInput);
    expect(providerInput).toHaveValue("");

    expect(dispatch).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: "UPDATE_ORIGINS",
        origins: expect.objectContaining({
          profiles: [
            expect.objectContaining({
              match_rules: expect.not.objectContaining({ provider: expect.anything() }),
            }),
          ],
        }),
      }),
    );

    activePolicy = {
      ...activePolicy,
      origins: {
        ...activePolicy.origins,
        profiles: [makeProfile(undefined, {})],
      },
    };

    rerender(<OriginEditor />);

    expect(
      await screen.findByPlaceholderText("e.g. my-custom-provider"),
    ).toHaveValue("");
  });

  it("clears the stored provider when switching an existing provider to custom mode", async () => {
    const user = userEvent.setup();
    render(<OriginEditor />);

    await user.click(screen.getByText("profile-alpha"));
    await user.click(screen.getAllByRole("combobox")[1]);
    await user.click(screen.getByRole("option", { name: "Custom..." }));

    await waitFor(() => {
      expect(
        screen.getByPlaceholderText("e.g. my-custom-provider"),
      ).toHaveValue("slack");
    });

    expect(dispatch).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: "UPDATE_ORIGINS",
        origins: expect.objectContaining({
          profiles: [
            expect.objectContaining({
              match_rules: expect.not.objectContaining({
                provider: expect.anything(),
              }),
            }),
          ],
        }),
      }),
    );
  });

  it("keeps custom space type inputs in custom mode when cleared", async () => {
    const user = userEvent.setup();
    activePolicy = {
      ...activePolicy,
      origins: {
        ...activePolicy.origins,
        profiles: [makeProfile(undefined, { space_type: "custom-space" })],
      },
    };

    const { rerender } = render(<OriginEditor />);

    await user.click(screen.getByText("profile-alpha"));

    const spaceTypeInput = await screen.findByPlaceholderText(
      "e.g. my-custom-space",
    );
    await user.clear(spaceTypeInput);
    expect(spaceTypeInput).toHaveValue("");

    expect(dispatch).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: "UPDATE_ORIGINS",
        origins: expect.objectContaining({
          profiles: [
            expect.objectContaining({
              match_rules: expect.not.objectContaining({ space_type: expect.anything() }),
            }),
          ],
        }),
      }),
    );

    activePolicy = {
      ...activePolicy,
      origins: {
        ...activePolicy.origins,
        profiles: [makeProfile(undefined, {})],
      },
    };

    rerender(<OriginEditor />);

    expect(
      await screen.findByPlaceholderText("e.g. my-custom-space"),
    ).toHaveValue("");
  });

  it("clears the stored space type when switching an existing space type to custom mode", async () => {
    const user = userEvent.setup();
    activePolicy = {
      ...activePolicy,
      origins: {
        ...activePolicy.origins,
        profiles: [makeProfile(undefined, { provider: "slack", space_type: "channel" })],
      },
    };

    render(<OriginEditor />);

    await user.click(screen.getByText("profile-alpha"));
    await user.click(screen.getAllByRole("combobox")[2]);
    await user.click(screen.getByRole("option", { name: "Custom..." }));

    await waitFor(() => {
      expect(
        screen.getByPlaceholderText("e.g. my-custom-space"),
      ).toHaveValue("channel");
    });

    expect(dispatch).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: "UPDATE_ORIGINS",
        origins: expect.objectContaining({
          profiles: [
            expect.objectContaining({
              match_rules: expect.not.objectContaining({
                space_type: expect.anything(),
              }),
            }),
          ],
        }),
      }),
    );
  });
});
