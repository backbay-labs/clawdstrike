import { render, screen, waitFor } from "@testing-library/react";
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

  it("keeps custom provider inputs in custom mode when cleared", async () => {
    const user = userEvent.setup();
    activePolicy = {
      ...activePolicy,
      origins: {
        ...activePolicy.origins,
        profiles: [makeProfile(undefined, { provider: "custom-provider" })],
      },
    };

    render(<OriginEditor />);

    await user.click(screen.getByText("profile-alpha"));

    const providerInput = await screen.findByPlaceholderText(
      "e.g. my-custom-provider",
    );
    await user.clear(providerInput);

    expect(dispatch).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: "UPDATE_ORIGINS",
        origins: expect.objectContaining({
          profiles: [
            expect.objectContaining({
              match_rules: expect.objectContaining({ provider: "" }),
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

    render(<OriginEditor />);

    await user.click(screen.getByText("profile-alpha"));

    const spaceTypeInput = await screen.findByPlaceholderText(
      "e.g. my-custom-space",
    );
    await user.clear(spaceTypeInput);

    expect(dispatch).toHaveBeenLastCalledWith(
      expect.objectContaining({
        type: "UPDATE_ORIGINS",
        origins: expect.objectContaining({
          profiles: [
            expect.objectContaining({
              match_rules: expect.objectContaining({ space_type: "" }),
            }),
          ],
        }),
      }),
    );
  });
});
