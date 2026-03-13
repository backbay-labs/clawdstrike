import { describe, expect, it } from "vitest";

import type { SavedPolicy, WorkbenchPolicy } from "../types";
import {
  renameOriginProfileIdInPolicy,
  renameOriginProfileIdInSavedPolicy,
} from "../origin-profile-utils";
import { policyToYaml } from "../yaml-utils";

function makePolicy(): WorkbenchPolicy {
  return {
    version: "1.4.0",
    name: "Origin Policy",
    description: "Origin profile test policy",
    guards: {},
    settings: {},
    origins: {
      default_behavior: "deny",
      profiles: [
        {
          id: "profile-old",
          match_rules: { provider: "slack", thread_id: "thread-1" },
          metadata: { channel: "eng-alerts" },
        },
      ],
    },
  };
}

function makeSavedPolicy(policy: WorkbenchPolicy): SavedPolicy {
  return {
    id: "saved-policy-1",
    policy,
    yaml: policyToYaml(policy),
    createdAt: "2026-03-11T00:00:00.000Z",
    updatedAt: "2026-03-11T00:00:00.000Z",
  };
}

describe("origin-profile-utils", () => {
  it("renames a referenced profile id inside a policy", () => {
    const updated = renameOriginProfileIdInPolicy(makePolicy(), "profile-old", "profile-new");

    expect(updated?.origins?.profiles[0]?.id).toBe("profile-new");
  });

  it("rebuilds saved-policy yaml after renaming a referenced profile id", () => {
    const saved = makeSavedPolicy(makePolicy());

    const updated = renameOriginProfileIdInSavedPolicy(
      saved,
      "profile-old",
      "profile-new",
      "2026-03-12T00:00:00.000Z",
    );

    expect(updated).not.toBeNull();
    expect(updated?.policy.origins?.profiles[0]?.id).toBe("profile-new");
    expect(updated?.yaml).toContain("profile-new");
    expect(updated?.yaml).not.toContain("profile-old");
    expect(updated?.updatedAt).toBe("2026-03-12T00:00:00.000Z");
  });

  it("returns null when the requested profile id is not referenced", () => {
    const updated = renameOriginProfileIdInSavedPolicy(
      makeSavedPolicy(makePolicy()),
      "missing-profile",
      "profile-new",
      "2026-03-12T00:00:00.000Z",
    );

    expect(updated).toBeNull();
  });
});
