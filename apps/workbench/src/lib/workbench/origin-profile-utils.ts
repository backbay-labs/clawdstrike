import type { SavedPolicy, WorkbenchPolicy } from "./types";
import { policyToYaml } from "./yaml-utils";

export function renameOriginProfileIdInPolicy(
  policy: WorkbenchPolicy,
  oldId: string,
  newId: string,
): WorkbenchPolicy | null {
  const profiles = policy.origins?.profiles;
  if (!profiles?.some((profile) => profile.id === oldId)) {
    return null;
  }

  const updatedProfiles = profiles.map((profile) =>
    profile.id === oldId ? { ...profile, id: newId } : profile,
  );

  return {
    ...policy,
    origins: {
      ...policy.origins!,
      profiles: updatedProfiles,
    },
  };
}

export function renameOriginProfileIdInSavedPolicy(
  savedPolicy: SavedPolicy,
  oldId: string,
  newId: string,
  updatedAt: string,
): SavedPolicy | null {
  const updatedPolicy = renameOriginProfileIdInPolicy(savedPolicy.policy, oldId, newId);
  if (!updatedPolicy) {
    return null;
  }

  return {
    ...savedPolicy,
    policy: updatedPolicy,
    yaml: policyToYaml(updatedPolicy),
    updatedAt,
  };
}
