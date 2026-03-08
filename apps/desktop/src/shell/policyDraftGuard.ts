export function appIdFromPath(pathname: string): string {
  const segment = pathname.split("/").filter(Boolean)[0] ?? "";
  return segment.split(/[?#]/)[0] ?? "";
}

export function shouldBlockDirtyPolicyDraftExit(params: {
  hasDirtyDraft: boolean;
  currentPathname: string;
  nextPathname: string;
}): boolean {
  if (!params.hasDirtyDraft) return false;
  const fromApp = appIdFromPath(params.currentPathname);
  const toApp = appIdFromPath(params.nextPathname);
  return fromApp === "nexus" && toApp !== "nexus";
}
