export function getWorkbenchAppBridgeTarget(
  pathname: string,
  appIds: readonly string[],
): string | null {
  const segments = pathname.split("/").filter(Boolean);
  if (segments.length !== 1) return null;
  const [appId] = segments;
  return appIds.includes(appId) ? appId : null;
}
