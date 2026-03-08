const STORAGE_KEY = "sdr:feature:policy-workbench";

export function computePolicyWorkbenchEnabled(
  envValue: string | undefined,
  localValue: string | null,
): boolean {
  if (localValue === "1" || localValue === "true") return true;
  if (localValue === "0" || localValue === "false") return false;

  if (envValue === "1" || envValue === "true") return true;
  if (envValue === "0" || envValue === "false") return false;

  return true;
}

export function isPolicyWorkbenchEnabled(): boolean {
  let localValue: string | null = null;
  try {
    localValue = localStorage.getItem(STORAGE_KEY);
  } catch {
    // Ignore storage errors and fall back to env/default.
  }

  const envValue =
    (import.meta.env.VITE_POLICY_WORKBENCH as string | undefined) ??
    (import.meta.env.VITE_ENABLE_POLICY_WORKBENCH as string | undefined);

  return computePolicyWorkbenchEnabled(envValue, localValue);
}
