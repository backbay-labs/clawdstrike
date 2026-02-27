/**
 * Probe a remote engine health endpoint.
 *
 * Returns true if the remote responds with an OK status within the timeout,
 * false on any error (network failure, non-OK status, timeout).
 */
export async function probeRemoteEngine(
  url: string,
  timeoutMs: number,
): Promise<boolean> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  // Prevent the timeout from keeping the process alive in Node.
  if (typeof timeoutId === 'object' && 'unref' in timeoutId) {
    (timeoutId as NodeJS.Timeout).unref();
  }

  try {
    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
    });
    return response.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timeoutId);
  }
}
