export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise<void>((resolve, reject) => {
    const timeoutId = setTimeout(() => resolve(), ms);
    timeoutId.unref?.();

    if (!signal) return;
    if (signal.aborted) {
      clearTimeout(timeoutId);
      reject(new Error('aborted'));
      return;
    }

    const onAbort = () => {
      clearTimeout(timeoutId);
      reject(new Error('aborted'));
    };
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

export async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  onTimeout: () => T,
): Promise<T> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return await promise;
  }

  let timeoutId: NodeJS.Timeout | undefined;
  const timer = new Promise<T>((resolve) => {
    timeoutId = setTimeout(() => resolve(onTimeout()), timeoutMs);
    timeoutId.unref?.();
  });

  try {
    return await Promise.race([promise, timer]);
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}

