type CryptoLike = {
  randomUUID?: () => string;
  getRandomValues?: (array: Uint8Array) => Uint8Array;
};

function getCrypto(): CryptoLike | undefined {
  return (globalThis as unknown as { crypto?: CryptoLike }).crypto;
}

export function createId(prefix: string): string {
  const crypto = getCrypto();

  if (crypto?.randomUUID) {
    return `${prefix}-${crypto.randomUUID()}`;
  }

  if (crypto?.getRandomValues) {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    return `${prefix}-${hex}`;
  }

  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

