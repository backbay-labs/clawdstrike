function normalizeSeed(seed: number, fallback: number): number {
  return Math.abs(Math.floor(seed)) || fallback;
}

export function mulberry32(seed: number): () => number {
  let s = seed;
  return () => {
    s |= 0;
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function createSpaceStationSeed(posX: number, posZ: number): number {
  return normalizeSeed(Math.abs(posX * 1000 + posZ * 37), 42);
}
