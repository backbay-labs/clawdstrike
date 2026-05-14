export function characterOffsetToCodeUnitIndex(
  value: string,
  characterOffset: number,
): number {
  const boundedOffset = Math.max(characterOffset, 0);
  let codeUnitIndex = 0;
  let seenCharacters = 0;

  for (const character of value) {
    if (seenCharacters >= boundedOffset) {
      return codeUnitIndex;
    }

    codeUnitIndex += character.length;
    seenCharacters += 1;
  }

  return value.length;
}

export function getLineTextAt(value: string, lineNumber: number): string | null {
  if (lineNumber < 1) {
    return null;
  }

  return value.split(/\r?\n/)[lineNumber - 1] ?? null;
}
