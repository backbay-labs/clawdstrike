const ESC = "\u001b";
const BEL = "\u0007";

export interface TerminalPreviewChunkResult {
  lines: string[];
  carry: string;
}

function applyPlainTextControls(value: string): string {
  let next = "";

  for (const char of value) {
    if (char === "\b") {
      next = next.slice(0, -1);
      continue;
    }

    if (char === "\r") {
      next += "\n";
      continue;
    }

    if (char === "\n" || char === "\t") {
      next += char;
      continue;
    }

    const code = char.charCodeAt(0);
    if ((code >= 0 && code < 0x20) || code === 0x7f) {
      continue;
    }

    next += char;
  }

  return next;
}

function appendPlainCharacter(current: string, char: string): string {
  if (char === "\b") {
    return current.slice(0, -1);
  }

  if (char === "\r") {
    return `${current}\n`;
  }

  if (char === "\n" || char === "\t") {
    return `${current}${char}`;
  }

  const code = char.charCodeAt(0);
  if ((code >= 0 && code < 0x20) || code === 0x7f) {
    return current;
  }

  return `${current}${char}`;
}

function sanitizePreviewText(value: string): { text: string; carry: string } {
  const normalized = value.replace(/\r\n/g, "\n");
  let text = "";
  let carry = "";
  let state:
    | "normal"
    | "esc"
    | "escIntermediate"
    | "csi"
    | "osc"
    | "oscEsc"
    | "st"
    | "stEsc" = "normal";

  for (const char of normalized) {
    const code = char.charCodeAt(0);

    switch (state) {
      case "normal":
        if (char === ESC) {
          state = "esc";
          carry = ESC;
          continue;
        }
        if (char === "\u009b") {
          state = "csi";
          carry = char;
          continue;
        }
        if (char === "\u009d") {
          state = "osc";
          carry = char;
          continue;
        }
        text = appendPlainCharacter(text, char);
        continue;

      case "esc":
        carry += char;
        if (char === "[") {
          state = "csi";
          continue;
        }
        if (char === "]") {
          state = "osc";
          continue;
        }
        if (char === "P" || char === "^" || char === "_" || char === "X") {
          state = "st";
          continue;
        }
        if (code >= 0x20 && code <= 0x2f) {
          state = "escIntermediate";
          continue;
        }
        if (code >= 0x30 && code <= 0x7e) {
          carry = "";
          state = "normal";
        }
        continue;

      case "escIntermediate":
        carry += char;
        if (code >= 0x20 && code <= 0x2f) {
          continue;
        }
        if (code >= 0x30 && code <= 0x7e) {
          carry = "";
          state = "normal";
        }
        continue;

      case "csi":
        carry += char;
        if (code >= 0x40 && code <= 0x7e) {
          carry = "";
          state = "normal";
        }
        continue;

      case "osc":
        carry += char;
        if (char === BEL || char === "\u009c") {
          carry = "";
          state = "normal";
          continue;
        }
        if (char === ESC) {
          state = "oscEsc";
        }
        continue;

      case "oscEsc":
        carry += char;
        if (char === "\\") {
          carry = "";
          state = "normal";
        } else {
          state = "osc";
        }
        continue;

      case "st":
        carry += char;
        if (char === "\u009c") {
          carry = "";
          state = "normal";
          continue;
        }
        if (char === ESC) {
          state = "stEsc";
        }
        continue;

      case "stEsc":
        carry += char;
        if (char === "\\") {
          carry = "";
          state = "normal";
        } else {
          state = "st";
        }
        continue;
    }
  }

  if (state === "normal") {
    carry = "";
  }

  return { text, carry };
}

export function appendTerminalPreviewChunk(
  existing: string[] | undefined,
  chunk: string,
  options?: { carry?: string; maxLines?: number },
): TerminalPreviewChunkResult {
  const current = [...(existing ?? [])];
  const maxLines = options?.maxLines ?? Number.POSITIVE_INFINITY;
  const combined = `${options?.carry ?? ""}${chunk}`;
  const { text, carry } = sanitizePreviewText(combined);

  if (text.length === 0) {
    return { lines: current, carry };
  }

  const segments = text.split("\n");
  if (segments.length > 0) {
    const [first, ...rest] = segments;
    if (current.length > 0) {
      current[current.length - 1] = `${current[current.length - 1] ?? ""}${first}`;
    } else {
      current.push(first);
    }
    current.push(...rest);
  }

  if (current.length > maxLines) {
    current.splice(0, current.length - maxLines);
  }

  return { lines: current, carry };
}

export function sanitizeTerminalPreviewLines(
  lines: string[] | undefined,
  maxLines?: number,
): string[] {
  if (!lines || lines.length === 0) {
    return [];
  }

  const { text } = sanitizePreviewText(lines.join("\n"));
  if (text.length === 0) {
    return [];
  }

  const next = text.split("\n");
  if (maxLines && next.length > maxLines) {
    return next.slice(-maxLines);
  }

  return next;
}

export const __terminalPreviewInternals = {
  appendPlainCharacter,
  applyPlainTextControls,
  sanitizePreviewText,
  ESC,
  BEL,
};
