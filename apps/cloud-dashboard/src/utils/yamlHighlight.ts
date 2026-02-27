/** Regex-based YAML syntax colorizer. Returns an HTML string with <span> tags. */
export function highlightYaml(yaml: string): string {
  return yaml
    .split("\n")
    .map((line) => {
      let escaped = line
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");

      // Comments
      if (/^\s*#/.test(escaped)) {
        return `<span style="color:var(--muted);opacity:0.5">${escaped}</span>`;
      }

      // Key: value lines
      const kvMatch = escaped.match(/^(\s*)([\w.@\-/]+)(:)(.*)/);
      if (kvMatch) {
        const [, indent, key, colon, rest] = kvMatch;
        const coloredKey = `<span style="color:var(--gold)">${key}</span>`;
        const coloredValue = colorizeValue(rest);
        return `${indent}${coloredKey}${colon}${coloredValue}`;
      }

      // List item values (- value)
      const listMatch = escaped.match(/^(\s*-\s+)(.*)/);
      if (listMatch) {
        const [, prefix, value] = listMatch;
        return `${prefix}${colorizeValue(value)}`;
      }

      return `<span style="color:rgba(229,231,235,0.85)">${escaped}</span>`;
    })
    .join("\n");
}

function colorizeValue(raw: string): string {
  const trimmed = raw.trim();

  // Inline comment
  const commentIdx = findInlineComment(raw);
  if (commentIdx >= 0) {
    const before = raw.slice(0, commentIdx);
    const comment = raw.slice(commentIdx);
    return `${colorizeValue(before)}<span style="color:var(--muted);opacity:0.5">${comment}</span>`;
  }

  // Quoted strings
  if (/^(&quot;|['"]).*(&quot;|['"])$/.test(trimmed)) {
    return `<span style="color:var(--text)">${raw}</span>`;
  }

  // Booleans
  if (/^(true|false|yes|no|on|off)$/i.test(trimmed)) {
    return `<span style="color:var(--teal)">${raw}</span>`;
  }

  // Numbers
  if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
    return `<span style="color:var(--teal)">${raw}</span>`;
  }

  // Null
  if (/^(null|~)$/i.test(trimmed)) {
    return `<span style="color:var(--muted)">${raw}</span>`;
  }

  return `<span style="color:rgba(229,231,235,0.85)">${raw}</span>`;
}

function findInlineComment(raw: string): number {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === "&" && raw.slice(i, i + 6) === "&quot;" && !inSingle) {
      inDouble = !inDouble;
      i += 5; // skip past &quot;
    }
    else if (ch === "#" && !inSingle && !inDouble && i > 0 && raw[i - 1] === " ") {
      return i;
    }
  }
  return -1;
}
