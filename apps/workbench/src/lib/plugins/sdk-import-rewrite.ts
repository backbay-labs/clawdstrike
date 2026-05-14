const SDK_IMPORT_RE =
  /import\s+(?:type\s+)?(?:\{[^}]*\}|\*\s+as\s+\w+)\s+from\s*['"]@clawdstrike\/plugin-sdk(?:\/[^'"]+)?['"];?\s*/gs;

function normalizeNamedImportSpecifier(specifier: string): string | null {
  const trimmed = specifier.trim();
  if (!trimmed) {
    return null;
  }

  if (/^type\s+/.test(trimmed)) {
    return null;
  }

  const withoutTypePrefix = trimmed;
  const aliasedMatch = withoutTypePrefix.match(
    /^([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)$/,
  );
  if (aliasedMatch) {
    return `${aliasedMatch[1]}: ${aliasedMatch[2]}`;
  }

  return withoutTypePrefix;
}

export function rewritePluginSdkImports(
  source: string,
  sdkGlobalRef = "window.__CLAWDSTRIKE_PLUGIN_SDK__",
): string {
  return source.replace(SDK_IMPORT_RE, (match) => {
    if (/^import\s+type\s/.test(match)) {
      return "";
    }

    const namespaceMatch = match.match(/import\s+\*\s+as\s+(\w+)/);
    if (namespaceMatch) {
      return `const ${namespaceMatch[1]} = ${sdkGlobalRef};\n`;
    }

    const namedMatch = match.match(/import\s*\{([^}]+)\}/s);
    if (namedMatch) {
      const names = namedMatch[1]
        .split(",")
        .map(normalizeNamedImportSpecifier)
        .filter((name): name is string => Boolean(name));
      return names.length > 0
        ? `const { ${names.join(", ")} } = ${sdkGlobalRef};\n`
        : "";
    }

    return match;
  });
}
