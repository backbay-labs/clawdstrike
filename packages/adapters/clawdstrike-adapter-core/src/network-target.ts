export interface ParseNetworkTargetOptions {
  /**
   * Port to use when parsing fails closed (for hostless/invalid targets).
   *
   * Use `'default'` to keep protocol default behavior (80 for http, else 443).
   */
  emptyPort?: number | 'default';
}

export interface ParsedNetworkTarget {
  host: string;
  port: number;
  url: string;
}

function resolveEmptyPort(
  defaultPort: number,
  emptyPort: ParseNetworkTargetOptions['emptyPort'],
): number {
  if (emptyPort === 'default') {
    return defaultPort;
  }
  return emptyPort ?? 0;
}

export function parseNetworkTarget(
  input: string,
  options: ParseNetworkTargetOptions = {},
): ParsedNetworkTarget {
  const trimmed = input.trim();
  if (!trimmed) {
    const port = options.emptyPort === 'default' ? 443 : options.emptyPort ?? 0;
    return { host: '', port, url: '' };
  }

  const schemeSep = trimmed.indexOf('://');
  const scheme = schemeSep === -1 ? '' : trimmed.slice(0, schemeSep).toLowerCase();
  const defaultPort = scheme === 'http' ? 80 : 443;
  const emptyPort = resolveEmptyPort(defaultPort, options.emptyPort);

  const withoutScheme = schemeSep === -1 ? trimmed : trimmed.slice(schemeSep + 3);
  const end = withoutScheme.search(/[/?#]/);
  const hostPortRaw = end === -1 ? withoutScheme : withoutScheme.slice(0, end);

  if (schemeSep !== -1 && hostPortRaw.length === 0) {
    // Hostless URIs (file/mailto/data/...) are not valid egress targets; fail closed.
    return { host: '', port: emptyPort, url: trimmed };
  }

  // Bare userinfo-like values are not valid egress targets.
  if (schemeSep === -1 && hostPortRaw.includes('@')) {
    return { host: '', port: emptyPort, url: trimmed };
  }

  const atIndex = hostPortRaw.lastIndexOf('@');
  const hostPort = atIndex === -1 ? hostPortRaw : hostPortRaw.slice(atIndex + 1);

  if (!hostPort) {
    return { host: '', port: emptyPort, url: trimmed };
  }

  // IPv6: [::1]:443
  if (hostPort.startsWith('[')) {
    const close = hostPort.indexOf(']');
    if (close !== -1) {
      const host = hostPort.slice(1, close);
      if (!host) {
        return { host: '', port: emptyPort, url: trimmed };
      }
      const rest = hostPort.slice(close + 1);
      if (rest.startsWith(':')) {
        const parsedPort = Number.parseInt(rest.slice(1), 10);
        if (Number.isFinite(parsedPort) && parsedPort > 0 && parsedPort <= 65535) {
          return { host, port: parsedPort, url: trimmed };
        }
      }
      return { host, port: defaultPort, url: trimmed };
    }
  }

  const lastColon = hostPort.lastIndexOf(':');
  const hasSingleColon = lastColon > 0 && hostPort.indexOf(':') === lastColon;
  if (hasSingleColon) {
    const host = hostPort.slice(0, lastColon);
    const portText = hostPort.slice(lastColon + 1);

    if (/^[0-9]+$/.test(portText)) {
      const parsedPort = Number.parseInt(portText, 10);
      if (Number.isFinite(parsedPort) && parsedPort > 0 && parsedPort <= 65535) {
        return { host, port: parsedPort, url: trimmed };
      }

      // Drop invalid numeric port suffix before returning host.
      return { host, port: defaultPort, url: trimmed };
    }

    // Single-colon but non-numeric suffix (e.g. `mailto:user@example.com`): fail closed.
    return { host: '', port: emptyPort, url: trimmed };
  }

  // Multi-colon hostless URI-like targets (e.g. `urn:isbn:...`) are not network hosts.
  if (schemeSep === -1 && hostPort.includes(':')) {
    return { host: '', port: emptyPort, url: trimmed };
  }

  return { host: hostPort, port: defaultPort, url: trimmed };
}
