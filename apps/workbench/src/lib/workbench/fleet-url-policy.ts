function parseIpv4Bytes(hostname: string): number[] | null {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) return null;
  const octets = hostname.split(".").map((part) => Number.parseInt(part, 10));
  if (octets.some((part) => Number.isNaN(part) || part < 0 || part > 255)) return null;
  return octets;
}

function isPrivateOrLoopbackIpv4(octets: number[]): boolean {
  const [a, b, c, d] = octets;
  if ([a, b, c, d].some((part) => part === undefined)) return false;

  return (
    a === 127 ||
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 0 && b === 0 && c === 0 && d === 0)
  );
}

function parseIpv6Bytes(hostname: string): number[] | null {
  let normalized = hostname.toLowerCase();
  if (normalized.startsWith("[") && normalized.endsWith("]")) {
    normalized = normalized.slice(1, -1);
  }

  const zoneIndex = normalized.indexOf("%");
  if (zoneIndex >= 0) {
    normalized = normalized.slice(0, zoneIndex);
  }

  if (!normalized.includes(":")) return null;

  const lastColon = normalized.lastIndexOf(":");
  const maybeIpv4 = lastColon >= 0 ? normalized.slice(lastColon + 1) : "";
  if (maybeIpv4.includes(".")) {
    const ipv4Bytes = parseIpv4Bytes(maybeIpv4);
    if (!ipv4Bytes) return null;
    const high = ((ipv4Bytes[0] << 8) | ipv4Bytes[1]).toString(16);
    const low = ((ipv4Bytes[2] << 8) | ipv4Bytes[3]).toString(16);
    normalized = `${normalized.slice(0, lastColon)}:${high}:${low}`;
  }

  if ((normalized.match(/::/g) || []).length > 1) return null;

  const hasCompression = normalized.includes("::");
  const [leftRaw, rightRaw = ""] = normalized.split("::");
  const leftParts = leftRaw ? leftRaw.split(":").filter(Boolean) : [];
  const rightParts = rightRaw ? rightRaw.split(":").filter(Boolean) : [];
  const parts = [...leftParts, ...rightParts];

  if (parts.some((part) => !/^[0-9a-f]{1,4}$/i.test(part))) {
    return null;
  }

  const missing = 8 - parts.length;
  if ((!hasCompression && parts.length !== 8) || (hasCompression && missing < 0)) {
    return null;
  }

  const hextets = hasCompression
    ? [...leftParts, ...Array.from({ length: missing }, () => "0"), ...rightParts]
    : parts;

  if (hextets.length !== 8) return null;

  return hextets.flatMap((part) => {
    const value = Number.parseInt(part, 16);
    return [(value >> 8) & 0xff, value & 0xff];
  });
}

export function isPrivateOrLoopbackFleetHostname(hostname: string): boolean {
  const ipv4Bytes = parseIpv4Bytes(hostname);
  if (ipv4Bytes) {
    return isPrivateOrLoopbackIpv4(ipv4Bytes);
  }

  const ipv6Bytes = parseIpv6Bytes(hostname);
  if (!ipv6Bytes) return false;

  const isAllZero = ipv6Bytes.every((part) => part === 0);
  if (isAllZero) return true;

  const isLoopback =
    ipv6Bytes.slice(0, 15).every((part) => part === 0) && ipv6Bytes[15] === 1;
  if (isLoopback) return true;

  const isUniqueLocal = (ipv6Bytes[0] & 0xfe) === 0xfc;
  if (isUniqueLocal) return true;

  const isLinkLocal = ipv6Bytes[0] === 0xfe && (ipv6Bytes[1] & 0xc0) === 0x80;
  if (isLinkLocal) return true;

  const isIpv4Mapped =
    ipv6Bytes.slice(0, 10).every((part) => part === 0) &&
    ipv6Bytes[10] === 0xff &&
    ipv6Bytes[11] === 0xff;
  const isIpv4Compatible = ipv6Bytes.slice(0, 12).every((part) => part === 0);
  if (isIpv4Mapped || isIpv4Compatible) {
    return isPrivateOrLoopbackIpv4(ipv6Bytes.slice(12));
  }

  return false;
}

export function validateFleetUrl(
  url: string,
): { valid: true; tlsWarning?: string } | { valid: false; reason: string } {
  const normalizedUrl = url.trim();
  if (!normalizedUrl) {
    return { valid: false, reason: "URL must not be empty" };
  }

  let parsed: URL;
  try {
    parsed = new URL(normalizedUrl);
  } catch {
    return { valid: false, reason: "Invalid URL format" };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return {
      valid: false,
      reason: `Unsupported URL scheme "${parsed.protocol}" — only http: and https: are allowed`,
    };
  }

  if (parsed.username || parsed.password) {
    return { valid: false, reason: "URLs must not include embedded credentials" };
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (!import.meta.env.DEV) {
    if (hostname === "localhost") {
      return { valid: false, reason: "localhost URLs are not allowed in production" };
    }
    if (isPrivateOrLoopbackFleetHostname(hostname)) {
      return {
        valid: false,
        reason: "Private/loopback IP addresses are not allowed in production",
      };
    }
  }

  if (parsed.protocol === "http:" && hostname !== "localhost" && hostname !== "127.0.0.1") {
    return {
      valid: true,
      tlsWarning:
        "Connection is using unencrypted HTTP. Use HTTPS in production to protect credentials in transit.",
    };
  }

  return { valid: true };
}
