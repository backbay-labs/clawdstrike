import { sanitizeErrorMessage } from "@/lib/plugins/threat-intel/sanitize-error";

export interface AbuseIPDBReportPayload {
  ip: string;
  categories: number[];
  comment: string;
}

export interface MispEventPayload {
  indicator: string;
  iocType: string;
  eventInfo: string;
  severity: "low" | "medium" | "high" | "critical";
}

export type ReportResult =
  | { success: true; data?: unknown; eventId?: string }
  | { success: false; error: string };

const IOC_TO_MISP_ATTR: Record<string, string> = {
  ip: "ip-dst",
  domain: "domain",
  sha256: "sha256",
  sha1: "sha1",
  md5: "md5",
  url: "url",
  email: "email-src",
};

/**
 * Maps an IOC type string to the corresponding MISP attribute type.
 * Falls back to "text" for unknown types.
 */
export function mapIocTypeToMispAttrType(iocType: string): string {
  return IOC_TO_MISP_ATTR[iocType] ?? "text";
}

function severityToMispThreatLevel(
  severity: MispEventPayload["severity"],
): number {
  switch (severity) {
    case "critical":
    case "high":
      return 1; // High
    case "medium":
      return 2; // Medium
    case "low":
      return 3; // Low
  }
}

const ABUSEIPDB_REPORT_URL = "https://api.abuseipdb.com/api/v2/report";

/**
 * Report a malicious IP to AbuseIPDB v2 API.
 *
 * @param payload - IP, abuse categories, and comment
 * @param apiKey - AbuseIPDB API key (sent via `Key` header)
 * @returns ReportResult with response data or error
 */
export async function reportToAbuseIPDB(
  payload: AbuseIPDBReportPayload,
  apiKey: string,
): Promise<ReportResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30_000);
  try {
    const response = await fetch(ABUSEIPDB_REPORT_URL, {
      method: "POST",
      headers: {
        Key: apiKey,
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        ip: payload.ip,
        categories: payload.categories.join(","),
        comment: payload.comment,
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const errorBody = await response.json().catch(() => null);
      const detail =
        errorBody?.errors?.[0]?.detail ??
        `${response.status} ${response.statusText}`;
      return { success: false, error: `AbuseIPDB report failed: ${detail}` };
    }

    const data = await response.json();
    return { success: true, data };
  } catch (err) {
    return {
      success: false,
      error: `AbuseIPDB report failed: ${sanitizeErrorMessage(err)}`,
    };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Report a malicious indicator to a MISP instance by creating an event.
 *
 * @param payload - Indicator value, type, event info, and severity
 * @param apiKey - MISP API key (sent via `Authorization` header)
 * @param baseUrl - MISP instance base URL (e.g., "https://misp.example.org")
 * @returns ReportResult with event ID or error
 */
export async function reportToMisp(
  payload: MispEventPayload,
  apiKey: string,
  baseUrl: string,
): Promise<ReportResult> {
  const url = `${baseUrl}/events/add`;
  const attrType = mapIocTypeToMispAttrType(payload.iocType);

  const body = {
    Event: {
      info: payload.eventInfo,
      distribution: 0, // Organization only
      threat_level_id: severityToMispThreatLevel(payload.severity),
      analysis: 2, // Completed
      Attribute: [
        {
          type: attrType,
          category: iocTypeToMispCategory(payload.iocType),
          value: payload.indicator,
        },
      ],
    },
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30_000);
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: apiKey,
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!response.ok) {
      const errorBody = await response.json().catch(() => null);
      const detail =
        errorBody?.message ?? `${response.status} ${response.statusText}`;
      return { success: false, error: `MISP report failed: ${detail}` };
    }

    const data = await response.json();
    const eventId = data?.Event?.id;
    return { success: true, eventId: eventId ? String(eventId) : undefined };
  } catch (err) {
    return { success: false, error: `MISP report failed: ${sanitizeErrorMessage(err)}` };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Maps an IOC type to a MISP attribute category.
 */
function iocTypeToMispCategory(iocType: string): string {
  switch (iocType) {
    case "ip":
    case "domain":
    case "url":
      return "Network activity";
    case "sha256":
    case "sha1":
    case "md5":
      return "Payload delivery";
    case "email":
      return "Payload delivery";
    default:
      return "Other";
  }
}
