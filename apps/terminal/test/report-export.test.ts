import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import * as fs from "node:fs/promises"
import * as os from "node:os"
import * as path from "node:path"
import type { HuntReport } from "../src/hunt/types"
import {
  buildReportExportAuditEvent,
  deriveTraceMetadata,
  exportReportBundle,
  readReportHistory,
  renderReportMarkdown,
} from "../src/tui/report-export"

let tempDir: string

function sampleReport(): HuntReport {
  return {
    id: "investigation-abc123",
    title: "Export Trace Test",
    severity: "high",
    created_at: new Date("2026-03-05T12:00:00Z").toISOString(),
    alert: {
      rule: "investigation:timeline",
      severity: "high",
      timestamp: new Date("2026-03-05T12:00:00Z").toISOString(),
      title: "Export Trace Test",
      matched_events: [
        {
          timestamp: new Date("2026-03-05T12:00:00Z").toISOString(),
          source: "receipt",
          kind: "policy_violation",
          verdict: "deny",
          summary: "Denied write to secrets file",
          details: {
            receipt_id: "rcpt-123",
            audit_id: "audit-789",
            session_id: "sess-456",
            path: "/tmp/secrets.env",
          },
        },
      ],
      evidence: {},
    },
    evidence: [
      {
        index: 1,
        relevance: "blocked action",
        event: {
          timestamp: new Date("2026-03-05T12:00:00Z").toISOString(),
          source: "receipt",
          kind: "policy_violation",
          verdict: "deny",
          summary: "Denied write to secrets file",
          details: {
            receipt_id: "rcpt-123",
            audit_id: "audit-789",
            session_id: "sess-456",
            path: "/tmp/secrets.env",
          },
        },
        merkle_proof: ["abc"],
      },
    ],
    merkle_root: "root-123",
    summary: "Ready for trace metadata export.",
    recommendations: ["Review the denied write before allowing the workflow."],
  }
}

beforeEach(async () => {
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-report-export-"))
})

afterEach(async () => {
  await fs.rm(tempDir, { recursive: true, force: true })
})

describe("report export trace metadata", () => {
  test("derives receipt and audit references from evidence details", () => {
    const trace = deriveTraceMetadata(sampleReport())

    expect(trace.eventSources).toEqual(["receipt"])
    expect(trace.receiptIds).toEqual(["rcpt-123"])
    expect(trace.auditEventIds).toEqual(["audit-789"])
    expect(trace.sessionIds).toEqual(["sess-456"])
  })

  test("writes export history with trace references", async () => {
    const result = await exportReportBundle(sampleReport(), tempDir)
    const history = await readReportHistory(tempDir)

    expect(history).toHaveLength(1)
    expect(history[0].jsonPath).toBe(result.historyEntry.jsonPath)
    expect(history[0].trace.receiptIds).toEqual(["rcpt-123"])
    expect(history[0].trace.auditEventIds).toEqual(["audit-789"])
    expect(history[0].investigationOrigin).toBe("timeline")
    expect(history[0].traceability.auditStatus).toBe("not_configured")
    expect(history[0].traceability.exportAuditEventId).toBeTruthy()
  })

  test("renders trace metadata into markdown handoff output", () => {
    const markdown = renderReportMarkdown(sampleReport())

    expect(markdown).toContain("## Trace Metadata")
    expect(markdown).toContain("Receipt IDs: rcpt-123")
    expect(markdown).toContain("Audit Event IDs: audit-789")
    expect(markdown).toContain("Session IDs: sess-456")
  })

  test("builds a report export audit event with shared trace identifiers", async () => {
    const result = await exportReportBundle(sampleReport(), tempDir)
    const event = buildReportExportAuditEvent(sampleReport(), result.historyEntry)

    expect(event.id).toBe(result.historyEntry.traceability.exportAuditEventId)
    expect(event.event_type).toBe("report_export")
    expect(event.action_type).toBe("report_export")
    expect(event.decision).toBe("allowed")
    expect((event.metadata as Record<string, unknown>).receipt_ids).toEqual(["rcpt-123"])
  })
})
