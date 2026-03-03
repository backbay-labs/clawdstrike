// hunt/mitre.ts - MITRE ATT&CK mapping engine
//
// Maps timeline events to MITRE ATT&CK techniques based on event
// kind/summary pattern matching. Produces a coverage matrix for
// the heatmap screen.

import type { TimelineEvent } from "./types"

export interface MitreMapping {
  tactic: string
  technique_id: string
  technique_name: string
  pattern: RegExp
}

export const MITRE_MAPPINGS: MitreMapping[] = [
  // Initial Access
  { tactic: "Initial Access", technique_id: "T1190", technique_name: "Exploit Public-Facing Application", pattern: /network_connect|exploit/i },
  { tactic: "Initial Access", technique_id: "T1566", technique_name: "Phishing", pattern: /phish|email.*attach/i },
  // Execution
  { tactic: "Execution", technique_id: "T1059", technique_name: "Command and Scripting Interpreter", pattern: /process_exec|shell|bash|cmd|powershell/i },
  { tactic: "Execution", technique_id: "T1204", technique_name: "User Execution", pattern: /user.*exec|click|open/i },
  { tactic: "Execution", technique_id: "T1106", technique_name: "Native API", pattern: /mcp.*tool|api.*call/i },
  // Persistence
  { tactic: "Persistence", technique_id: "T1547", technique_name: "Boot or Logon Autostart", pattern: /autostart|startup|cron|systemd/i },
  { tactic: "Persistence", technique_id: "T1053", technique_name: "Scheduled Task/Job", pattern: /cron|schedule|task.*sched/i },
  // Privilege Escalation
  { tactic: "Privilege Escalation", technique_id: "T1548", technique_name: "Abuse Elevation Control", pattern: /sudo|setuid|elevation|privilege/i },
  // Defense Evasion
  { tactic: "Defense Evasion", technique_id: "T1070", technique_name: "Indicator Removal", pattern: /delete.*log|clear.*history|file_delete.*log/i },
  { tactic: "Defense Evasion", technique_id: "T1036", technique_name: "Masquerading", pattern: /masquerad|rename.*proc/i },
  { tactic: "Defense Evasion", technique_id: "T1562", technique_name: "Impair Defenses", pattern: /policy_violation|guard.*bypass|deny.*override/i },
  // Credential Access
  { tactic: "Credential Access", technique_id: "T1003", technique_name: "OS Credential Dumping", pattern: /credential|passwd|shadow|secret/i },
  { tactic: "Credential Access", technique_id: "T1552", technique_name: "Unsecured Credentials", pattern: /\.env|api.key|token|secret.*leak/i },
  // Discovery
  { tactic: "Discovery", technique_id: "T1083", technique_name: "File and Directory Discovery", pattern: /file_open.*\/etc|ls.*-la|find.*\//i },
  { tactic: "Discovery", technique_id: "T1046", technique_name: "Network Service Discovery", pattern: /network.*scan|port.*scan|nmap/i },
  // Lateral Movement
  { tactic: "Lateral Movement", technique_id: "T1021", technique_name: "Remote Services", pattern: /ssh|rdp|remote.*desktop/i },
  // Collection
  { tactic: "Collection", technique_id: "T1005", technique_name: "Data from Local System", pattern: /file_open.*sensitive|read.*config/i },
  { tactic: "Collection", technique_id: "T1074", technique_name: "Data Staged", pattern: /stage|collect.*data|archive/i },
  // Exfiltration
  { tactic: "Exfiltration", technique_id: "T1048", technique_name: "Exfiltration Over Alternative Protocol", pattern: /exfil|dns.*tunnel|upload.*data/i },
  { tactic: "Exfiltration", technique_id: "T1041", technique_name: "Exfiltration Over C2 Channel", pattern: /c2|command.*control|beacon/i },
  // Command and Control
  { tactic: "Command and Control", technique_id: "T1071", technique_name: "Application Layer Protocol", pattern: /http.*beacon|dns.*c2|covert.*channel/i },
  // Impact
  { tactic: "Impact", technique_id: "T1485", technique_name: "Data Destruction", pattern: /rm\s+-rf|delete.*all|destroy|wipe/i },
  { tactic: "Impact", technique_id: "T1486", technique_name: "Data Encrypted for Impact", pattern: /encrypt|ransom/i },
]

/** Ordered unique list of tactics (kill-chain order) */
export const TACTICS: string[] = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Exfiltration",
  "Command and Control",
  "Impact",
]

/** Ordered unique list of technique IDs */
export const TECHNIQUES: string[] = (() => {
  const seen = new Set<string>()
  const result: string[] = []
  for (const m of MITRE_MAPPINGS) {
    if (!seen.has(m.technique_id)) {
      seen.add(m.technique_id)
      result.push(m.technique_id)
    }
  }
  return result
})()

export interface CoverageMatrix {
  tactics: string[]
  techniques: Array<{ id: string; name: string; tactic: string }>
  matrix: number[][] // [technique_idx][tactic_idx] = hit count
  eventsByTechnique: Map<string, TimelineEvent[]>
}

export function buildCoverageMatrix(events: TimelineEvent[]): CoverageMatrix {
  const tacticIndex = new Map<string, number>()
  for (let i = 0; i < TACTICS.length; i++) {
    tacticIndex.set(TACTICS[i], i)
  }

  // Build technique metadata
  const techniques: Array<{ id: string; name: string; tactic: string }> = []
  const techIdToIdx = new Map<string, number>()
  const seen = new Set<string>()
  for (const m of MITRE_MAPPINGS) {
    if (!seen.has(m.technique_id)) {
      seen.add(m.technique_id)
      techIdToIdx.set(m.technique_id, techniques.length)
      techniques.push({ id: m.technique_id, name: m.technique_name, tactic: m.tactic })
    }
  }

  // Initialize matrix: rows = techniques, cols = tactics
  const matrix: number[][] = []
  for (let t = 0; t < techniques.length; t++) {
    matrix.push(new Array(TACTICS.length).fill(0))
  }

  const eventsByTechnique = new Map<string, TimelineEvent[]>()

  for (const evt of events) {
    const matchStr = `${evt.kind} ${evt.summary}`
    for (const mapping of MITRE_MAPPINGS) {
      if (mapping.pattern.test(matchStr)) {
        const tIdx = techIdToIdx.get(mapping.technique_id)
        const cIdx = tacticIndex.get(mapping.tactic)
        if (tIdx !== undefined && cIdx !== undefined) {
          matrix[tIdx][cIdx]++
          const existing = eventsByTechnique.get(mapping.technique_id) ?? []
          existing.push(evt)
          eventsByTechnique.set(mapping.technique_id, existing)
        }
      }
    }
  }

  return { tactics: TACTICS, techniques, matrix, eventsByTechnique }
}
