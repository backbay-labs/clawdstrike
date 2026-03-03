import type { TimelineEvent, Alert } from './types.js';

export interface MitreTechnique {
  id: string;
  tactic: string;
  name: string;
}

interface MitreMapping {
  pattern: RegExp;
  technique: MitreTechnique;
}

const MITRE_MAPPINGS: MitreMapping[] = [
  { pattern: /\/etc\/shadow/i, technique: { id: 'T1003.008', tactic: 'credential-access', name: 'OS Credential Dumping: /etc/passwd and /etc/shadow' } },
  { pattern: /\/etc\/passwd/i, technique: { id: 'T1003.008', tactic: 'credential-access', name: 'OS Credential Dumping: /etc/passwd and /etc/shadow' } },
  { pattern: /\.ssh\//i, technique: { id: 'T1552.004', tactic: 'credential-access', name: 'Unsecured Credentials: Private Keys' } },
  { pattern: /\.pem|\.key/i, technique: { id: 'T1552.004', tactic: 'credential-access', name: 'Unsecured Credentials: Private Keys' } },
  { pattern: /curl|wget/i, technique: { id: 'T1105', tactic: 'command-and-control', name: 'Ingress Tool Transfer' } },
  { pattern: /egress|exfil/i, technique: { id: 'T1041', tactic: 'exfiltration', name: 'Exfiltration Over C2 Channel' } },
  { pattern: /\/bin\/bash|\/bin\/sh|\/bin\/zsh/i, technique: { id: 'T1059.004', tactic: 'execution', name: 'Command and Scripting Interpreter: Unix Shell' } },
  { pattern: /powershell/i, technique: { id: 'T1059.001', tactic: 'execution', name: 'Command and Scripting Interpreter: PowerShell' } },
  { pattern: /python/i, technique: { id: 'T1059.006', tactic: 'execution', name: 'Command and Scripting Interpreter: Python' } },
  { pattern: /cron|crontab|at\s/i, technique: { id: 'T1053.003', tactic: 'persistence', name: 'Scheduled Task/Job: Cron' } },
  { pattern: /ssh\s|sshd|ssh-keygen/i, technique: { id: 'T1021.004', tactic: 'lateral-movement', name: 'Remote Services: SSH' } },
  { pattern: /dns|nslookup|dig\s/i, technique: { id: 'T1071.004', tactic: 'command-and-control', name: 'Application Layer Protocol: DNS' } },
  { pattern: /base64/i, technique: { id: 'T1140', tactic: 'defense-evasion', name: 'Deobfuscate/Decode Files or Information' } },
  { pattern: /chmod|chown/i, technique: { id: 'T1222.002', tactic: 'defense-evasion', name: 'File and Directory Permissions Modification: Linux and Mac' } },
  { pattern: /\.env|environment/i, technique: { id: 'T1082', tactic: 'discovery', name: 'System Information Discovery' } },
  { pattern: /whoami|id\s|uname/i, technique: { id: 'T1033', tactic: 'discovery', name: 'System Owner/User Discovery' } },
  { pattern: /netstat|ss\s|ifconfig|ip\s+addr/i, technique: { id: 'T1049', tactic: 'discovery', name: 'System Network Connections Discovery' } },
  { pattern: /ps\s|top\s|htop/i, technique: { id: 'T1057', tactic: 'discovery', name: 'Process Discovery' } },
  { pattern: /find\s|locate\s|ls\s/i, technique: { id: 'T1083', tactic: 'discovery', name: 'File and Directory Discovery' } },
  { pattern: /iptables|firewall/i, technique: { id: 'T1562.004', tactic: 'defense-evasion', name: 'Impair Defenses: Disable or Modify System Firewall' } },
  { pattern: /docker|kubectl|container/i, technique: { id: 'T1610', tactic: 'execution', name: 'Deploy Container' } },
  { pattern: /systemctl|service\s/i, technique: { id: 'T1543.002', tactic: 'persistence', name: 'Create or Modify System Process: Systemd Service' } },
  { pattern: /nc\s|ncat|netcat/i, technique: { id: 'T1095', tactic: 'command-and-control', name: 'Non-Application Layer Protocol' } },
  { pattern: /reverse.?shell|bind.?shell/i, technique: { id: 'T1059', tactic: 'execution', name: 'Command and Scripting Interpreter' } },
];

/**
 * Map a timeline event to matching MITRE ATT&CK techniques.
 * Matches against summary, process, and actionType fields.
 */
export function mapEventToMitre(event: TimelineEvent): MitreTechnique[] {
  const searchFields = [
    event.summary,
    event.process ?? '',
    event.actionType ?? '',
  ].join(' ');

  const seen = new Set<string>();
  const result: MitreTechnique[] = [];

  for (const mapping of MITRE_MAPPINGS) {
    if (mapping.pattern.test(searchFields)) {
      if (!seen.has(mapping.technique.id)) {
        seen.add(mapping.technique.id);
        result.push(mapping.technique);
      }
    }
  }

  return result;
}

/**
 * Map an alert to MITRE techniques, deduped across all evidence events.
 */
export function mapAlertToMitre(alert: Alert): MitreTechnique[] {
  const seen = new Set<string>();
  const result: MitreTechnique[] = [];

  for (const event of alert.evidence) {
    for (const technique of mapEventToMitre(event)) {
      if (!seen.has(technique.id)) {
        seen.add(technique.id);
        result.push(technique);
      }
    }
  }

  return result;
}

/**
 * Build a MITRE ATT&CK coverage matrix from alerts.
 * Groups techniques by tactic.
 */
export function coverageMatrix(alerts: Alert[]): Map<string, MitreTechnique[]> {
  const matrix = new Map<string, MitreTechnique[]>();

  for (const alert of alerts) {
    const techniques = mapAlertToMitre(alert);
    for (const tech of techniques) {
      const existing = matrix.get(tech.tactic) ?? [];
      if (!existing.some(t => t.id === tech.id)) {
        existing.push(tech);
        matrix.set(tech.tactic, existing);
      }
    }
  }

  return matrix;
}
