"""MITRE ATT&CK technique mapping for hunt events and alerts."""

from __future__ import annotations

import re
from dataclasses import dataclass

from clawdstrike.hunt.types import Alert, TimelineEvent


@dataclass(frozen=True)
class MitreTechnique:
    """A MITRE ATT&CK technique reference."""

    id: str
    tactic: str
    name: str


_MITRE_MAPPINGS: list[tuple[re.Pattern[str], MitreTechnique]] = [
    (re.compile(r"/etc/shadow", re.IGNORECASE), MitreTechnique(id="T1003.008", tactic="credential-access", name="OS Credential Dumping: /etc/passwd and /etc/shadow")),
    (re.compile(r"/etc/passwd", re.IGNORECASE), MitreTechnique(id="T1003.008", tactic="credential-access", name="OS Credential Dumping: /etc/passwd and /etc/shadow")),
    (re.compile(r"\.ssh/", re.IGNORECASE), MitreTechnique(id="T1552.004", tactic="credential-access", name="Unsecured Credentials: Private Keys")),
    (re.compile(r"\.pem|\.key", re.IGNORECASE), MitreTechnique(id="T1552.004", tactic="credential-access", name="Unsecured Credentials: Private Keys")),
    (re.compile(r"curl|wget", re.IGNORECASE), MitreTechnique(id="T1105", tactic="command-and-control", name="Ingress Tool Transfer")),
    (re.compile(r"egress|exfil", re.IGNORECASE), MitreTechnique(id="T1041", tactic="exfiltration", name="Exfiltration Over C2 Channel")),
    (re.compile(r"/bin/bash|/bin/sh|/bin/zsh", re.IGNORECASE), MitreTechnique(id="T1059.004", tactic="execution", name="Command and Scripting Interpreter: Unix Shell")),
    (re.compile(r"powershell", re.IGNORECASE), MitreTechnique(id="T1059.001", tactic="execution", name="Command and Scripting Interpreter: PowerShell")),
    (re.compile(r"python", re.IGNORECASE), MitreTechnique(id="T1059.006", tactic="execution", name="Command and Scripting Interpreter: Python")),
    (re.compile(r"cron|crontab|at\s", re.IGNORECASE), MitreTechnique(id="T1053.003", tactic="persistence", name="Scheduled Task/Job: Cron")),
    (re.compile(r"ssh\s|sshd|ssh-keygen", re.IGNORECASE), MitreTechnique(id="T1021.004", tactic="lateral-movement", name="Remote Services: SSH")),
    (re.compile(r"dns|nslookup|dig\s", re.IGNORECASE), MitreTechnique(id="T1071.004", tactic="command-and-control", name="Application Layer Protocol: DNS")),
    (re.compile(r"base64", re.IGNORECASE), MitreTechnique(id="T1140", tactic="defense-evasion", name="Deobfuscate/Decode Files or Information")),
    (re.compile(r"chmod|chown", re.IGNORECASE), MitreTechnique(id="T1222.002", tactic="defense-evasion", name="File and Directory Permissions Modification: Linux and Mac")),
    (re.compile(r"\.env|environment", re.IGNORECASE), MitreTechnique(id="T1082", tactic="discovery", name="System Information Discovery")),
    (re.compile(r"whoami|id\s|uname", re.IGNORECASE), MitreTechnique(id="T1033", tactic="discovery", name="System Owner/User Discovery")),
    (re.compile(r"netstat|ss\s|ifconfig|ip\s+addr", re.IGNORECASE), MitreTechnique(id="T1049", tactic="discovery", name="System Network Connections Discovery")),
    (re.compile(r"ps\s|top\s|htop", re.IGNORECASE), MitreTechnique(id="T1057", tactic="discovery", name="Process Discovery")),
    (re.compile(r"find\s|locate\s|ls\s", re.IGNORECASE), MitreTechnique(id="T1083", tactic="discovery", name="File and Directory Discovery")),
    (re.compile(r"iptables|firewall", re.IGNORECASE), MitreTechnique(id="T1562.004", tactic="defense-evasion", name="Impair Defenses: Disable or Modify System Firewall")),
    (re.compile(r"docker|kubectl|container", re.IGNORECASE), MitreTechnique(id="T1610", tactic="execution", name="Deploy Container")),
    (re.compile(r"systemctl|service\s", re.IGNORECASE), MitreTechnique(id="T1543.002", tactic="persistence", name="Create or Modify System Process: Systemd Service")),
    (re.compile(r"nc\s|ncat|netcat", re.IGNORECASE), MitreTechnique(id="T1095", tactic="command-and-control", name="Non-Application Layer Protocol")),
    (re.compile(r"reverse.?shell|bind.?shell", re.IGNORECASE), MitreTechnique(id="T1059", tactic="execution", name="Command and Scripting Interpreter")),
]


def map_event_to_mitre(event: TimelineEvent) -> list[MitreTechnique]:
    """Map a timeline event to matching MITRE ATT&CK techniques.

    Matches against summary, process, and action_type fields.
    """
    search_fields = " ".join([
        event.summary,
        event.process or "",
        event.action_type or "",
    ])

    seen: set[str] = set()
    result: list[MitreTechnique] = []

    for pattern, technique in _MITRE_MAPPINGS:
        if pattern.search(search_fields):
            if technique.id not in seen:
                seen.add(technique.id)
                result.append(technique)

    return result


def map_alert_to_mitre(alert: Alert) -> list[MitreTechnique]:
    """Map an alert to MITRE techniques, deduped across all evidence events."""
    seen: set[str] = set()
    result: list[MitreTechnique] = []

    for event in alert.evidence:
        for technique in map_event_to_mitre(event):
            if technique.id not in seen:
                seen.add(technique.id)
                result.append(technique)

    return result


def coverage_matrix(alerts: list[Alert]) -> dict[str, list[MitreTechnique]]:
    """Build a MITRE ATT&CK coverage matrix from alerts.

    Groups techniques by tactic.
    """
    matrix: dict[str, list[MitreTechnique]] = {}

    for alert in alerts:
        techniques = map_alert_to_mitre(alert)
        for tech in techniques:
            existing = matrix.get(tech.tactic, [])
            if not any(t.id == tech.id for t in existing):
                existing.append(tech)
                matrix[tech.tactic] = existing

    return matrix


__all__ = [
    "MitreTechnique",
    "map_event_to_mitre",
    "map_alert_to_mitre",
    "coverage_matrix",
]
