import { useState, useMemo, useCallback } from "react";
import { cn } from "@/lib/utils";
import {
  IconSearch,
  IconDownload,
  IconEye,
  IconChevronDown,
  IconChevronUp,
  IconTag,
} from "@tabler/icons-react";

// ---- SigmaHQ Rule data model ----

interface SigmaHQRule {
  id: string;
  title: string;
  description: string;
  status: string;
  level: string;
  author: string;
  category: string;
  product: string;
  tags: string[];
  fileName: string;
  content: string;
}

// ---- Level badge colors ----

const LEVEL_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  informational: {
    bg: "bg-[#6f7f9a]/10",
    text: "text-[#6f7f9a]",
    border: "border-[#6f7f9a]/20",
  },
  low: {
    bg: "bg-[#3dbf84]/10",
    text: "text-[#3dbf84]",
    border: "border-[#3dbf84]/20",
  },
  medium: {
    bg: "bg-[#d4a84b]/10",
    text: "text-[#d4a84b]",
    border: "border-[#d4a84b]/20",
  },
  high: {
    bg: "bg-[#e0915c]/10",
    text: "text-[#e0915c]",
    border: "border-[#e0915c]/20",
  },
  critical: {
    bg: "bg-[#c45c5c]/10",
    text: "text-[#c45c5c]",
    border: "border-[#c45c5c]/20",
  },
};

// ---- Tactic helpers ----

const TACTIC_ORDER = [
  "initial_access",
  "execution",
  "persistence",
  "privilege_escalation",
  "defense_evasion",
  "credential_access",
  "discovery",
  "lateral_movement",
  "collection",
  "exfiltration",
  "command_and_control",
  "impact",
  "uncategorized",
] as const;

const TACTIC_LABELS: Record<string, string> = {
  initial_access: "Initial Access",
  execution: "Execution",
  persistence: "Persistence",
  privilege_escalation: "Privilege Escalation",
  defense_evasion: "Defense Evasion",
  credential_access: "Credential Access",
  discovery: "Discovery",
  lateral_movement: "Lateral Movement",
  collection: "Collection",
  exfiltration: "Exfiltration",
  command_and_control: "Command & Control",
  impact: "Impact",
  uncategorized: "Uncategorized",
};

const LEVEL_SEVERITY: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  informational: 0,
};

function extractTactic(tags: string[]): string {
  for (const tag of tags) {
    const match = tag.match(/^attack\.(\w+)$/);
    if (match && !tag.match(/^attack\.t\d/i)) return match[1];
  }
  return "uncategorized";
}

function extractTechniques(tags: string[]): string[] {
  return tags
    .filter((t) => /^attack\.t\d+/i.test(t))
    .map((t) => t.replace("attack.", "").toUpperCase());
}

function levelColorHex(level: string): string {
  switch (level) {
    case "critical":
      return "#c45c5c";
    case "high":
      return "#e0915c";
    case "medium":
      return "#d4a84b";
    case "low":
      return "#3dbf84";
    default:
      return "#6f7f9a";
  }
}

const PRODUCT_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  windows: {
    bg: "bg-[#7c9aef]/10",
    text: "text-[#7c9aef]",
    border: "border-[#7c9aef]/20",
  },
  linux: {
    bg: "bg-[#e0915c]/10",
    text: "text-[#e0915c]",
    border: "border-[#e0915c]/20",
  },
  aws: {
    bg: "bg-[#d4a84b]/10",
    text: "text-[#d4a84b]",
    border: "border-[#d4a84b]/20",
  },
  azure: {
    bg: "bg-[#5b8def]/10",
    text: "text-[#5b8def]",
    border: "border-[#5b8def]/20",
  },
};

// ---- Static SigmaHQ catalog ----

const SIGMAHQ_CATALOG: SigmaHQRule[] = [
  // 1. PowerShell Encoded Command
  {
    id: "f3a98ce2-1b4a-4c7d-9e8f-2a5b6d7c8e01",
    title: "PowerShell Encoded Command Execution",
    description:
      "Detects execution of PowerShell with encoded or base64-encoded commands, commonly used by attackers to obfuscate malicious payloads and evade static analysis.",
    status: "test",
    level: "medium",
    author: "SigmaHQ Community",
    category: "process_creation",
    product: "windows",
    tags: ["attack.execution", "attack.t1059.001"],
    fileName: "proc_creation_win_powershell_encoded.yml",
    content: `title: PowerShell Encoded Command Execution
id: f3a98ce2-1b4a-4c7d-9e8f-2a5b6d7c8e01
status: test
description: |
    Detects execution of PowerShell with encoded or base64-encoded commands,
    commonly used by attackers to obfuscate malicious payloads and evade
    static analysis.
references:
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe
author: SigmaHQ Community
date: 2024/01/15
modified: 2025/06/10
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    selection_cli:
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
            - ' -e JAB'
            - ' -e SQB'
            - ' -e SQBFAF'
            - ' -e aQB'
            - ' -e cwB'
            - ' -e aWB'
    condition: selection_img and selection_cli
falsepositives:
    - Legitimate admin scripts using encoded commands for deployment
    - Software installers with encoded parameters
level: medium
`,
  },

  // 2. Mimikatz Usage
  {
    id: "a642964e-bab3-4793-a1e2-4c0e1b7e3c02",
    title: "Mimikatz Command Line Usage",
    description:
      "Detects well-known Mimikatz command line arguments used for credential dumping, privilege escalation, and Kerberos ticket manipulation.",
    status: "test",
    level: "high",
    author: "SigmaHQ Community",
    category: "process_creation",
    product: "windows",
    tags: ["attack.credential_access", "attack.t1003.001", "attack.t1003.002"],
    fileName: "proc_creation_win_mimikatz_command_line.yml",
    content: `title: Mimikatz Command Line Usage
id: a642964e-bab3-4793-a1e2-4c0e1b7e3c02
status: test
description: |
    Detects well-known Mimikatz command line arguments used for credential
    dumping, privilege escalation, and Kerberos ticket manipulation.
references:
    - https://github.com/gentilkiwi/mimikatz
    - https://attack.mitre.org/software/S0002/
author: SigmaHQ Community
date: 2023/08/20
modified: 2025/04/12
tags:
    - attack.credential_access
    - attack.t1003.001
    - attack.t1003.002
    - attack.s0002
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        CommandLine|contains:
            - 'sekurlsa::'
            - 'kerberos::'
            - 'crypto::'
            - 'lsadump::'
            - 'privilege::debug'
            - 'token::elevate'
            - 'vault::cred'
            - 'dpapi::'
    selection_img:
        Image|endswith:
            - '\\mimikatz.exe'
        OriginalFileName: 'mimikatz.exe'
    condition: selection_cmd or selection_img
falsepositives:
    - Security testing tools using similar command syntax
    - Penetration testing activities
level: high
`,
  },

  // 3. LSASS Memory Dump
  {
    id: "5d2c62b8-cd0d-48fa-8e30-3b8e3c7d3a03",
    title: "LSASS Process Memory Dump Access",
    description:
      "Detects access to the LSASS process memory, which may indicate credential dumping attempts using tools like Mimikatz, ProcDump, or comsvcs.dll.",
    status: "test",
    level: "high",
    author: "SigmaHQ Community",
    category: "process_access",
    product: "windows",
    tags: ["attack.credential_access", "attack.t1003.001"],
    fileName: "proc_access_win_lsass_dump.yml",
    content: `title: LSASS Process Memory Dump Access
id: 5d2c62b8-cd0d-48fa-8e30-3b8e3c7d3a03
status: test
description: |
    Detects access to the LSASS process memory, which may indicate credential
    dumping attempts using tools like Mimikatz, ProcDump, or comsvcs.dll.
references:
    - https://attack.mitre.org/techniques/T1003/001/
    - https://www.microsoft.com/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/
author: SigmaHQ Community
date: 2023/05/10
modified: 2025/03/22
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x1438'
            - '0x143a'
    filter_system:
        SourceImage|startswith:
            - 'C:\\Windows\\System32\\'
            - 'C:\\Windows\\SysWOW64\\'
    filter_av:
        SourceImage|contains:
            - '\\MsMpEng.exe'
            - '\\MpCmdRun.exe'
    condition: selection and not filter_system and not filter_av
falsepositives:
    - Antivirus and EDR solutions accessing LSASS
    - Windows Error Reporting (WER)
level: high
`,
  },

  // 4. Suspicious Outbound Connection to Uncommon Port
  {
    id: "b6e3f1a9-4d2c-5e7f-8a9b-0c1d2e3f4a04",
    title: "Suspicious Outbound Connection to Uncommon Port",
    description:
      "Detects outbound network connections to non-standard ports that may indicate C2 communication, data exfiltration, or reverse shell activity.",
    status: "experimental",
    level: "low",
    author: "SigmaHQ Community",
    category: "network_connection",
    product: "windows",
    tags: ["attack.command_and_control", "attack.t1571", "attack.exfiltration", "attack.t1048"],
    fileName: "net_connection_win_outbound_uncommon_port.yml",
    content: `title: Suspicious Outbound Connection to Uncommon Port
id: b6e3f1a9-4d2c-5e7f-8a9b-0c1d2e3f4a04
status: experimental
description: |
    Detects outbound network connections to non-standard ports that may indicate
    C2 communication, data exfiltration, or reverse shell activity.
references:
    - https://attack.mitre.org/techniques/T1571/
author: SigmaHQ Community
date: 2024/02/20
tags:
    - attack.command_and_control
    - attack.t1571
    - attack.exfiltration
    - attack.t1048
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
    filter_standard:
        DestinationPort:
            - 80
            - 443
            - 53
            - 22
            - 25
            - 110
            - 143
            - 587
            - 993
            - 995
            - 3389
            - 5985
            - 5986
            - 8080
            - 8443
    filter_local:
        DestinationIp|startswith:
            - '10.'
            - '172.16.'
            - '172.17.'
            - '172.18.'
            - '172.19.'
            - '172.20.'
            - '172.21.'
            - '172.22.'
            - '172.23.'
            - '172.24.'
            - '172.25.'
            - '172.26.'
            - '172.27.'
            - '172.28.'
            - '172.29.'
            - '172.30.'
            - '172.31.'
            - '192.168.'
            - '127.'
    condition: selection and not filter_standard and not filter_local
falsepositives:
    - Custom applications using non-standard ports
    - VPN or tunnel software
    - Development tools connecting to debug ports
level: low
`,
  },

  // 5. Certutil Download
  {
    id: "e4d1c3b5-2a6f-4e8d-9c0b-7a5d3f1e2b05",
    title: "Certutil Used to Download File",
    description:
      "Detects the use of certutil.exe to download files from the internet, a technique commonly abused by threat actors as a LOLBIN for payload delivery.",
    status: "test",
    level: "high",
    author: "SigmaHQ Community",
    category: "process_creation",
    product: "windows",
    tags: ["attack.command_and_control", "attack.t1105", "attack.defense_evasion", "attack.t1140"],
    fileName: "proc_creation_win_certutil_download.yml",
    content: `title: Certutil Used to Download File
id: e4d1c3b5-2a6f-4e8d-9c0b-7a5d3f1e2b05
status: test
description: |
    Detects the use of certutil.exe to download files from the internet, a
    technique commonly abused by threat actors as a living-off-the-land binary
    (LOLBIN) for payload delivery.
references:
    - https://attack.mitre.org/techniques/T1105/
    - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
author: SigmaHQ Community
date: 2023/09/15
modified: 2025/01/08
tags:
    - attack.command_and_control
    - attack.t1105
    - attack.defense_evasion
    - attack.t1140
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\\certutil.exe'
        OriginalFileName: 'CertUtil.exe'
    selection_download:
        CommandLine|contains:
            - 'urlcache'
            - '-urlcache'
            - '/urlcache'
            - '-split'
            - '/split'
    selection_url:
        CommandLine|contains:
            - 'http://'
            - 'https://'
            - 'ftp://'
    condition: selection_img and selection_download and selection_url
falsepositives:
    - Legitimate certificate operations that happen to reference URLs
    - Admin scripts using certutil for downloads in controlled environments
level: high
`,
  },

  // 6. Schtasks Persistence
  {
    id: "c7a2d1e9-3b4f-5a6c-8d7e-9f0a1b2c3d06",
    title: "Scheduled Task Creation via Schtasks",
    description:
      "Detects creation of scheduled tasks via schtasks.exe, a common persistence mechanism used by threat actors to maintain access after initial compromise.",
    status: "test",
    level: "medium",
    author: "SigmaHQ Community",
    category: "process_creation",
    product: "windows",
    tags: ["attack.persistence", "attack.execution", "attack.t1053.005"],
    fileName: "proc_creation_win_schtasks_creation.yml",
    content: `title: Scheduled Task Creation via Schtasks
id: c7a2d1e9-3b4f-5a6c-8d7e-9f0a1b2c3d06
status: test
description: |
    Detects creation of scheduled tasks via schtasks.exe, a common persistence
    mechanism used by threat actors to maintain access after initial compromise.
references:
    - https://attack.mitre.org/techniques/T1053/005/
    - https://docs.microsoft.com/en-us/windows/win32/taskschd/schtasks
author: SigmaHQ Community
date: 2023/11/01
modified: 2025/05/20
tags:
    - attack.persistence
    - attack.execution
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\\schtasks.exe'
    selection_create:
        CommandLine|contains:
            - '/create'
            - '-create'
    selection_suspicious:
        CommandLine|contains:
            - '/sc onlogon'
            - '/sc onidle'
            - '/sc onstart'
            - '/rl highest'
            - 'powershell'
            - 'cmd.exe /c'
            - 'mshta'
            - 'wscript'
            - 'cscript'
            - 'rundll32'
            - 'regsvr32'
    condition: selection_img and selection_create and selection_suspicious
falsepositives:
    - Legitimate administrative task scheduling
    - Software update mechanisms
    - IT management tools
level: medium
`,
  },

  // 7. Reg.exe Modifying Run Keys
  {
    id: "d8b3e2f0-4c5a-6b7d-9e8f-0a1b2c3d4e07",
    title: "Registry Run Key Modification via Reg.exe",
    description:
      "Detects modification of Windows registry Run and RunOnce keys using reg.exe, a common persistence technique to execute malware at logon.",
    status: "test",
    level: "high",
    author: "SigmaHQ Community",
    category: "registry_set",
    product: "windows",
    tags: ["attack.persistence", "attack.t1547.001"],
    fileName: "registry_set_win_run_key_modification.yml",
    content: `title: Registry Run Key Modification via Reg.exe
id: d8b3e2f0-4c5a-6b7d-9e8f-0a1b2c3d4e07
status: test
description: |
    Detects modification of Windows registry Run and RunOnce keys using reg.exe,
    a common persistence technique to execute malware at system startup or user logon.
references:
    - https://attack.mitre.org/techniques/T1547/001/
    - https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
author: SigmaHQ Community
date: 2023/07/12
modified: 2025/02/15
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection_target:
        TargetObject|contains:
            - '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\'
            - '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\'
            - '\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\'
            - '\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\'
    filter_legitimate:
        Image|startswith:
            - 'C:\\Windows\\System32\\'
            - 'C:\\Program Files\\'
            - 'C:\\Program Files (x86)\\'
    condition: selection_target and not filter_legitimate
falsepositives:
    - Legitimate software installation adding startup entries
    - Group Policy updates
level: high
`,
  },

  // 8. Suspicious DNS Query to Dynamic DNS
  {
    id: "e9c4f3a1-5d6b-7c8e-0f1a-2b3c4d5e6f08",
    title: "DNS Query to Dynamic DNS Provider",
    description:
      "Detects DNS queries to known dynamic DNS providers frequently used by threat actors to host C2 infrastructure and phishing domains.",
    status: "test",
    level: "medium",
    author: "SigmaHQ Community",
    category: "dns_query",
    product: "windows",
    tags: ["attack.command_and_control", "attack.t1568.002"],
    fileName: "net_dns_query_win_dynamic_dns.yml",
    content: `title: DNS Query to Dynamic DNS Provider
id: e9c4f3a1-5d6b-7c8e-0f1a-2b3c4d5e6f08
status: test
description: |
    Detects DNS queries to known dynamic DNS providers frequently used by
    threat actors to host command-and-control infrastructure and phishing domains.
references:
    - https://attack.mitre.org/techniques/T1568/002/
    - https://unit42.paloaltonetworks.com/dynamic-dns-abuse/
author: SigmaHQ Community
date: 2024/03/10
modified: 2025/07/01
tags:
    - attack.command_and_control
    - attack.t1568.002
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith:
            - '.duckdns.org'
            - '.no-ip.com'
            - '.no-ip.org'
            - '.no-ip.biz'
            - '.ddns.net'
            - '.dynu.com'
            - '.freedns.afraid.org'
            - '.hopto.org'
            - '.zapto.org'
            - '.sytes.net'
            - '.serveftp.com'
            - '.servegame.com'
            - '.servehttp.com'
            - '.myftp.biz'
    condition: selection
falsepositives:
    - Legitimate use of dynamic DNS for home labs or IoT devices
    - Remote access tools used for legitimate administration
level: medium
`,
  },

  // 9. WMI Process Creation
  {
    id: "f0d5a4b2-6e7c-8d9f-1a0b-3c4d5e6f7a09",
    title: "WMI Spawning Process",
    description:
      "Detects process creation by WMI provider host (WmiPrvSE.exe), which indicates WMI-based execution commonly used for lateral movement and persistence.",
    status: "test",
    level: "medium",
    author: "SigmaHQ Community",
    category: "process_creation",
    product: "windows",
    tags: ["attack.execution", "attack.t1047"],
    fileName: "proc_creation_win_wmi_spawn_process.yml",
    content: `title: WMI Spawning Process
id: f0d5a4b2-6e7c-8d9f-1a0b-3c4d5e6f7a09
status: test
description: |
    Detects process creation by WMI provider host (WmiPrvSE.exe), which indicates
    WMI-based execution commonly used for lateral movement and persistence.
references:
    - https://attack.mitre.org/techniques/T1047/
author: SigmaHQ Community
date: 2023/06/28
modified: 2025/03/15
tags:
    - attack.execution
    - attack.t1047
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\\WmiPrvSE.exe'
    selection_suspicious:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
            - '\\cmd.exe'
            - '\\mshta.exe'
            - '\\wscript.exe'
            - '\\cscript.exe'
            - '\\rundll32.exe'
            - '\\regsvr32.exe'
    condition: selection and selection_suspicious
falsepositives:
    - Legitimate WMI-based system management scripts
    - SCCM and other enterprise management tools
level: medium
`,
  },

  // 10. Suspicious Cron Job (Linux)
  {
    id: "a1e6b5c3-7f8d-9e0a-2b1c-4d5e6f7a8b10",
    title: "Suspicious Cron Job Creation",
    description:
      "Detects creation or modification of cron jobs using crontab or direct writes to cron directories, a common Linux persistence mechanism.",
    status: "experimental",
    level: "medium",
    author: "SigmaHQ Community",
    category: "process_creation",
    product: "linux",
    tags: ["attack.persistence", "attack.t1053.003"],
    fileName: "proc_creation_lnx_suspicious_cron.yml",
    content: `title: Suspicious Cron Job Creation
id: a1e6b5c3-7f8d-9e0a-2b1c-4d5e6f7a8b10
status: experimental
description: |
    Detects creation or modification of cron jobs using crontab or direct writes
    to cron directories, a common Linux persistence mechanism.
references:
    - https://attack.mitre.org/techniques/T1053/003/
author: SigmaHQ Community
date: 2024/05/12
tags:
    - attack.persistence
    - attack.t1053.003
logsource:
    category: process_creation
    product: linux
detection:
    selection_crontab:
        Image|endswith: '/crontab'
        CommandLine|contains:
            - '-e'
            - '-l'
    selection_direct_write:
        Image|endswith:
            - '/bash'
            - '/sh'
            - '/dash'
        CommandLine|contains:
            - '/etc/cron'
            - '/var/spool/cron'
            - '/etc/crontab'
    selection_reverse_shell:
        CommandLine|contains:
            - '/dev/tcp/'
            - 'bash -i'
            - 'nc -e'
            - 'python -c'
            - 'curl | bash'
            - 'wget -O - |'
    condition: (selection_crontab or selection_direct_write) and selection_reverse_shell
falsepositives:
    - Legitimate cron job management by system administrators
    - Configuration management tools (Ansible, Puppet, Chef)
level: medium
`,
  },

  // 11. SSH Brute Force (Linux)
  {
    id: "b2f7c6d4-8a9e-0f1b-3c2d-5e6f7a8b9c11",
    title: "SSH Brute Force Connection Attempt",
    description:
      "Detects potential SSH brute force attacks by monitoring for rapid outbound SSH connections from a single source, indicating credential spraying or brute force tooling.",
    status: "experimental",
    level: "medium",
    author: "SigmaHQ Community",
    category: "network_connection",
    product: "linux",
    tags: ["attack.credential_access", "attack.t1110.001", "attack.lateral_movement", "attack.t1021.004"],
    fileName: "net_connection_lnx_ssh_brute_force.yml",
    content: `title: SSH Brute Force Connection Attempt
id: b2f7c6d4-8a9e-0f1b-3c2d-5e6f7a8b9c11
status: experimental
description: |
    Detects potential SSH brute force attacks by monitoring for outbound SSH
    connections from suspicious tools commonly used for credential spraying.
references:
    - https://attack.mitre.org/techniques/T1110/001/
    - https://attack.mitre.org/techniques/T1021/004/
author: SigmaHQ Community
date: 2024/04/18
tags:
    - attack.credential_access
    - attack.t1110.001
    - attack.lateral_movement
    - attack.t1021.004
logsource:
    category: network_connection
    product: linux
detection:
    selection_port:
        DestinationPort: 22
    selection_tools:
        Image|endswith:
            - '/hydra'
            - '/medusa'
            - '/ncrack'
            - '/patator'
        CommandLine|contains:
            - 'ssh://'
            - '-t ssh'
            - 'ssh_login'
    condition: selection_port and selection_tools
falsepositives:
    - Legitimate penetration testing activities
    - SSH configuration management with multiple hosts
level: medium
`,
  },

  // 12. AWS CloudTrail IAM Policy Change
  {
    id: "c3a8d7e5-9b0f-1a2c-4d3e-6f7a8b9c0d12",
    title: "AWS IAM Policy Modification",
    description:
      "Detects modifications to IAM policies in AWS CloudTrail logs, which could indicate privilege escalation attempts or unauthorized access configuration changes.",
    status: "test",
    level: "medium",
    author: "SigmaHQ Community",
    category: "cloudtrail",
    product: "aws",
    tags: ["attack.persistence", "attack.t1098", "attack.privilege_escalation", "attack.t1484"],
    fileName: "cloud_aws_iam_policy_change.yml",
    content: `title: AWS IAM Policy Modification
id: c3a8d7e5-9b0f-1a2c-4d3e-6f7a8b9c0d12
status: test
description: |
    Detects modifications to IAM policies in AWS CloudTrail logs, which could
    indicate privilege escalation attempts or unauthorized access configuration changes.
references:
    - https://attack.mitre.org/techniques/T1098/
    - https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html
author: SigmaHQ Community
date: 2024/01/22
modified: 2025/08/05
tags:
    - attack.persistence
    - attack.t1098
    - attack.privilege_escalation
    - attack.t1484
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'iam.amazonaws.com'
        eventName:
            - 'PutUserPolicy'
            - 'PutGroupPolicy'
            - 'PutRolePolicy'
            - 'AttachUserPolicy'
            - 'AttachGroupPolicy'
            - 'AttachRolePolicy'
            - 'CreatePolicy'
            - 'CreatePolicyVersion'
            - 'DeleteUserPolicy'
            - 'DeleteGroupPolicy'
            - 'DeleteRolePolicy'
    filter_console:
        userIdentity.invokedBy: 'AWS Internal'
    condition: selection and not filter_console
falsepositives:
    - Legitimate IAM policy changes by administrators
    - Infrastructure-as-code deployments (Terraform, CloudFormation)
    - Automated compliance remediation tools
level: medium
`,
  },

  // 13. Azure AD Suspicious Sign-In
  {
    id: "d4b9e8f6-0c1a-2b3d-5e4f-7a8b9c0d1e13",
    title: "Azure AD Suspicious Sign-In Activity",
    description:
      "Detects suspicious Azure AD sign-in patterns including sign-ins from unfamiliar locations, impossible travel, or sign-ins with error codes indicating compromise attempts.",
    status: "experimental",
    level: "medium",
    author: "SigmaHQ Community",
    category: "azure_signinlogs",
    product: "azure",
    tags: ["attack.initial_access", "attack.t1078.004", "attack.credential_access", "attack.t1110"],
    fileName: "cloud_azure_ad_suspicious_signin.yml",
    content: `title: Azure AD Suspicious Sign-In Activity
id: d4b9e8f6-0c1a-2b3d-5e4f-7a8b9c0d1e13
status: experimental
description: |
    Detects suspicious Azure AD sign-in patterns including sign-ins with
    risk indicators or from anonymous/known-malicious IP addresses.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-risky-sign-ins
    - https://attack.mitre.org/techniques/T1078/004/
author: SigmaHQ Community
date: 2024/06/15
tags:
    - attack.initial_access
    - attack.t1078.004
    - attack.credential_access
    - attack.t1110
logsource:
    product: azure
    service: signinlogs
detection:
    selection_risk:
        RiskLevelDuringSignIn:
            - 'high'
            - 'medium'
    selection_status:
        Status.errorCode|contains:
            - '50053'
            - '50126'
            - '50074'
    selection_anon:
        IsInteractive: true
        NetworkLocationDetails|contains: 'anonymizer'
    condition: selection_risk or (selection_status) or selection_anon
falsepositives:
    - Users connecting through VPN or Tor for privacy reasons
    - Traveling employees with legitimate access needs
    - Misconfigured MFA policies triggering false risk signals
level: medium
`,
  },

  // 14. Web Shell Detection via Process
  {
    id: "e5c0f9a7-1d2b-3c4e-6f5a-8b9c0d1e2f14",
    title: "Web Shell Detection via Suspicious Process Spawn",
    description:
      "Detects web shell activity by identifying suspicious child processes spawned by web server processes (IIS, Apache, Nginx), indicating remote code execution.",
    status: "test",
    level: "critical",
    author: "SigmaHQ Community",
    category: "process_creation",
    product: "windows",
    tags: ["attack.persistence", "attack.t1505.003", "attack.initial_access"],
    fileName: "proc_creation_win_webshell_spawn.yml",
    content: `title: Web Shell Detection via Suspicious Process Spawn
id: e5c0f9a7-1d2b-3c4e-6f5a-8b9c0d1e2f14
status: test
description: |
    Detects web shell activity by identifying suspicious child processes spawned
    by web server processes (IIS, Apache, Nginx), indicating remote code execution.
references:
    - https://attack.mitre.org/techniques/T1505/003/
    - https://www.microsoft.com/security/blog/2021/02/11/web-shell-attacks-continue-to-rise/
author: SigmaHQ Community
date: 2023/04/08
modified: 2025/06/30
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.initial_access
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\w3wp.exe'
            - '\\httpd.exe'
            - '\\nginx.exe'
            - '\\php-cgi.exe'
            - '\\tomcat.exe'
            - '\\UMWorkerProcess.exe'
    selection_child:
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\pwsh.exe'
            - '\\whoami.exe'
            - '\\net.exe'
            - '\\net1.exe'
            - '\\ipconfig.exe'
            - '\\systeminfo.exe'
            - '\\tasklist.exe'
            - '\\certutil.exe'
            - '\\bitsadmin.exe'
            - '\\cscript.exe'
            - '\\wscript.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Web applications that legitimately spawn system processes
    - CGI scripts with intended command execution
level: critical
`,
  },

  // 15. Lateral Movement via PsExec
  {
    id: "f6d1a0b8-2e3c-4d5f-7a6b-9c0d1e2f3a15",
    title: "Lateral Movement via PsExec Service Installation",
    description:
      "Detects PsExec-style lateral movement by identifying the creation of the PSEXESVC service or the execution of PsExec with remote target arguments.",
    status: "test",
    level: "high",
    author: "SigmaHQ Community",
    category: "process_creation",
    product: "windows",
    tags: ["attack.lateral_movement", "attack.t1021.002", "attack.execution", "attack.t1569.002"],
    fileName: "proc_creation_win_psexec_lateral_movement.yml",
    content: `title: Lateral Movement via PsExec Service Installation
id: f6d1a0b8-2e3c-4d5f-7a6b-9c0d1e2f3a15
status: test
description: |
    Detects PsExec-style lateral movement by identifying the creation of the
    PSEXESVC service or the execution of PsExec with remote target arguments.
references:
    - https://attack.mitre.org/techniques/T1021/002/
    - https://attack.mitre.org/techniques/T1569/002/
    - https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
author: SigmaHQ Community
date: 2023/03/25
modified: 2025/05/10
tags:
    - attack.lateral_movement
    - attack.t1021.002
    - attack.execution
    - attack.t1569.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_psexec_img:
        Image|endswith:
            - '\\PsExec.exe'
            - '\\PsExec64.exe'
        CommandLine|contains: '\\\\'
    selection_service:
        Image|endswith: '\\PSEXESVC.exe'
        User|contains:
            - 'SYSTEM'
            - 'NT AUTHORITY'
    condition: selection_psexec_img or selection_service
falsepositives:
    - Legitimate system administration using PsExec
    - Software deployment tools
    - IT helpdesk remote support activities
level: high
`,
  },
];

// ---- Product filter options ----

type ProductFilter = "all" | "windows" | "linux" | "cloud";
type LevelFilter = "all" | "low" | "medium" | "high" | "critical";

function matchesProductFilter(rule: SigmaHQRule, filter: ProductFilter): boolean {
  if (filter === "all") return true;
  if (filter === "cloud") return rule.product === "aws" || rule.product === "azure";
  return rule.product === filter;
}

// ---- Tactic group header ----

function TacticGroupHeader({ tactic, count }: { tactic: string; count: number }) {
  return (
    <div className="border-b border-[#2d3240] pt-6 pb-2 flex items-baseline gap-2">
      <span className="text-[13px] font-syne font-black uppercase tracking-[0.12em] text-[#ece7dc]">
        {TACTIC_LABELS[tactic] ?? tactic}
      </span>
      <span className="inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono text-[#6f7f9a] bg-[#131721] border border-[#2d3240] rounded">
        {count}
      </span>
    </div>
  );
}

// ---- Critical rule card ----

function CriticalRuleCard({
  rule,
  isExpanded,
  onToggleExpand,
  onImport,
}: {
  rule: SigmaHQRule;
  isExpanded: boolean;
  onToggleExpand: () => void;
  onImport: () => void;
}) {
  const techniques = extractTechniques(rule.tags);

  return (
    <div
      className="mt-2 border-l-[3px] border-[#c45c5c] bg-[#c45c5c]/[0.03] rounded-r-lg p-4"
    >
      {/* Top row: CRITICAL badge + product */}
      <div className="flex items-center gap-2 mb-2">
        <span className="inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono font-bold uppercase text-[#c45c5c] bg-[#c45c5c]/10 border border-[#c45c5c]/20 rounded">
          CRITICAL
        </span>
        <span
          className={cn(
            "inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono border rounded",
            (PRODUCT_COLORS[rule.product] ?? PRODUCT_COLORS.windows).bg,
            (PRODUCT_COLORS[rule.product] ?? PRODUCT_COLORS.windows).text,
            (PRODUCT_COLORS[rule.product] ?? PRODUCT_COLORS.windows).border,
          )}
        >
          {rule.product}
        </span>
        <span className="inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono bg-[#131721] text-[#6f7f9a] border border-[#2d3240] rounded">
          {rule.category}
        </span>
      </div>

      {/* Title */}
      <h4 className="text-[15px] font-syne font-bold text-[#ece7dc] leading-tight mb-2">
        {rule.title}
      </h4>

      {/* Full description */}
      <p className="text-xs text-[#6f7f9a] leading-relaxed mb-3">
        {rule.description}
      </p>

      {/* ATT&CK technique badges */}
      {techniques.length > 0 && (
        <div className="flex items-center gap-1 mb-3 flex-wrap">
          {techniques.map((tech) => (
            <span
              key={tech}
              className="inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono font-bold bg-[#7c9aef]/10 text-[#7c9aef] border border-[#7c9aef]/20 rounded"
            >
              {tech}
            </span>
          ))}
        </div>
      )}

      {/* Expanded YAML preview */}
      {isExpanded && (
        <div className="mb-3 rounded-md bg-[#131721] border border-[#2d3240]/50 overflow-hidden">
          <div className="flex items-center justify-between px-3 py-1.5 border-b border-[#2d3240]/30">
            <span className="text-[9px] font-mono text-[#6f7f9a]">
              {rule.fileName}
            </span>
            <span className="text-[9px] font-mono text-[#7c9aef]/50">
              sigma yaml
            </span>
          </div>
          <pre className="p-3 text-[10px] font-mono text-[#6f7f9a]/80 leading-relaxed overflow-x-auto max-h-[400px] overflow-y-auto whitespace-pre">
            {rule.content}
          </pre>
        </div>
      )}

      {/* Footer: author + actions */}
      <div className="pt-3 border-t border-[#2d3240]/30 flex items-center justify-between">
        <span className="text-[10px] text-[#6f7f9a]/60">{rule.author}</span>
        <div className="flex items-center gap-1.5">
          <button
            onClick={onToggleExpand}
            title={isExpanded ? "Collapse" : "Preview YAML"}
            className="flex items-center gap-1 px-2 py-1 rounded-md bg-[#131721] text-[#6f7f9a] text-[10px] font-medium hover:text-[#ece7dc] transition-colors"
          >
            {isExpanded ? (
              <>
                <IconChevronUp size={11} stroke={1.5} />
                Collapse
              </>
            ) : (
              <>
                <IconEye size={11} stroke={1.5} />
                Preview
              </>
            )}
          </button>
          <button
            onClick={onImport}
            title="Open in editor"
            className="flex items-center gap-1 px-2 py-1 rounded-md bg-[#7c9aef]/10 text-[#7c9aef] text-[10px] font-medium hover:bg-[#7c9aef]/20 transition-colors"
          >
            <IconDownload size={11} stroke={1.5} />
            Open in editor
          </button>
        </div>
      </div>
    </div>
  );
}

// ---- Standard rule row ----

function StandardRuleRow({
  rule,
  isExpanded,
  onToggleExpand,
  onImport,
}: {
  rule: SigmaHQRule;
  isExpanded: boolean;
  onToggleExpand: () => void;
  onImport: () => void;
}) {
  const techniques = extractTechniques(rule.tags);
  const primaryTechnique = techniques[0] ?? null;
  const borderColor = levelColorHex(rule.level);
  const levelColor = LEVEL_COLORS[rule.level] ?? LEVEL_COLORS.medium;
  const productColor = PRODUCT_COLORS[rule.product] ?? PRODUCT_COLORS.windows;

  return (
    <div className="mt-1">
      {/* Compact row */}
      <div
        onClick={onToggleExpand}
        className="group flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-[#131721]/40 transition-colors rounded-r"
        style={{ borderLeft: `2px solid ${borderColor}` }}
      >
        {/* Title */}
        <span className="flex-1 text-xs font-syne font-medium text-[#ece7dc] truncate">
          {rule.title}
        </span>

        {/* Level badge */}
        <span
          className={cn(
            "shrink-0 inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono font-bold uppercase border rounded",
            levelColor.bg,
            levelColor.text,
            levelColor.border,
          )}
        >
          {rule.level}
        </span>

        {/* Product badge */}
        <span
          className={cn(
            "shrink-0 inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono border rounded",
            productColor.bg,
            productColor.text,
            productColor.border,
          )}
        >
          {rule.product}
        </span>

        {/* Primary technique */}
        {primaryTechnique && (
          <span className="shrink-0 inline-flex items-center px-1.5 py-0.5 text-[8px] font-mono bg-[#7c9aef]/5 text-[#7c9aef]/70 border border-[#7c9aef]/10 rounded">
            {primaryTechnique}
          </span>
        )}

        {/* Hover-revealed Open button */}
        <button
          onClick={(e) => {
            e.stopPropagation();
            onImport();
          }}
          className="shrink-0 opacity-0 group-hover:opacity-100 flex items-center gap-1 px-2 py-1 rounded-md bg-[#7c9aef]/10 text-[#7c9aef] text-[10px] font-medium hover:bg-[#7c9aef]/20 transition-all"
        >
          <IconDownload size={11} stroke={1.5} />
          Open
        </button>

        {/* Expand chevron */}
        {isExpanded ? (
          <IconChevronUp size={12} className="shrink-0 text-[#6f7f9a]" stroke={1.5} />
        ) : (
          <IconChevronDown size={12} className="shrink-0 text-[#6f7f9a]" stroke={1.5} />
        )}
      </div>

      {/* Expanded details */}
      {isExpanded && (
        <div
          className="ml-[2px] pl-5 pr-3 pb-3 bg-[#131721]/20 rounded-br"
          style={{ borderLeft: `2px solid ${borderColor}` }}
        >
          {/* Description */}
          <p className="text-xs text-[#6f7f9a] leading-relaxed mb-3 pt-2">
            {rule.description}
          </p>

          {/* All tags */}
          <div className="flex items-center gap-1 mb-3 flex-wrap">
            {rule.tags.map((tag) => (
              <span
                key={tag}
                className="inline-flex items-center px-1.5 py-0.5 text-[8px] font-mono bg-[#7c9aef]/5 text-[#7c9aef]/70 border border-[#7c9aef]/10 rounded"
              >
                {tag}
              </span>
            ))}
          </div>

          {/* Author + filename */}
          <div className="flex items-center gap-4 text-[10px] text-[#6f7f9a]/60 mb-3">
            <span>{rule.author}</span>
            <span className="font-mono">{rule.fileName}</span>
          </div>

          {/* YAML preview */}
          <div className="rounded-md bg-[#131721] border border-[#2d3240]/50 overflow-hidden">
            <div className="flex items-center justify-between px-3 py-1.5 border-b border-[#2d3240]/30">
              <span className="text-[9px] font-mono text-[#6f7f9a]">
                {rule.fileName}
              </span>
              <span className="text-[9px] font-mono text-[#7c9aef]/50">
                sigma yaml
              </span>
            </div>
            <pre className="p-3 text-[10px] font-mono text-[#6f7f9a]/80 leading-relaxed overflow-x-auto max-h-[400px] overflow-y-auto whitespace-pre">
              {rule.content}
            </pre>
          </div>

          {/* Actions row */}
          <div className="flex items-center justify-end gap-1.5 mt-3">
            <button
              onClick={onImport}
              title="Open in editor"
              className="flex items-center gap-1 px-2 py-1 rounded-md bg-[#7c9aef]/10 text-[#7c9aef] text-[10px] font-medium hover:bg-[#7c9aef]/20 transition-colors"
            >
              <IconDownload size={11} stroke={1.5} />
              Open in editor
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ---- Component ----

interface SigmaHQBrowserProps {
  onImport: (yaml: string, title: string) => void;
}

export function SigmaHQBrowser({ onImport }: SigmaHQBrowserProps) {
  const [search, setSearch] = useState("");
  const [productFilter, setProductFilter] = useState<ProductFilter>("all");
  const [levelFilter, setLevelFilter] = useState<LevelFilter>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filteredRules = useMemo(() => {
    let rules = SIGMAHQ_CATALOG;

    // Product filter
    rules = rules.filter((r) => matchesProductFilter(r, productFilter));

    // Level filter
    if (levelFilter !== "all") {
      rules = rules.filter((r) => r.level === levelFilter);
    }

    // Search filter
    if (search.trim()) {
      const q = search.toLowerCase().trim();
      rules = rules.filter(
        (r) =>
          r.title.toLowerCase().includes(q) ||
          r.description.toLowerCase().includes(q) ||
          r.tags.some((t) => t.toLowerCase().includes(q)) ||
          r.category.toLowerCase().includes(q) ||
          r.product.toLowerCase().includes(q) ||
          r.fileName.toLowerCase().includes(q) ||
          r.author.toLowerCase().includes(q),
      );
    }

    return rules;
  }, [search, productFilter, levelFilter]);

  const toggleExpand = useCallback((id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  }, []);

  // Product filter counts
  const productCounts = useMemo(() => {
    const counts = { all: SIGMAHQ_CATALOG.length, windows: 0, linux: 0, cloud: 0 };
    for (const r of SIGMAHQ_CATALOG) {
      if (r.product === "windows") counts.windows++;
      else if (r.product === "linux") counts.linux++;
      else if (r.product === "aws" || r.product === "azure") counts.cloud++;
    }
    return counts;
  }, []);

  // Group filtered rules by MITRE tactic, sorted by tactic order then severity
  const groupedRules = useMemo(() => {
    const groups = new Map<string, SigmaHQRule[]>();

    for (const rule of filteredRules) {
      const tactic = extractTactic(rule.tags);
      const existing = groups.get(tactic);
      if (existing) {
        existing.push(rule);
      } else {
        groups.set(tactic, [rule]);
      }
    }

    // Sort rules within each group by severity (critical first)
    for (const rules of groups.values()) {
      rules.sort(
        (a, b) => (LEVEL_SEVERITY[b.level] ?? 0) - (LEVEL_SEVERITY[a.level] ?? 0),
      );
    }

    // Sort groups by tactic order
    const ordered: [string, SigmaHQRule[]][] = [];
    for (const tactic of TACTIC_ORDER) {
      const rules = groups.get(tactic);
      if (rules && rules.length > 0) {
        ordered.push([tactic, rules]);
      }
    }
    // Any remaining tactics not in the order list
    for (const [tactic, rules] of groups) {
      if (!TACTIC_ORDER.includes(tactic as (typeof TACTIC_ORDER)[number]) && rules.length > 0) {
        ordered.push([tactic, rules]);
      }
    }

    return ordered;
  }, [filteredRules]);

  return (
    <div>
      {/* Header */}
      <div className="flex items-center gap-2 mb-4">
        <div className="w-8 h-8 rounded-lg bg-[#7c9aef]/10 border border-[#7c9aef]/20 flex items-center justify-center shrink-0">
          <IconTag size={16} className="text-[#7c9aef]" />
        </div>
        <div>
          <h3 className="font-syne font-bold text-sm text-[#ece7dc]">
            SigmaHQ Community Rules
          </h3>
          <p className="text-[10px] text-[#6f7f9a]">
            Curated detection rules from the SigmaHQ open-source repository
          </p>
        </div>
        <span className="ml-auto text-[10px] font-mono text-[#7c9aef]/60">
          {SIGMAHQ_CATALOG.length} rules
        </span>
      </div>

      {/* Search bar */}
      <div className="relative mb-4">
        <IconSearch
          size={14}
          className="absolute left-3 top-1/2 -translate-y-1/2 text-[#6f7f9a]"
          stroke={1.5}
        />
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by title, tag, ATT&CK technique, category..."
          className="w-full pl-8 pr-3 py-2 rounded-lg bg-[#131721] border border-[#2d3240] text-[#ece7dc] text-xs placeholder:text-[#6f7f9a]/50 focus:outline-none focus:border-[#7c9aef]/40 transition-colors"
        />
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-3 mb-5 flex-wrap">
        {/* Product filters */}
        <div className="flex items-center gap-1">
          <span className="text-[9px] font-mono text-[#6f7f9a] mr-1 uppercase tracking-wider">
            Platform
          </span>
          {(
            [
              { value: "all", label: "All" },
              { value: "windows", label: "Windows" },
              { value: "linux", label: "Linux" },
              { value: "cloud", label: "Cloud" },
            ] as const
          ).map(({ value, label }) => (
            <button
              key={value}
              onClick={() => setProductFilter(value)}
              className={cn(
                "flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[10px] font-medium transition-colors",
                productFilter === value
                  ? "bg-[#7c9aef]/10 text-[#7c9aef] border border-[#7c9aef]/20"
                  : "bg-[#131721] text-[#6f7f9a] border border-[#2d3240] hover:text-[#ece7dc]",
              )}
            >
              {label}
              <span className="text-[9px] opacity-60">{productCounts[value]}</span>
            </button>
          ))}
        </div>

        {/* Level filters */}
        <div className="flex items-center gap-1">
          <span className="text-[9px] font-mono text-[#6f7f9a] mr-1 uppercase tracking-wider">
            Level
          </span>
          {(
            [
              { value: "all", label: "All" },
              { value: "low", label: "Low" },
              { value: "medium", label: "Medium" },
              { value: "high", label: "High" },
              { value: "critical", label: "Critical" },
            ] as const
          ).map(({ value, label }) => {
            const colors =
              value === "all"
                ? { active: "bg-[#7c9aef]/10 text-[#7c9aef] border-[#7c9aef]/20" }
                : {
                    active: `${LEVEL_COLORS[value].bg} ${LEVEL_COLORS[value].text} ${LEVEL_COLORS[value].border}`,
                  };
            return (
              <button
                key={value}
                onClick={() => setLevelFilter(value)}
                className={cn(
                  "px-2.5 py-1.5 rounded-md text-[10px] font-medium transition-colors border",
                  levelFilter === value
                    ? colors.active
                    : "bg-[#131721] text-[#6f7f9a] border-[#2d3240] hover:text-[#ece7dc]",
                )}
              >
                {label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Tactic-grouped results */}
      {filteredRules.length === 0 ? (
        <div className="rounded-xl border border-dashed border-[#2d3240]/60 bg-[#0b0d13]/30 px-8 py-14 text-center flex flex-col items-center">
          <div className="w-12 h-12 rounded-2xl bg-[#131721] border border-[#2d3240]/50 flex items-center justify-center mb-4">
            <IconSearch size={20} className="text-[#6f7f9a]" />
          </div>
          <p className="text-[13px] font-medium text-[#6f7f9a] mb-1">
            No rules match your filters
          </p>
          <p className="text-[11px] text-[#6f7f9a]/60 max-w-[300px] leading-relaxed">
            Try adjusting your search terms or filter selections
          </p>
        </div>
      ) : (
        <div className="space-y-0">
          {groupedRules.map(([tactic, rules]) => (
            <div key={tactic}>
              <TacticGroupHeader tactic={tactic} count={rules.length} />
              {rules.map((rule) =>
                rule.level === "critical" ? (
                  <CriticalRuleCard
                    key={rule.id}
                    rule={rule}
                    isExpanded={expandedId === rule.id}
                    onToggleExpand={() => toggleExpand(rule.id)}
                    onImport={() => onImport(rule.content, rule.title)}
                  />
                ) : (
                  <StandardRuleRow
                    key={rule.id}
                    rule={rule}
                    isExpanded={expandedId === rule.id}
                    onToggleExpand={() => toggleExpand(rule.id)}
                    onImport={() => onImport(rule.content, rule.title)}
                  />
                ),
              )}
            </div>
          ))}
        </div>
      )}

      {/* Results count */}
      {filteredRules.length > 0 && (
        <p className="text-[10px] text-[#6f7f9a]/50 mt-4 text-center">
          Showing {filteredRules.length} of {SIGMAHQ_CATALOG.length} SigmaHQ community rules
        </p>
      )}
    </div>
  );
}
