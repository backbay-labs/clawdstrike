// ---- Sigma Rule Templates ----
// Pre-built Sigma rule templates for common detection scenarios.
// Each template is a complete, valid Sigma rule ready for customization.

export interface SigmaTemplate {
  id: string;
  name: string;
  description: string;
  /** ATT&CK tactic or general use case category. */
  category: string;
  logsourceCategory: string;
  logsourceProduct: string;
  level: string;
  /** Full YAML content of the Sigma rule. */
  content: string;
}

export const SIGMA_TEMPLATES: SigmaTemplate[] = [
  // 1. Suspicious PowerShell Encoded Command Execution
  {
    id: "f3a98ce2-1b4a-4c7d-9e8f-2a5b6d7c8e9f",
    name: "Suspicious PowerShell Encoded Command Execution",
    description:
      "Detects execution of PowerShell with encoded commands, commonly used by attackers to obfuscate malicious scripts.",
    category: "Execution",
    logsourceCategory: "process_creation",
    logsourceProduct: "windows",
    level: "medium",
    content: `title: Suspicious PowerShell Encoded Command Execution
id: f3a98ce2-1b4a-4c7d-9e8f-2a5b6d7c8e9f
status: experimental
description: |
    Detects execution of PowerShell with encoded commands, which is commonly
    used by attackers to obfuscate malicious scripts.
author: ClawdStrike Workbench
date: 2026/03/14
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_powershell:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    selection_encoded:
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - '-e '
    condition: selection_powershell and selection_encoded
falsepositives:
    - Legitimate admin scripts using encoded commands
    - Software installers
level: medium
`,
  },

  // 2. Outbound Network Connection to Uncommon Port
  {
    id: "a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
    name: "Outbound Connection to Uncommon Port",
    description:
      "Detects outbound network connections to non-standard ports that may indicate C2 communication or data exfiltration.",
    category: "Command and Control",
    logsourceCategory: "network_connection",
    logsourceProduct: "windows",
    level: "low",
    content: `title: Outbound Connection to Uncommon Port
id: a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: |
    Detects outbound network connections to non-standard ports that may
    indicate command-and-control communication or data exfiltration channels.
author: ClawdStrike Workbench
date: 2026/03/14
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
    filter_standard_ports:
        DestinationPort:
            - 80
            - 443
            - 53
            - 22
            - 25
            - 587
            - 993
            - 995
            - 8080
            - 8443
    filter_local:
        DestinationIp|startswith:
            - '10.'
            - '172.16.'
            - '192.168.'
            - '127.'
    condition: selection and not filter_standard_ports and not filter_local
falsepositives:
    - Custom applications using non-standard ports
    - VPN or tunnel software
    - Development and testing tools
level: low
`,
  },

  // 3. Suspicious DNS Query to Known Dynamic DNS Provider
  {
    id: "b7e84f19-3c2a-4d6e-8f1b-9a0c5d7e6f2a",
    name: "DNS Query to Dynamic DNS Provider",
    description:
      "Detects DNS queries to known dynamic DNS providers frequently abused by threat actors for C2 infrastructure.",
    category: "Command and Control",
    logsourceCategory: "dns_query",
    logsourceProduct: "windows",
    level: "medium",
    content: `title: DNS Query to Dynamic DNS Provider
id: b7e84f19-3c2a-4d6e-8f1b-9a0c5d7e6f2a
status: experimental
description: |
    Detects DNS queries to known dynamic DNS providers that are frequently
    abused by threat actors to host command-and-control infrastructure.
author: ClawdStrike Workbench
date: 2026/03/14
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
    condition: selection
falsepositives:
    - Legitimate use of dynamic DNS services for home labs
    - IoT devices using dynamic DNS for remote access
level: medium
`,
  },

  // 4. Suspicious File Created in Startup Folder
  {
    id: "c8d93a27-4f5b-6e7c-1d2a-3b4c5d6e7f8a",
    name: "File Created in Startup Folder",
    description:
      "Detects creation of files in Windows startup folders, a common persistence technique used by malware.",
    category: "Persistence",
    logsourceCategory: "file_event",
    logsourceProduct: "windows",
    level: "high",
    content: `title: File Created in Startup Folder
id: c8d93a27-4f5b-6e7c-1d2a-3b4c5d6e7f8a
status: experimental
description: |
    Detects creation of files in Windows startup folders, a common
    persistence technique used by malware to survive system reboots.
author: ClawdStrike Workbench
date: 2026/03/14
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: file_event
    product: windows
detection:
    selection_user_startup:
        TargetFilename|contains:
            - '\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\'
    selection_common_startup:
        TargetFilename|contains:
            - '\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\'
    filter_installer:
        Image|endswith:
            - '\\msiexec.exe'
            - '\\setup.exe'
    condition: (selection_user_startup or selection_common_startup) and not filter_installer
falsepositives:
    - Legitimate software installers adding startup entries
    - System administrators deploying login scripts
level: high
`,
  },

  // 5. Linux Process Creation with Suspicious Arguments
  {
    id: "d9e04b38-5a6c-7f8d-2e3b-4c5d6e7f8a9b",
    name: "Linux Reverse Shell via Common Utilities",
    description:
      "Detects execution of common Linux utilities with arguments indicating a reverse shell attempt.",
    category: "Execution",
    logsourceCategory: "process_creation",
    logsourceProduct: "linux",
    level: "high",
    content: `title: Linux Reverse Shell via Common Utilities
id: d9e04b38-5a6c-7f8d-2e3b-4c5d6e7f8a9b
status: experimental
description: |
    Detects execution of common Linux utilities with arguments that indicate
    a reverse shell attempt, such as bash redirecting to /dev/tcp or python
    spawning interactive shells over network sockets.
author: ClawdStrike Workbench
date: 2026/03/14
tags:
    - attack.execution
    - attack.t1059.004
    - attack.t1071.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_bash_reverse:
        CommandLine|contains:
            - '/dev/tcp/'
            - '/dev/udp/'
    selection_python_reverse:
        Image|endswith:
            - '/python'
            - '/python3'
        CommandLine|contains:
            - 'socket'
            - 'subprocess'
            - 'pty.spawn'
    selection_netcat:
        Image|endswith:
            - '/nc'
            - '/ncat'
            - '/netcat'
        CommandLine|contains:
            - '-e /bin'
            - '-e /usr/bin'
    condition: selection_bash_reverse or (selection_python_reverse) or selection_netcat
falsepositives:
    - Legitimate network debugging with netcat
    - DevOps automation scripts
level: high
`,
  },
];
