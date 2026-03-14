/**
 * Built-in YARA rule templates for the detection engineering IDE.
 */

export interface YaraTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  content: string;
}

export const YARA_TEMPLATES: YaraTemplate[] = [
  {
    id: "generic-malware",
    name: "Generic Malware Detection",
    description: "Detects PE files with suspicious import combinations commonly used by malware.",
    category: "Malware",
    content: `import "pe"

rule generic_malware_suspicious_imports {
    meta:
        author = "ClawdStrike"
        description = "Detects PE files with suspicious API import patterns"
        date = "2026-03-14"
        reference = "https://attack.mitre.org/techniques/T1055/"
        severity = "high"

    strings:
        $api_virtualalloc = "VirtualAllocEx" ascii wide
        $api_writeprocess = "WriteProcessMemory" ascii wide
        $api_createthread = "CreateRemoteThread" ascii wide
        $api_ntunmap = "NtUnmapViewOfSection" ascii wide
        $api_openprocess = "OpenProcess" ascii wide

        $s_debug = "IsDebuggerPresent" ascii wide
        $s_sandbox = "SbieDll.dll" ascii wide nocase

    condition:
        pe.is_pe and
        (
            ($api_virtualalloc and $api_writeprocess and $api_createthread) or
            ($api_ntunmap and $api_openprocess and $api_writeprocess) or
            (2 of ($s_*) and 2 of ($api_*))
        )
}
`,
  },
  {
    id: "webshell-detection",
    name: "Web Shell Detection",
    description: "Detects common PHP and JSP web shell patterns including eval, exec, and base64-encoded payloads.",
    category: "Web Threats",
    content: `rule webshell_eval_exec_patterns {
    meta:
        author = "ClawdStrike"
        description = "Detects PHP and JSP web shells with eval/exec patterns"
        date = "2026-03-14"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        severity = "critical"

    strings:
        // PHP eval patterns
        $php_eval1 = "eval($_" ascii nocase
        $php_eval2 = "eval(base64_decode(" ascii nocase
        $php_eval3 = "eval(gzinflate(" ascii nocase
        $php_eval4 = "assert($_" ascii nocase
        $php_exec1 = "system($_" ascii nocase
        $php_exec2 = "passthru($_" ascii nocase
        $php_exec3 = "shell_exec($_" ascii nocase
        $php_exec4 = "exec($_" ascii nocase
        $php_preg = /preg_replace\\s*\\(\\s*['\"]\\/.+\\/e['\"]/ ascii

        // JSP patterns
        $jsp_runtime = "Runtime.getRuntime().exec(" ascii
        $jsp_process = "ProcessBuilder" ascii
        $jsp_cmd1 = "request.getParameter" ascii
        $jsp_cmd2 = /cmd\\s*=\\s*request\\.get/ ascii

        // Common obfuscation
        $obf_chr = /chr\\s*\\(\\s*\\d+\\s*\\)\\s*\\.\\s*chr/ ascii nocase
        $obf_b64 = "base64_decode" ascii nocase

    condition:
        (
            // PHP web shell
            any of ($php_eval*) or
            (any of ($php_exec*) and $obf_b64) or
            $php_preg
        ) or (
            // JSP web shell
            ($jsp_runtime or $jsp_process) and
            any of ($jsp_cmd*)
        ) or (
            // Obfuscated shell
            $obf_chr and any of ($php_*)
        )
}
`,
  },
  {
    id: "credential-dumper",
    name: "Credential Dumper",
    description: "Detects tools and patterns associated with credential dumping, including mimikatz signatures and LSASS access.",
    category: "Credential Access",
    content: `rule credential_dumper_indicators {
    meta:
        author = "ClawdStrike"
        description = "Detects credential dumping tools and LSASS memory access patterns"
        date = "2026-03-14"
        reference = "https://attack.mitre.org/techniques/T1003/"
        severity = "critical"

    strings:
        // Mimikatz signatures
        $mimi1 = "mimikatz" ascii wide nocase
        $mimi2 = "gentilkiwi" ascii wide
        $mimi3 = "sekurlsa::" ascii wide
        $mimi4 = "kerberos::golden" ascii wide
        $mimi5 = "privilege::debug" ascii wide

        // LSASS access patterns
        $lsass1 = "lsass.exe" ascii wide nocase
        $lsass2 = "lsass.dmp" ascii wide nocase
        $lsass3 = "MiniDumpWriteDump" ascii wide

        // Credential file targets
        $cred1 = "\\\\SAM" ascii wide
        $cred2 = "\\\\SECURITY" ascii wide
        $cred3 = "\\\\SYSTEM" ascii wide
        $cred4 = "ntds.dit" ascii wide nocase

        // API indicators
        $api1 = "OpenProcess" ascii wide
        $api2 = "MiniDumpWriteDump" ascii wide
        $api3 = "LsaRetrievePrivateData" ascii wide
        $api4 = "CredEnumerate" ascii wide

        // Common tool strings
        $tool1 = "procdump" ascii wide nocase
        $tool2 = "comsvcs.dll" ascii wide nocase
        $tool3 = "SecretsDump" ascii wide nocase

    condition:
        (2 of ($mimi*)) or
        ($lsass1 and $lsass3) or
        ($lsass2) or
        (2 of ($cred*) and any of ($api*)) or
        (any of ($tool*) and $lsass1)
}
`,
  },
  {
    id: "ransomware-indicators",
    name: "Ransomware Indicators",
    description: "Detects ransomware behavior patterns including file encryption APIs, shadow copy deletion, and ransom note artifacts.",
    category: "Ransomware",
    content: `rule ransomware_behavior_indicators {
    meta:
        author = "ClawdStrike"
        description = "Detects ransomware behavior including encryption and ransom note patterns"
        date = "2026-03-14"
        reference = "https://attack.mitre.org/techniques/T1486/"
        severity = "critical"

    strings:
        // Crypto API usage
        $crypto1 = "CryptEncrypt" ascii wide
        $crypto2 = "CryptGenKey" ascii wide
        $crypto3 = "CryptImportKey" ascii wide
        $crypto4 = "BCryptEncrypt" ascii wide
        $crypto5 = "CryptAcquireContext" ascii wide

        // Shadow copy deletion
        $shadow1 = "vssadmin delete shadows" ascii wide nocase
        $shadow2 = "wmic shadowcopy delete" ascii wide nocase
        $shadow3 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $shadow4 = "wbadmin delete catalog" ascii wide nocase

        // Ransom note indicators
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $note2 = "bitcoin" ascii wide nocase
        $note3 = "decrypt" ascii wide nocase
        $note4 = "ransom" ascii wide nocase
        $note5 = /[a-zA-Z0-9]{25,34}/ ascii  // Bitcoin address pattern
        $note6 = ".onion" ascii wide

        // File extension manipulation
        $ext1 = ".locked" ascii wide
        $ext2 = ".encrypted" ascii wide
        $ext3 = ".crypt" ascii wide
        $ext4 = "README_TO_DECRYPT" ascii wide nocase
        $ext5 = "HOW_TO_RECOVER" ascii wide nocase

    condition:
        (
            // Encryption + shadow deletion
            (2 of ($crypto*) and any of ($shadow*))
        ) or (
            // Ransom note content
            (2 of ($note*) and any of ($ext*))
        ) or (
            // Shadow deletion + ransom indicators
            (2 of ($shadow*) and any of ($note*))
        ) or (
            // Full combo: crypto + notes + extension
            any of ($crypto*) and any of ($note*) and any of ($ext*)
        )
}
`,
  },
];
