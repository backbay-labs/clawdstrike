# ShellCommandGuard

Validates shell commands against forbidden regex patterns and checks extracted path tokens against the `ForbiddenPathGuard`.

## Actions

- `GuardAction::ShellCommand(commandline)`

## Configuration

```yaml
guards:
  shell_command:
    enabled: true
    forbidden_patterns:
      - '(?i)\brm\s+(-rf?|--recursive)\s+/\s*(?:$|\*)'
      - '(?i)\bcurl\s+[^|]*\|\s*(bash|sh|zsh)\b'
      - '(?i)\bwget\s+[^|]*\|\s*(bash|sh|zsh)\b'
      - '(?i)\bnc\s+[^\n]*\s+-e\s+'
      - '(?i)\bbash\s+-i\s+>&\s+/dev/tcp/'
      - '(?i)\bbase64\s+[^|]*\|\s*(curl|wget|nc)\b'
    enforce_forbidden_paths: true
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable this guard. |
| `forbidden_patterns` | string[] | (see defaults) | Regex patterns that are forbidden in shell commands. |
| `enforce_forbidden_paths` | bool | `true` | Whether to run ForbiddenPathGuard checks on best-effort extracted path tokens. |

### Default forbidden patterns

The built-in patterns block:

- `rm -rf /` and variants (destructive recursive deletion)
- `curl ... | bash` / `wget ... | sh` (download-and-execute)
- `nc ... -e` and `bash -i >& /dev/tcp/` (reverse shells)
- `base64 ... | curl` (base64-encoded exfiltration)

## Path extraction

When `enforce_forbidden_paths` is enabled, the guard performs best-effort extraction of filesystem paths from the command line:

1. Shell-style tokenization (respects single/double quoting, backslash escapes).
2. Redirection targets (`>`, `>>`, `<`, `2>`, etc.) are treated as paths.
3. `--flag=/path/to/file` style arguments are parsed.
4. Tokens that look like filesystem paths (`/`, `~`, `./`, `../`, `.env`, `.ssh/`, `.aws/`, `.gnupg/`) are extracted.
5. Windows drive-rooted paths (`C:\...`) are extracted from the raw command line.

Extracted paths are checked against `ForbiddenPathGuard` with its current configuration.

## Notes

- Quoted pipe operators (`'|'`) are normalized before pattern matching to prevent evasion.
- A blocked pattern match produces `Severity::Critical`.
- A forbidden path hit also produces `Severity::Critical`.
