# Output Sanitization Example

Demonstrates Clawdstrike's output sanitization pipeline. The sanitizer scans LLM-generated text before it reaches the user, detecting and redacting secrets, PII, and internal infrastructure details using pattern matching, entropy analysis, and configurable allowlist/denylist rules.

## Architecture

```
                        LLM Output
                            |
              +-------------+-------------+
              |             |             |
        Pattern Matching  Entropy     Denylist
        (secrets, PII,   Analysis    (custom
         internal URLs)  (Shannon    terms)
                         entropy)
              |             |             |
              +-------------+-------------+
                            |
                       Findings
                    (spans, categories,
                     confidence scores)
                            |
                     Allowlist Filter
                  (skip known-safe values)
                            |
                       Redaction
                  (full / partial /
                   type_label / hash)
                            |
                       Safe Output
```

## What It Demonstrates

- **Batch sanitization** -- process a block of text containing API keys, tokens, emails, phone numbers, credit cards, internal IPs, and sensitive file paths; view the before/after and a findings table
- **Streaming sanitization** -- split a GitHub token across two chunks to show that the carry-byte buffer correctly detects secrets spanning chunk boundaries
- **Category isolation** -- run the sanitizer three times, each with only one category enabled (secrets, pii, internal), to see what each layer catches independently
- **Allowlist / denylist** -- allowlist a specific email so it passes through unredacted, and add a custom denylist term that gets caught even though it matches no built-in pattern
- **Findings report** -- structured output with finding IDs, categories, data types, confidence scores, and safe preview strings (never raw secrets)

## Prerequisites

```bash
npm install
```

## Run

```bash
npx tsx index.ts
```

## Expected Output

```
=== Clawdstrike Output Sanitization Example ===

Phase 1: Full Batch Sanitization
────────────────────────────────────────────────────────────────────────────────────
Input:
Here are the credentials you requested:

API Key: sk-abc123def456ghi789jkl012mno345pqr678stu901vwxyz12
GitHub Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
...

Sanitized output:
Here are the credentials you requested:

API Key: [REDACTED:openai_api_key]
GitHub Token: [REDACTED:github_token]

Contact the admin at ad***om or call 55***09.
The customer's card number is 45***66.

Internal services are running at [REDACTED:internal]/api and
the database is at [REDACTED:internal]. Config is at [REDACTED:internal].

Findings:
ID                            Category  Type                Conf  Preview
────────────────────────────────────────────────────────────────────────────────────
secret_openai_api_key         secret    openai_api_key      0.99  sk***12
secret_github_token           secret    github_token        0.99  gh***ij
pii_email                     pii       email               0.95  ad***om
pii_phone                     pii       phone               0.80  55***09
pii_credit_card               pii       credit_card         0.70  45***66
internal_localhost_url         internal  internal_url        0.80  ht***80
internal_private_ip            internal  internal_ip         0.80  19***00
internal_file_path_sensitive   internal  sensitive_path      0.70  /e***l/
...

Phase 2: Streaming Sanitization
────────────────────────────────────────────────────────────────────────────────────
Chunk 1: "The token is ghp_ABCDEF"
Chunk 2: "GHIJKLMNOPQRSTUVWXYZabcdefghij and it's secret."
...
Findings: 1 sensitive item(s) detected across chunk boundaries

Phase 3: Category Isolation
────────────────────────────────────────────────────────────────────────────────────
[secrets only] ... findings
[pii only] ... findings
[internal only] ... findings

Phase 4: Allowlist / Denylist
────────────────────────────────────────────────────────────────────────────────────
Email findings: 0 (admin@internal-corp.com was allowlisted)
Denylist findings: 1 (PROJECT_ATLAS matched)

=== Done ===
```

(Exact redaction text, finding counts, and timing may vary across SDK versions.)
