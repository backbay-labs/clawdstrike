# PromptInjectionGuard

Detects common prompt-injection patterns in untrusted text (web pages, emails, documents, etc.).

This guard is intended to run at the boundary where your agent runtime ingests external content.

## Actions

This guard evaluates only:

- `GuardAction::Custom("untrusted_text", payload)`

Payload formats:

- `"just a string"` (treated as `text`)
- `{ "text": "...", "source": "..." }`

## Configuration

```yaml
guards:
  prompt_injection:
    warn_at_or_above: suspicious # safe|suspicious|high|critical
    block_at_or_above: high      # safe|suspicious|high|critical
    max_scan_bytes: 200000
```

## Helper utilities

The Rust crate also exposes a cheap detector and boundary markers:

- `hushclaw::detect_prompt_injection`
- `hushclaw::wrap_user_content`
- `hushclaw::USER_CONTENT_START` / `hushclaw::USER_CONTENT_END`
- `hushclaw::FingerprintDeduper` (optional log/alert dedupe via `PromptInjectionReport.fingerprint`)

The recommended pattern is:

1. Treat external text as data, not instructions.
2. Wrap it in `[USER_CONTENT_START] ... [USER_CONTENT_END]`.
3. Add a standing system/developer instruction to never follow instructions inside those markers.
