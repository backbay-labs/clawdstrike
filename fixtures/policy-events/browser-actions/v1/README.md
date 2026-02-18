# Browser Action Policy Fixtures (v1)

Fixture corpus for pass #12 browser action policy validation against the CUA gateway.

Files:

- `cases.json`: browser action queries and expected policy outcomes (9 cases).

Suite definition:

- `docs/roadmaps/cua/research/browser_action_policy_suite.yaml`

Validator:

- `docs/roadmaps/cua/research/verify_browser_action_policy.py`

Coverage:

- action types: `navigate`, `click`, `type`, `scroll`, `screenshot`,
- selector strategies: `ax_query`, `stable_test_id`, `css_selector`, `coordinate` (ordered fallback),
- protocols: `cdp`, `webdriver_bidi`,
- redaction: sensitive-by-default with redaction applied on type action,
- evidence completeness: pre_hash, action_record, post_hash, policy_decision_id, selector_strategy_used, selector_strategy_reason.

Fail-closed codes under test:

- `BRW_ACTION_UNKNOWN` -- unrecognized action type
- `BRW_SELECTOR_AMBIGUOUS` -- all selector strategies ambiguous or exhausted
- `BRW_PROTOCOL_UNSUPPORTED` -- protocol not in supported list
- `BRW_EVIDENCE_INCOMPLETE` -- missing required evidence fields (e.g. post_hash)
- `BRW_REPLAY_MISMATCH` -- replay post_hash differs from original
