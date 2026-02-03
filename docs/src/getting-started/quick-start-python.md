# Quick Start (Python)

Get Clawdstrike running in your Python project in under 5 minutes.

## Installation

```bash
pip install hush-py
```

For native performance (optional PyO3 bindings):

```bash
pip install hush-py[native]
```

## Basic Usage

### Check File Access

```python
from hush import HushEngine, GuardContext

engine = HushEngine()
ctx = GuardContext()

# Check if a file access is allowed
result = await engine.check_file_access("/home/user/.ssh/id_rsa", ctx)

if not result.allowed:
    print(f"Access denied: {result.violations}")
else:
    print("Access allowed")
```

### Synchronous API

For non-async contexts:

```python
from hush import HushEngine, GuardContext

engine = HushEngine()
ctx = GuardContext()

# Sync version
result = engine.check_file_access_sync("/etc/passwd", ctx)
print(f"Allowed: {result.allowed}")
```

### Check Network Egress

```python
result = await engine.check_egress("api.openai.com", 443, ctx)

if result.allowed:
    # Proceed with network request
    import httpx
    async with httpx.AsyncClient() as client:
        response = await client.get("https://api.openai.com/v1/models")
```

### Check MCP Tool Invocation

```python
result = await engine.check_mcp_tool(
    "shell_exec",
    {"command": "ls -la"},
    ctx
)

if not result.allowed:
    raise PermissionError(f"Tool blocked: {result.violations[0].reason}")
```

## Using Rulesets

Load a pre-configured ruleset:

```python
engine = HushEngine(ruleset="strict")  # or "ai-agent", "cicd", "permissive"
```

## Custom Policy

Load from a YAML file:

```python
engine = HushEngine.from_policy_file("./my-policy.yaml")
```

Or define inline:

```python
engine = HushEngine(policy={
    "version": "1.0.0",
    "name": "My Custom Policy",
    "extends": "clawdstrike:default",
    "guards": {
        "egress_allowlist": {
            "additional_allow": ["api.mycompany.com"]
        }
    }
})
```

## Jailbreak Detection

Detect jailbreak attempts in user input:

```python
from hush import JailbreakDetector

detector = JailbreakDetector(
    block_threshold=70,
    warn_threshold=30,
    session_aggregation=True
)

session_id = "user-123-session-456"

async def handle_user_message(message: str) -> str:
    result = await detector.detect(message, session_id)

    if result.blocked:
        print(f"Jailbreak detected: {result.severity}")
        print(f"Signals: {[s.id for s in result.signals]}")
        return "I can't process that request."

    if result.risk_score >= 30:
        print(f"Suspicious input (score: {result.risk_score})")

    # Proceed with LLM call
    return await call_llm(message)
```

## Output Sanitization

Redact secrets and PII from LLM output:

```python
from hush import OutputSanitizer

sanitizer = OutputSanitizer(
    categories={"secrets": True, "pii": True},
    redaction_strategies={
        "secret": "full",
        "pii": "partial"
    }
)

async def process_llm_response(response: str) -> str:
    result = await sanitizer.sanitize(response)

    if result.was_redacted:
        print(f"Redacted {len(result.findings)} sensitive items")

    return result.sanitized
```

## Signed Receipts

Create tamper-evident records:

```python
from hush import HushEngine, sha256

# Engine with signing enabled
engine = HushEngine(signing={"enabled": True})

# Run checks
result = await engine.check_file_access("/app/config.json", ctx)

# Create signed receipt
content_hash = sha256(str(result).encode())
receipt = await engine.create_signed_receipt(content_hash)

# Save for audit
save_receipt(receipt)

# Verify later
from hush import verify_receipt

is_valid = verify_receipt(receipt, engine.get_public_key())
print(f"Receipt valid: {is_valid}")
```

## With Context

Provide execution context:

```python
ctx = GuardContext(
    cwd="/app/workspace",
    session_id="session-123",
    agent_id="coding-assistant",
    metadata={
        "user_id": "user-456",
        "environment": "production"
    }
)

result = await engine.check_file_access("./src/main.py", ctx)
```

## Integration with LangChain

```python
from hush import HushEngine, GuardContext
from langchain.tools import BaseTool

class SecureFileTool(BaseTool):
    name = "read_file"
    description = "Read a file from disk"

    def __init__(self):
        super().__init__()
        self.engine = HushEngine(ruleset="ai-agent")
        self.ctx = GuardContext()

    async def _arun(self, path: str) -> str:
        # Check access first
        result = await self.engine.check_file_access(path, self.ctx)
        if not result.allowed:
            raise PermissionError(f"Access denied: {result.violations}")

        # Safe to read
        with open(path) as f:
            return f.read()
```

## Integration with FastAPI

```python
from fastapi import FastAPI, HTTPException
from hush import JailbreakDetector, OutputSanitizer

app = FastAPI()
detector = JailbreakDetector()
sanitizer = OutputSanitizer()

@app.post("/chat")
async def chat(message: str, session_id: str):
    # Check input
    detection = await detector.detect(message, session_id)
    if detection.blocked:
        raise HTTPException(400, "Request blocked by security policy")

    # Call LLM
    response = await call_llm(message)

    # Sanitize output
    result = await sanitizer.sanitize(response)
    return {"response": result.sanitized}
```

## Error Handling

```python
from hush import PolicyValidationError, GuardError

try:
    engine = HushEngine.from_policy_file("./policy.yaml")
except PolicyValidationError as e:
    print(f"Invalid policy: {e.validation_errors}")
    raise

try:
    result = await engine.check_file_access(path, ctx)
except GuardError as e:
    # Guard evaluation failed - fail closed
    print(f"Guard error, denying access: {e}")
    result = type("Result", (), {"allowed": False})()
```

## Type Hints

Full type hints are provided:

```python
from hush import (
    HushEngine,
    GuardContext,
    GuardResult,
    JailbreakDetector,
    JailbreakDetectionResult,
    OutputSanitizer,
    SanitizationResult,
)

async def check_access(engine: HushEngine, path: str) -> GuardResult:
    ctx = GuardContext()
    return await engine.check_file_access(path, ctx)
```

## Next Steps

- [Policy Schema](../reference/policy-schema.md) — Full policy reference
- [Guards Reference](../reference/guards/README.md) — All available guards
- [Custom Guards](../guides/custom-guards.md) — Create your own guards
- [Python API Reference](../reference/api/python.md) — Complete API docs
