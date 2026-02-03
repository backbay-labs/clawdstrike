# Python API Reference

The `hush-py` package provides a Python SDK for Clawdstrike with full feature parity.

## Installation

```bash
pip install hush-py

# With native PyO3 bindings (faster crypto)
pip install hush-py[native]
```

## Core Classes

### HushEngine

The main entry point for policy enforcement.

```python
from hush import HushEngine, GuardContext

class HushEngine:
    def __init__(
        self,
        ruleset: str | None = None,
        policy: dict | None = None,
        signing: dict | None = None,
    ) -> None: ...

    @classmethod
    def from_policy_file(cls, path: str) -> "HushEngine": ...

    async def check_file_access(
        self, path: str, context: GuardContext
    ) -> GuardResult: ...

    async def check_file_write(
        self, path: str, content: str, context: GuardContext
    ) -> GuardResult: ...

    async def check_patch(
        self, path: str, patch: str, context: GuardContext
    ) -> GuardResult: ...

    async def check_egress(
        self, host: str, port: int, context: GuardContext
    ) -> GuardResult: ...

    async def check_mcp_tool(
        self, tool_name: str, args: dict, context: GuardContext
    ) -> GuardResult: ...

    async def check_action_report(
        self, action: GuardAction, context: GuardContext
    ) -> GuardReport: ...

    async def create_signed_receipt(
        self, content_hash: bytes
    ) -> SignedReceipt: ...

    def get_public_key(self) -> str: ...

    # Sync versions
    def check_file_access_sync(
        self, path: str, context: GuardContext
    ) -> GuardResult: ...
    # ... (sync version for each async method)
```

### GuardContext

Execution context passed to guards.

```python
from hush import GuardContext

class GuardContext:
    def __init__(
        self,
        cwd: str | None = None,
        session_id: str | None = None,
        agent_id: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> None: ...

    cwd: str | None
    session_id: str | None
    agent_id: str | None
    metadata: dict[str, str]
```

### GuardResult

Result of a guard evaluation.

```python
from hush import GuardResult, Verdict, Violation

class GuardResult:
    allowed: bool
    verdict: Verdict
    violations: list[Violation]
    evidence: list[GuardEvidence]

class Verdict(Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"

class Violation:
    guard_name: str
    pattern: str | None
    reason: str
    severity: str
    span: tuple[int, int] | None
```

## Jailbreak Detection

### JailbreakDetector

Multi-layer jailbreak detection.

```python
from hush import JailbreakDetector, JailbreakDetectionResult

class JailbreakDetector:
    def __init__(
        self,
        layers: dict[str, bool] | None = None,
        block_threshold: int = 70,
        warn_threshold: int = 30,
        max_input_bytes: int = 100_000,
        session_aggregation: bool = True,
        session_ttl_ms: int = 3_600_000,
        session_half_life_ms: int = 900_000,
        llm_judge: Callable[[str], Awaitable[float]] | None = None,
    ) -> None: ...

    async def detect(
        self, input: str, session_id: str | None = None
    ) -> JailbreakDetectionResult: ...

    def detect_sync(
        self, input: str, session_id: str | None = None
    ) -> JailbreakDetectionResult: ...

class JailbreakDetectionResult:
    severity: Literal["safe", "suspicious", "likely", "confirmed"]
    confidence: float  # 0-1
    risk_score: int    # 0-100
    blocked: bool
    fingerprint: str   # SHA-256 hex
    signals: list[JailbreakSignal]
    layers: JailbreakLayers
    session: JailbreakSession | None

class JailbreakSignal:
    id: str
    category: JailbreakCategory
    weight: float

class JailbreakCategory(Enum):
    ROLE_PLAY = "role_play"
    AUTHORITY_CONFUSION = "authority_confusion"
    ENCODING_ATTACK = "encoding_attack"
    HYPOTHETICAL_FRAMING = "hypothetical_framing"
    ADVERSARIAL_SUFFIX = "adversarial_suffix"
    SYSTEM_IMPERSONATION = "system_impersonation"
    INSTRUCTION_EXTRACTION = "instruction_extraction"
    MULTI_TURN_GROOMING = "multi_turn_grooming"
    PAYLOAD_SPLITTING = "payload_splitting"
```

## Output Sanitization

### OutputSanitizer

Sensitive data detection and redaction.

```python
from hush import OutputSanitizer, SanitizationResult

class OutputSanitizer:
    def __init__(
        self,
        categories: dict[str, bool] | None = None,
        redaction_strategies: dict[str, str] | None = None,
        secrets: dict | None = None,
        pii: dict | None = None,
        internal: dict | None = None,
        allowlist: dict | None = None,
        performance: dict | None = None,
    ) -> None: ...

    async def sanitize(
        self,
        output: str,
        context: SanitizationContext | None = None,
    ) -> SanitizationResult: ...

    def sanitize_sync(self, output: str) -> SanitizationResult: ...

    async def detect(self, output: str) -> list[SensitiveDataFinding]: ...

    def create_stream(self) -> SanitizationStream: ...

    def add_pattern(self, pattern: SecretPatternDef) -> None: ...

class SanitizationResult:
    sanitized: str
    was_redacted: bool
    findings: list[SensitiveDataFinding]
    redactions: list[Redaction]
    stats: ProcessingStats

class SensitiveDataFinding:
    id: str
    category: Literal["secret", "pii", "phi", "pci", "internal"]
    type: str
    confidence: float
    span: tuple[int, int]
    match_preview: str
    detector: Literal["pattern", "ner", "entropy", "custom"]
    recommended_action: RedactionStrategy

class RedactionStrategy(Enum):
    FULL = "full"
    PARTIAL = "partial"
    TYPE_LABEL = "type_label"
    HASH = "hash"
    NONE = "none"
```

### Streaming Sanitization

```python
from hush import OutputSanitizer

sanitizer = OutputSanitizer()
stream = sanitizer.create_stream()

async def sanitize_stream(llm_stream):
    async for chunk in llm_stream:
        safe_chunk = stream.write(chunk)
        if safe_chunk:
            yield safe_chunk

    final = stream.flush()
    if final:
        yield final

    findings = stream.get_findings()
    if findings:
        log_findings(findings)
```

## Watermarking

### PromptWatermarker

Embed provenance markers in prompts.

```python
from hush import PromptWatermarker, WatermarkExtractor

class PromptWatermarker:
    def __init__(
        self,
        encoding: str = "metadata",
        include_timestamp: bool = True,
        include_sequence: bool = True,
        generate_key_pair: bool = True,
        private_key: str | None = None,
        public_key: str | None = None,
    ) -> None: ...

    def watermark(
        self,
        prompt: str,
        payload: WatermarkPayload | None = None,
    ) -> WatermarkedPrompt: ...

    def get_public_key(self) -> str: ...

class WatermarkedPrompt:
    original: str
    watermarked: str
    watermark: EncodedWatermark
    stats: WatermarkStats

class WatermarkExtractor:
    def __init__(
        self,
        trusted_public_keys: list[str],
        allow_unverified: bool = False,
    ) -> None: ...

    def extract(self, text: str) -> WatermarkExtractionResult: ...
    def extract_and_verify(self, text: str) -> WatermarkExtractionResult: ...
```

## Cryptographic Primitives

### Hashing

```python
from hush import sha256, keccak256, to_hex

# Hash bytes
digest = sha256(b"hello world")
hex_digest = to_hex(digest)

# Keccak-256 (Ethereum compatible)
eth_hash = keccak256(b"hello world")
```

### Signing

```python
from hush import generate_keypair, sign, verify

# Generate Ed25519 keypair
private_key, public_key = generate_keypair()

# Sign a message
message = b"important data"
signature = sign(message, private_key)

# Verify signature
is_valid = verify(message, signature, public_key)
```

### Receipts

```python
from hush import SignedReceipt, verify_receipt

class SignedReceipt:
    receipt: Receipt
    signature: bytes
    public_key: str

    def to_json(self) -> str: ...
    @classmethod
    def from_json(cls, json_str: str) -> "SignedReceipt": ...

# Verify a receipt
is_valid = verify_receipt(signed_receipt, public_key)
```

## Policy Types

```python
from hush import Policy, GuardConfig

class Policy:
    version: str
    name: str
    extends: str | None
    settings: PolicySettings
    guards: dict[str, GuardConfig]

class PolicySettings:
    fail_fast: bool
    verbose_logging: bool
    session_timeout_secs: int | None
```

## Error Types

```python
from hush import (
    PolicyValidationError,
    GuardError,
    SignatureError,
    SanitizationError,
)

class PolicyValidationError(Exception):
    validation_errors: list[str]

class GuardError(Exception):
    guard_name: str
    message: str

class SignatureError(Exception):
    pass

class SanitizationError(Exception):
    pass
```

## Type Stubs

Full type stubs are provided for IDE support:

```python
# All types are exported from the main module
from hush import (
    # Core
    HushEngine,
    GuardContext,
    GuardResult,
    GuardAction,
    Verdict,
    Violation,

    # Jailbreak
    JailbreakDetector,
    JailbreakDetectionResult,
    JailbreakSignal,
    JailbreakCategory,

    # Sanitization
    OutputSanitizer,
    SanitizationResult,
    SensitiveDataFinding,
    RedactionStrategy,

    # Watermarking
    PromptWatermarker,
    WatermarkExtractor,
    WatermarkedPrompt,

    # Crypto
    sha256,
    keccak256,
    sign,
    verify,
    generate_keypair,
    SignedReceipt,

    # Errors
    PolicyValidationError,
    GuardError,
)
```

## Async/Sync API

All async methods have sync counterparts with `_sync` suffix:

```python
# Async
result = await engine.check_file_access(path, ctx)

# Sync
result = engine.check_file_access_sync(path, ctx)
```

## Thread Safety

- `HushEngine` is thread-safe for concurrent checks
- `JailbreakDetector` session state uses thread-safe collections
- `OutputSanitizer` is stateless and thread-safe
- `PromptWatermarker` signing operations are thread-safe
