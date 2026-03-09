# Go API Reference

The Go SDK lives under `packages/sdk/hush-go` and is published as `github.com/backbay-labs/clawdstrike-go`.

It provides:

- `clawdstrike.Clawdstrike` facade with built-in rulesets and typed check helpers
- `guards.Decision` return type with `Status`, `Message`, `Guard`, and per-guard details
- local Rust-backed policy evaluation for the core guard surface
- daemon-backed evaluation through `hushd`
- stateful sessions via `session.ClawdstrikeSession`
- origin context and `origin.output_send` transport helpers for daemon-backed origin enforcement

## Installation

```bash
go get github.com/backbay-labs/clawdstrike-go
```

## Facade API

```go
package main

import (
	"fmt"

	clawdstrike "github.com/backbay-labs/clawdstrike-go"
)

func main() {
	cs, err := clawdstrike.WithDefaults("strict")
	if err != nil {
		panic(err)
	}

	decision := cs.CheckFileAccess("/etc/shadow")
	fmt.Println(decision.Status, decision.Message)

	decision = cs.CheckShell("rm -rf /")
	fmt.Println(decision.Status, decision.Guard)
}
```

## Loading from policy or daemon

```go
package main

import (
	"time"

	clawdstrike "github.com/backbay-labs/clawdstrike-go"
)

func main() {
	cs, err := clawdstrike.FromPolicy("./policy.yaml")
	if err != nil {
		panic(err)
	}
	_ = cs

	remote, err := clawdstrike.FromDaemon("https://hushd.example.com", "dev-token")
	if err != nil {
		panic(err)
	}
	_ = remote
}
```

For daemon-backed evaluation with explicit transport settings:

```go
remote, err := clawdstrike.FromDaemonWithConfig("https://hushd.example.com", clawdstrike.DaemonConfig{
	APIKey:        "dev-token",
	Timeout:       15 * time.Second,
	RetryAttempts: 3,
	RetryBackoff:  250 * time.Millisecond,
})
if err != nil {
	panic(err)
}
_ = remote
```

## Sessions

```go
package main

import (
	"fmt"

	clawdstrike "github.com/backbay-labs/clawdstrike-go"
)

func main() {
	cs, err := clawdstrike.WithDefaults("strict")
	if err != nil {
		panic(err)
	}

	session := cs.Session(clawdstrike.SessionOptions{
		ID:      "sess-123",
		AgentID: "triage-bot",
	})

	decision := session.CheckFileAccess("/srv/runbook.md")
	summary := session.GetSummary()

	fmt.Println(decision.Status)
	fmt.Println(summary.CheckCount, summary.DenyCount)
}
```

Session checks keep the session's own `session_id` and `agent_id` pinned. Per-check `origin`,
`cwd`, `context.Context`, and metadata can still vary.

## Origin-aware checks

Current support is intentionally split by backend:

- local Go engine: fails closed for `origin` and `origin.output_send`
- daemon-backed Go SDK: supports `GuardContext.Origin`, session-aware origin tracking, and `origin.output_send`

Example:

```go
package main

import (
	"fmt"

	clawdstrike "github.com/backbay-labs/clawdstrike-go"
	"github.com/backbay-labs/clawdstrike-go/guards"
)

func main() {
	cs, err := clawdstrike.FromDaemon("https://hushd.example.com", "dev-token")
	if err != nil {
		panic(err)
	}

	origin := guards.NewOriginContext(guards.OriginProviderSlack).
		WithTenantID("T123").
		WithSpaceID("C456").
		WithActorRole("incident_commander")

	decision := cs.CheckWithContext(
		guards.McpTool("read_file", map[string]interface{}{"path": "/srv/runbook.md"}),
		guards.NewContext().WithOrigin(origin),
	)
	fmt.Println(decision.Status, decision.Message)

	session := cs.Session(clawdstrike.SessionOptions{
		ID:      "sess-123",
		AgentID: "triage-bot",
	})

	sendDecision := session.CheckWithContext(
		guards.NewOutputSendPayload("Posting sanitized status update").
			WithTarget("slack://incident-room").
			WithMimeType("text/plain").
			WithMetadata(map[string]interface{}{"thread_id": "1712502451.000100"}).
			GuardAction(),
		guards.NewContext().WithOrigin(origin),
	)
	fmt.Println(sendDecision.Status, sendDecision.Message)
}
```

Wire behavior:

- outbound daemon JSON uses canonical snake_case origin fields
- inbound origin JSON accepts camelCase aliases
- `origin.output_send` is translated to hushd `action_type: "output_send"`

## Local-engine limitation

If you pass `origin` to a local Go SDK instance created with `WithDefaults(...)`, `FromPolicy(...)`,
or `FromEngine(...)`, the SDK denies the request with guidance to use a daemon-backed instance. That
is intentional until local-engine origin-runtime parity exists in Go.

## See also

- [Installation](../../getting-started/installation.md)
- [Origin Enclaves](../../guides/origin-enclaves.md)
