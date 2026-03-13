# clawdstrike-go

Go SDK for Clawdstrike security verification.

## Install

```bash
go get github.com/backbay-labs/clawdstrike-go
```

## Quick Start

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
}
```

## Origin-Aware Checks

Origin-aware enforcement currently works through hushd. The local Go engine
fails closed on origin-aware usage until local-engine parity exists.

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

Canonical wire behavior:

- outbound JSON uses snake_case origin fields
- inbound origin JSON accepts camelCase aliases
- `origin.output_send` is encoded as hushd `action_type: "output_send"`
- local engine usage with `origin` or `origin.output_send` is denied with guidance to use hushd
