# Installation

Clawdstrike ships as a Rust workspace with a CLI (`clawdstrike`) and libraries (`clawdstrike`, `hush-core`, `hush-proxy`).

## Rust CLI (`clawdstrike`)

### From source (recommended)

```bash
# From a workspace checkout
cargo install --path crates/services/hush-cli
```

### From crates.io (if published)

If your environment has `hush-cli` available in a Cargo registry:

```bash
cargo install hush-cli
```

### Verify installation

```bash
clawdstrike --version
```

## Daemon (`hushd` / `clawdstriked`) (optional)

`hushd` (`clawdstriked` is an alias binary) is an HTTP daemon that can evaluate checks server-side. It is still evolving, so treat it as optional/WIP.

```bash
cargo install --path crates/services/hushd
```

You can start it via the CLI:

```bash
clawdstrike daemon start
```

## TypeScript SDK

```bash
npm install @clawdstrike/sdk
```

For `PolicyLab` examples (`observe -> synth -> tighten`), use a package build that includes PolicyLab-enabled WASM bindings.

```typescript
import { Clawdstrike } from "@clawdstrike/sdk";

const cs = Clawdstrike.withDefaults("strict");
const decision = await cs.checkFile("~/.ssh/id_rsa", "read");
```

## Python SDK

```bash
pip install clawdstrike
```

For `PolicyLab` examples, use a wheel that includes the bundled native extension with PolicyLab support.

```python
from clawdstrike import Clawdstrike

cs = Clawdstrike.with_defaults("strict")
decision = cs.check_file("/etc/shadow")
print(decision.denied)  # True
```

Origin-aware policies work on the native Python backend and through `hushd`. The pure-Python
fallback rejects origin-aware usage fail-closed.

## Go SDK

```bash
go get github.com/backbay-labs/clawdstrike-go
```

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

For origin-aware policies in Go, use `clawdstrike.FromDaemon(...)` against `hushd`.

## Requirements

- Rust `1.93+` (workspace `rust-version`)

## Next Steps

- [Quick Start](./quick-start.md) - Get running in 5 minutes
- [Your First Policy](./first-policy.md) - Write a custom policy
