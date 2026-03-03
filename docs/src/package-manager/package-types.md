# Package Types

`pkg init` supports these package types:

- `guard`: runtime guard plugin package
- `policy-pack`: packaged policy/ruleset content
- `adapter`: integration adapter package scaffold
- `engine`: alternate engine package scaffold
- `template`: reusable template package scaffold
- `bundle`: meta-package that can include dependencies

The package manifest is always `clawdstrike-pkg.toml` with at least:

```toml
[package]
name = "@scope/name"
version = "1.0.0"
pkg_type = "guard"
```
