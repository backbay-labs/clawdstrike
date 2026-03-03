# clawdstrike pkg init

Initialize a new package scaffold in the current directory.

## Usage

```bash
clawdstrike pkg init --pkg-type <guard|policy-pack|adapter|engine|template|bundle> --name <@scope/name|name>
```

## What It Creates

- `clawdstrike-pkg.toml`
- Type-specific starter files
- Minimal package layout for `pkg pack` and `pkg publish`

## Example

```bash
clawdstrike pkg init --pkg-type guard --name @acme/demo-guard
```
