module spider-sense-threat-intel-go-example

go 1.24.0

require github.com/backbay-labs/clawdstrike-go v0.0.0

require (
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/backbay-labs/clawdstrike-go => ../../../packages/sdk/hush-go
