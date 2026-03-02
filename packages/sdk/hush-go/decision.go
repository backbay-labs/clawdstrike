package clawdstrike

import "github.com/backbay/clawdstrike-go/guards"

// DecisionStatus represents the outcome of a security check.
type DecisionStatus string

const (
	// StatusAllow means the action is permitted.
	StatusAllow DecisionStatus = "allow"
	// StatusWarn means the action is permitted but flagged.
	StatusWarn DecisionStatus = "warn"
	// StatusDeny means the action is blocked.
	StatusDeny DecisionStatus = "deny"
)

// Decision is the user-facing result of a Clawdstrike security check.
type Decision struct {
	Status   DecisionStatus
	Guard    string
	Severity string
	Message  string
	Details  interface{}
}

// decisionFromGuardResult converts an internal GuardResult to a Decision.
func decisionFromGuardResult(r guards.GuardResult) Decision {
	status := StatusAllow
	if !r.Allowed {
		status = StatusDeny
	} else if r.Severity >= guards.Warning {
		status = StatusWarn
	}
	return Decision{
		Status:   status,
		Guard:    r.Guard,
		Severity: r.Severity.String(),
		Message:  r.Message,
		Details:  r.Details,
	}
}
