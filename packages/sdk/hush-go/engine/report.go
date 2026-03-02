package engine

import (
	"time"

	"github.com/backbay/clawdstrike-go/guards"
)

// GuardResultEntry records one guard's evaluation result with timing.
type GuardResultEntry struct {
	GuardName string
	Result    guards.GuardResult
	Duration  time.Duration
}

// GuardReport aggregates results from all guards for a single action check.
type GuardReport struct {
	Results       []GuardResultEntry
	Allowed       bool
	TotalDuration time.Duration
}

// DeniedEntries returns only the entries that denied the action.
func (r *GuardReport) DeniedEntries() []GuardResultEntry {
	var denied []GuardResultEntry
	for _, e := range r.Results {
		if !e.Result.Allowed {
			denied = append(denied, e)
		}
	}
	return denied
}

// WarningEntries returns entries that allowed but flagged with warnings.
func (r *GuardReport) WarningEntries() []GuardResultEntry {
	var warnings []GuardResultEntry
	for _, e := range r.Results {
		if e.Result.Allowed && e.Result.Severity >= guards.Warning {
			warnings = append(warnings, e)
		}
	}
	return warnings
}
