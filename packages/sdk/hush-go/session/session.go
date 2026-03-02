// Package session implements stateful security sessions that track check
// counts, violations, and blocked actions across multiple guard evaluations.
package session

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/backbay/clawdstrike-go/guards"
	"github.com/backbay/clawdstrike-go/internal"
)

// Engine is the subset of engine.HushEngine that sessions require.
// Defined as an interface to avoid import cycles.
type Engine interface {
	CheckAction(action guards.GuardAction, ctx *guards.GuardContext) guards.GuardResult
}

// Options configures a new session.
type Options struct {
	ID      string
	AgentID string
}

// ClawdstrikeSession tracks security check state over a sequence of actions.
// All counter operations are safe for concurrent use.
type ClawdstrikeSession struct {
	id        string
	agentID   string
	engine    Engine
	createdAt time.Time

	checkCount atomic.Int64
	allowCount atomic.Int64
	warnCount  atomic.Int64
	denyCount  atomic.Int64

	mu             sync.Mutex
	blockedActions []string
}

// NewSession creates a new session bound to an engine.
func NewSession(eng Engine, opts Options) *ClawdstrikeSession {
	id := opts.ID
	if id == "" {
		id = internal.CreateID("sess")
	}
	return &ClawdstrikeSession{
		id:        id,
		agentID:   opts.AgentID,
		engine:    eng,
		createdAt: time.Now(),
	}
}

// ID returns the session identifier.
func (s *ClawdstrikeSession) ID() string {
	return s.id
}

// DecisionStatus represents the outcome of a security check.
type DecisionStatus string

const (
	StatusAllow DecisionStatus = "allow"
	StatusWarn  DecisionStatus = "warn"
	StatusDeny  DecisionStatus = "deny"
)

// Decision is the result of a session check.
type Decision struct {
	Status   DecisionStatus
	Guard    string
	Severity string
	Message  string
	Details  interface{}
}

// Check evaluates an action, updates counters, and returns a decision.
func (s *ClawdstrikeSession) Check(action guards.GuardAction) Decision {
	ctx := guards.NewContext().WithSessionID(s.id)
	if s.agentID != "" {
		ctx = ctx.WithAgentID(s.agentID)
	}

	result := s.engine.CheckAction(action, ctx)
	s.checkCount.Add(1)

	var status DecisionStatus
	switch {
	case !result.Allowed:
		status = StatusDeny
		s.denyCount.Add(1)
		s.mu.Lock()
		s.blockedActions = append(s.blockedActions, action.Type)
		s.mu.Unlock()
	case result.Severity >= guards.Warning:
		status = StatusWarn
		s.warnCount.Add(1)
	default:
		status = StatusAllow
		s.allowCount.Add(1)
	}

	return Decision{
		Status:   status,
		Guard:    result.Guard,
		Severity: result.Severity.String(),
		Message:  result.Message,
		Details:  result.Details,
	}
}

// SessionSummary captures the aggregated state of a session.
type SessionSummary struct {
	ID             string
	CheckCount     int64
	AllowCount     int64
	WarnCount      int64
	DenyCount      int64
	BlockedActions []string
	Duration       time.Duration
}

// GetSummary returns a snapshot of the session's state.
func (s *ClawdstrikeSession) GetSummary() SessionSummary {
	s.mu.Lock()
	blocked := make([]string, len(s.blockedActions))
	copy(blocked, s.blockedActions)
	s.mu.Unlock()

	return SessionSummary{
		ID:             s.id,
		CheckCount:     s.checkCount.Load(),
		AllowCount:     s.allowCount.Load(),
		WarnCount:      s.warnCount.Load(),
		DenyCount:      s.denyCount.Load(),
		BlockedActions: blocked,
		Duration:       time.Since(s.createdAt),
	}
}
