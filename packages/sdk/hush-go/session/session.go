// Package session implements stateful security sessions that track check
// counts, violations, and blocked actions across multiple guard evaluations.
package session

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/backbay-labs/clawdstrike-go/guards"
	"github.com/backbay-labs/clawdstrike-go/internal"
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

func (s *ClawdstrikeSession) ID() string {
	return s.id
}

// Check evaluates an action, updates counters, and returns a decision.
func (s *ClawdstrikeSession) Check(action guards.GuardAction) guards.Decision {
	ctx := guards.NewContext().WithSessionID(s.id)
	if s.agentID != "" {
		ctx = ctx.WithAgentID(s.agentID)
	}

	s.checkCount.Add(1)
	result := s.engine.CheckAction(action, ctx)

	decision := guards.DecisionFromResult(result)
	switch decision.Status {
	case guards.StatusDeny:
		s.denyCount.Add(1)
		s.mu.Lock()
		s.blockedActions = append(s.blockedActions, action.Type)
		s.mu.Unlock()
	case guards.StatusWarn:
		s.warnCount.Add(1)
	default:
		s.allowCount.Add(1)
	}

	return decision
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
// The mutex is held for the entire snapshot to ensure consistency
// between the blocked actions list and the atomic counters.
func (s *ClawdstrikeSession) GetSummary() SessionSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	blocked := make([]string, len(s.blockedActions))
	copy(blocked, s.blockedActions)
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
