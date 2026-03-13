package adapter

import (
	"sync"
	"sync/atomic"

	"github.com/backbay-labs/clawdstrike-go/guards"
	"github.com/backbay-labs/clawdstrike-go/internal"
)

// SecurityContext tracks security state for an adapter session.
type SecurityContext struct {
	ID             string
	SessionID      string
	origin         *guards.OriginContext
	CheckCount     atomic.Int64
	ViolationCount atomic.Int64

	mu           sync.Mutex
	blockedTools []string
}

func NewSecurityContext(sessionID string) *SecurityContext {
	return &SecurityContext{
		ID:        internal.CreateID("sctx"),
		SessionID: sessionID,
	}
}

func (sc *SecurityContext) RecordCheck() {
	sc.CheckCount.Add(1)
}

func (sc *SecurityContext) RecordViolation(toolName string) {
	sc.ViolationCount.Add(1)
	sc.mu.Lock()
	sc.blockedTools = append(sc.blockedTools, toolName)
	sc.mu.Unlock()
}

func (sc *SecurityContext) GetBlockedTools() []string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	result := make([]string, len(sc.blockedTools))
	copy(result, sc.blockedTools)
	return result
}

func (sc *SecurityContext) WithOrigin(origin *guards.OriginContext) *SecurityContext {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.origin = origin.Clone()
	return sc
}

func (sc *SecurityContext) Origin() *guards.OriginContext {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.origin.Clone()
}
