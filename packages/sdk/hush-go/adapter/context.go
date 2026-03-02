package adapter

import (
	"sync"
	"sync/atomic"

	"github.com/backbay/clawdstrike-go/internal"
)

// SecurityContext tracks security state for an adapter session.
type SecurityContext struct {
	ID             string
	SessionID      string
	CheckCount     atomic.Int64
	ViolationCount atomic.Int64

	mu          sync.Mutex
	AuditEvents []AuditEvent
	BlockedTools []string
}

// NewSecurityContext creates a new security context with a generated ID.
func NewSecurityContext(sessionID string) *SecurityContext {
	return &SecurityContext{
		ID:        internal.CreateID("sctx"),
		SessionID: sessionID,
	}
}

// RecordCheck increments the check counter.
func (sc *SecurityContext) RecordCheck() {
	sc.CheckCount.Add(1)
}

// RecordViolation increments the violation counter and records the blocked tool.
func (sc *SecurityContext) RecordViolation(toolName string) {
	sc.ViolationCount.Add(1)
	sc.mu.Lock()
	sc.BlockedTools = append(sc.BlockedTools, toolName)
	sc.mu.Unlock()
}

// AddAuditEvent appends an audit event to the context.
func (sc *SecurityContext) AddAuditEvent(event AuditEvent) {
	sc.mu.Lock()
	sc.AuditEvents = append(sc.AuditEvents, event)
	sc.mu.Unlock()
}

// GetBlockedTools returns a snapshot of blocked tool names.
func (sc *SecurityContext) GetBlockedTools() []string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	result := make([]string, len(sc.BlockedTools))
	copy(result, sc.BlockedTools)
	return result
}
