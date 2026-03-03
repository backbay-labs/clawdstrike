package adapter

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/backbay-labs/clawdstrike-go/guards"
	"github.com/backbay-labs/clawdstrike-go/internal"
)

// AuditEvent records a security-relevant event.
type AuditEvent struct {
	ID        string
	Type      string
	Timestamp time.Time
	ContextID string
	SessionID string
	ToolName  string
	Decision  *guards.Decision
	Details   interface{}
}

func NewAuditEvent(eventType, toolName string, decision *guards.Decision) AuditEvent {
	return AuditEvent{
		ID:        internal.CreateID("audit"),
		Type:      eventType,
		Timestamp: time.Now().UTC(),
		ToolName:  toolName,
		Decision:  decision,
	}
}

// AuditLogger defines the interface for audit event storage and retrieval.
type AuditLogger interface {
	Log(event AuditEvent) error
	GetSessionEvents(sessionID string) ([]AuditEvent, error)
	Export(format string) ([]byte, error)
}

// InMemoryAuditLogger is a simple in-memory audit logger for testing.
type InMemoryAuditLogger struct {
	mu     sync.Mutex
	events []AuditEvent
}

func NewInMemoryAuditLogger() *InMemoryAuditLogger {
	return &InMemoryAuditLogger{}
}

func (l *InMemoryAuditLogger) Log(event AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
	return nil
}

func (l *InMemoryAuditLogger) GetSessionEvents(sessionID string) ([]AuditEvent, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var result []AuditEvent
	for _, e := range l.events {
		if e.SessionID == sessionID {
			result = append(result, e)
		}
	}
	return result, nil
}

// Export serializes events in the given format. Only "json" is supported.
func (l *InMemoryAuditLogger) Export(format string) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	switch format {
	case "json":
		return json.MarshalIndent(l.events, "", "  ")
	default:
		return nil, fmt.Errorf("unsupported export format: %q", format)
	}
}
