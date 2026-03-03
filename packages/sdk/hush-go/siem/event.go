// Package siem provides security event types and an event bus for exporting
// Clawdstrike security events to SIEM platforms.
package siem

import "time"

// SecurityEvent represents a security-relevant event from the Clawdstrike runtime.
type SecurityEvent struct {
	SchemaVersion string                 `json:"schema_version"`
	EventID       string                 `json:"event_id"`
	EventType     string                 `json:"event_type"`
	Timestamp     time.Time              `json:"timestamp"`
	Agent         AgentInfo              `json:"agent,omitempty"`
	Session       SessionInfo            `json:"session,omitempty"`
	Outcome       string                 `json:"outcome"` // "allow", "deny", "warn"
	Decision      *DecisionInfo          `json:"decision,omitempty"`
	Resource      *ResourceInfo          `json:"resource,omitempty"`
	Threat        *ThreatInfo            `json:"threat,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	Labels        map[string]string      `json:"labels,omitempty"`
}

// AgentInfo identifies the AI agent that triggered the event.
type AgentInfo struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

// SessionInfo identifies the session context.
type SessionInfo struct {
	ID        string    `json:"id"`
	StartTime time.Time `json:"start_time,omitempty"`
}

// DecisionInfo captures the guard decision details.
type DecisionInfo struct {
	Guard    string `json:"guard"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// ResourceInfo describes the resource being accessed.
type ResourceInfo struct {
	Type string `json:"type"` // "file", "network", "tool"
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
	Tool string `json:"tool,omitempty"`
}

// ThreatInfo provides threat intelligence context.
type ThreatInfo struct {
	Category   string   `json:"category"`
	Confidence float64  `json:"confidence"`
	Indicators []string `json:"indicators,omitempty"`
}
