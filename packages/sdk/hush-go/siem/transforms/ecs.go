// Package transforms converts SecurityEvents to standard SIEM schema formats.
package transforms

import (
	"github.com/backbay/clawdstrike-go/siem"
)

// ToECS converts a SecurityEvent to Elastic Common Schema (ECS) format.
func ToECS(event siem.SecurityEvent) map[string]interface{} {
	ecs := map[string]interface{}{
		"@timestamp": event.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z"),
		"ecs": map[string]string{
			"version": "8.11.0",
		},
		"event": map[string]interface{}{
			"kind":     "alert",
			"category": []string{"intrusion_detection"},
			"type":     []string{event.EventType},
			"id":       event.EventID,
			"outcome":  event.Outcome,
		},
		"agent": map[string]interface{}{
			"id":   event.Agent.ID,
			"name": event.Agent.Name,
			"type": event.Agent.Type,
		},
	}

	if event.Decision != nil {
		ecs["rule"] = map[string]interface{}{
			"name":     event.Decision.Guard,
			"severity": event.Decision.Severity,
		}
		ecs["message"] = event.Decision.Message
	}

	if event.Resource != nil {
		switch event.Resource.Type {
		case "file":
			ecs["file"] = map[string]string{"path": event.Resource.Path}
		case "network":
			ecs["destination"] = map[string]string{"domain": event.Resource.Host}
		case "tool":
			ecs["process"] = map[string]string{"name": event.Resource.Tool}
		}
	}

	if event.Threat != nil {
		ecs["threat"] = map[string]interface{}{
			"indicator": map[string]interface{}{
				"confidence": event.Threat.Confidence,
			},
			"technique": map[string]interface{}{
				"name": event.Threat.Category,
			},
		}
	}

	if len(event.Labels) > 0 {
		ecs["labels"] = event.Labels
	}

	return ecs
}
