package transforms

import (
	"github.com/backbay-labs/clawdstrike-go/siem"
)

// OCSF Activity IDs for Security Finding.
const (
	ocsfClassUID    = 2001 // Security Finding
	ocsfActivityNew = 1    // Create
)

// outcomeToOCSF maps Clawdstrike outcomes to OCSF status IDs.
var outcomeToOCSF = map[string]int{
	"allow": 1, // Success
	"deny":  2, // Failure
	"warn":  0, // Unknown
}

// severityToOCSF maps severity strings to OCSF severity IDs.
var severityToOCSF = map[string]int{
	"info":     1,
	"warning":  3,
	"warn":     3,
	"error":    4,
	"low":      2,
	"medium":   3,
	"high":     4,
	"critical": 5,
}

// ToOCSF converts a SecurityEvent to Open Cybersecurity Schema Framework format.
func ToOCSF(event siem.SecurityEvent) map[string]interface{} {
	statusID := 0
	if id, ok := outcomeToOCSF[event.Outcome]; ok {
		statusID = id
	}

	ocsf := map[string]interface{}{
		"class_uid":   ocsfClassUID,
		"activity_id": ocsfActivityNew,
		"time":        event.Timestamp.UnixMilli(),
		"status_id":   statusID,
		"message":     event.EventType,
		"metadata": map[string]interface{}{
			"version":      event.SchemaVersion,
			"product":      map[string]string{"name": "clawdstrike", "vendor_name": "backbay"},
			"original_uid": event.EventID,
		},
		"actor": map[string]interface{}{
			"agent": map[string]interface{}{
				"uid":       event.Agent.ID,
				"name":      event.Agent.Name,
				"type_name": event.Agent.Type,
			},
		},
	}

	if event.Decision != nil {
		sevID := 0
		if id, ok := severityToOCSF[event.Decision.Severity]; ok {
			sevID = id
		}
		ocsf["severity_id"] = sevID
		ocsf["finding"] = map[string]interface{}{
			"title":   event.Decision.Guard,
			"message": event.Decision.Message,
		}
	}

	if event.Resource != nil {
		resources := []map[string]interface{}{
			{
				"type": event.Resource.Type,
				"name": resourceName(event.Resource),
			},
		}
		ocsf["resources"] = resources
	}

	if event.Threat != nil {
		ocsf["confidence_id"] = int(event.Threat.Confidence * 10)
		ocsf["analytic"] = map[string]interface{}{
			"category": event.Threat.Category,
		}
	}

	return ocsf
}

func resourceName(r *siem.ResourceInfo) string {
	switch r.Type {
	case "file":
		return r.Path
	case "network":
		return r.Host
	case "tool":
		return r.Tool
	default:
		return ""
	}
}
