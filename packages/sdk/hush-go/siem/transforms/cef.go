package transforms

import (
	"fmt"
	"strings"

	"github.com/backbay-labs/clawdstrike-go/siem"
)

// CEF severity mapping.
var severityToCEF = map[string]int{
	"info":     1,
	"warning":  5,
	"warn":     5,
	"error":    8,
	"low":      3,
	"medium":   5,
	"high":     7,
	"critical": 10,
}

// ToCEF converts a SecurityEvent to Common Event Format (ArcSight) string.
// Format: CEF:0|vendor|product|version|signatureId|name|severity|extensions
func ToCEF(event siem.SecurityEvent) string {
	severity := 0
	name := event.EventType
	signatureID := event.EventType

	if event.Decision != nil {
		if s, ok := severityToCEF[event.Decision.Severity]; ok {
			severity = s
		}
		name = event.Decision.Guard
	}

	extensions := []string{
		fmt.Sprintf("rt=%d", event.Timestamp.UnixMilli()),
		fmt.Sprintf("externalId=%s", cefEscape(event.EventID)),
		fmt.Sprintf("outcome=%s", event.Outcome),
	}

	if event.Agent.ID != "" {
		extensions = append(extensions, fmt.Sprintf("suid=%s", cefEscape(event.Agent.ID)))
	}
	if event.Agent.Name != "" {
		extensions = append(extensions, fmt.Sprintf("suser=%s", cefEscape(event.Agent.Name)))
	}

	if event.Resource != nil {
		switch event.Resource.Type {
		case "file":
			extensions = append(extensions, fmt.Sprintf("filePath=%s", cefEscape(event.Resource.Path)))
		case "network":
			extensions = append(extensions, fmt.Sprintf("dhost=%s", cefEscape(event.Resource.Host)))
		case "tool":
			extensions = append(extensions, fmt.Sprintf("cs1=%s cs1Label=tool", cefEscape(event.Resource.Tool)))
		}
	}

	if event.Decision != nil && event.Decision.Message != "" {
		extensions = append(extensions, fmt.Sprintf("msg=%s", cefEscape(event.Decision.Message)))
	}

	return fmt.Sprintf("CEF:0|Backbay|Clawdstrike|1.0|%s|%s|%d|%s",
		cefEscape(signatureID),
		cefEscape(name),
		severity,
		strings.Join(extensions, " "),
	)
}

// cefEscape escapes special characters in CEF field values.
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}
