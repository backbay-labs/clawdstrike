package guards

import (
	"fmt"
	"strings"
)

// Jailbreak patterns for heuristic detection.
var jailbreakPatterns = []string{
	"do anything now",
	"dan mode",
	"developer mode",
	"jailbreak",
	"ignore all rules",
	"bypass all",
	"unrestricted mode",
	"no ethical guidelines",
	"no safety guidelines",
	"pretend you have no restrictions",
	"act as an unrestricted ai",
	"you have been freed",
	"maximum mode",
	"god mode",
	"sudo mode",
	"admin override",
}

// JailbreakGuard detects jailbreak attempts in user input.
type JailbreakGuard struct{}

// NewJailbreakGuard creates a jailbreak guard. Config is reserved for future native delegation.
func NewJailbreakGuard() *JailbreakGuard {
	return &JailbreakGuard{}
}

func (g *JailbreakGuard) Name() string { return "jailbreak" }

func (g *JailbreakGuard) Handles(action GuardAction) bool {
	return action.Type == "custom" && action.CustomType == "user_input"
}

func (g *JailbreakGuard) Check(action GuardAction, ctx *GuardContext) GuardResult {
	text, ok := action.CustomData.(string)
	if !ok {
		return Block(g.Name(), Error, "user_input data is not a string")
	}

	lower := strings.ToLower(text)
	matches := 0
	var matched []string

	for _, pat := range jailbreakPatterns {
		if strings.Contains(lower, pat) {
			matches++
			matched = append(matched, pat)
		}
	}

	if matches == 0 {
		return Allow(g.Name())
	}

	score := float64(matches) / 3.0
	if score > 1.0 {
		score = 1.0
	}

	details := map[string]interface{}{
		"score":           score,
		"matched_count":   matches,
		"matched_patterns": matched,
	}

	if matches >= 2 {
		return Block(g.Name(), Critical,
			fmt.Sprintf("jailbreak attempt detected (%d patterns matched)", matches)).
			WithDetails(details)
	}

	return Warn(g.Name(),
		fmt.Sprintf("possible jailbreak attempt (%d pattern matched)", matches)).
		WithDetails(details)
}
