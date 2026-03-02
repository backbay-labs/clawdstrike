// Package cli provides a bridge to the Clawdstrike CLI binary for policy
// evaluation. This allows Go programs to delegate policy decisions to the
// standalone hush CLI, which supports the full policy resolution pipeline.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// Default timeout for CLI invocations.
const defaultTimeout = 30 * time.Second

// CLIBridge invokes the Clawdstrike CLI binary for policy evaluation.
// Fail-closed: errors, timeouts, and unexpected exit codes result in deny.
type CLIBridge struct {
	binaryPath string
	timeout    time.Duration
	pathErr    error
}

// validateBinaryPath checks that a binary path does not contain shell metacharacters.
func validateBinaryPath(path string) error {
	for _, c := range path {
		switch c {
		case ';', '|', '&', '$', '`', '(', ')':
			return fmt.Errorf("binary path contains shell metacharacter %q", string(c))
		}
	}
	return nil
}

// NewCLIBridge creates a bridge to the CLI binary at the given path.
// If the path contains shell metacharacters, all subsequent checks will deny.
func NewCLIBridge(binaryPath string) *CLIBridge {
	b := &CLIBridge{
		binaryPath: binaryPath,
		timeout:    defaultTimeout,
	}
	b.pathErr = validateBinaryPath(binaryPath)
	return b
}

func (b *CLIBridge) WithTimeout(d time.Duration) *CLIBridge {
	b.timeout = d
	return b
}

// PolicyEvent describes an action to be evaluated by the CLI.
type PolicyEvent struct {
	Type     string                 `json:"type"`
	Path     string                 `json:"path,omitempty"`
	Content  string                 `json:"content,omitempty"`
	Host     string                 `json:"host,omitempty"`
	ToolName string                 `json:"tool_name,omitempty"`
	Args     map[string]interface{} `json:"args,omitempty"`
}

// CLIResponse is the JSON response from the CLI binary.
type CLIResponse struct {
	Status   string      `json:"status"`
	Guard    string      `json:"guard,omitempty"`
	Severity string      `json:"severity,omitempty"`
	Message  string      `json:"message,omitempty"`
	Details  interface{} `json:"details,omitempty"`
}

// CLIDecision is the result of a CLI policy evaluation.
// This is distinct from guards.Decision as it represents the external CLI protocol.
type CLIDecision struct {
	Status   string
	Guard    string
	Severity string
	Message  string
	Details  interface{}
}

// Check evaluates a policy event using the CLI binary.
// Exit codes: 0=allow, 1=warn, 2=deny. Any error returns deny (fail-closed).
func (b *CLIBridge) Check(ctx context.Context, event PolicyEvent) (*CLIDecision, error) {
	if b.pathErr != nil {
		return denyDecision("cli_bridge",
			fmt.Sprintf("invalid binary path: %v", b.pathErr)), nil
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return denyDecision("cli_bridge", fmt.Sprintf("failed to marshal event: %v", err)), nil
	}

	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, b.binaryPath, "policy", "eval", "-", "--json")
	cmd.Stdin = bytes.NewReader(eventJSON)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()

	// Check for context deadline (timeout)
	if ctx.Err() != nil {
		return denyDecision("cli_bridge",
			fmt.Sprintf("CLI timed out after %v", b.timeout)), nil
	}

	// Parse exit code
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			// Non-exit error (binary not found, permission denied, etc.)
			return denyDecision("cli_bridge",
				fmt.Sprintf("CLI execution error: %v", err)), nil
		}
	}

	// Parse JSON response
	var resp CLIResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		// Cannot parse response → fail-closed
		return denyDecision("cli_bridge",
			fmt.Sprintf("failed to parse CLI response: %v", err)), nil
	}

	// Prefer the JSON Status field if present; fall back to exit code mapping.
	var status string
	if resp.Status != "" {
		status = resp.Status
	} else {
		switch exitCode {
		case 0:
			status = "allow"
		case 1:
			status = "warn"
		case 2:
			status = "deny"
		default:
			// Unknown exit code → fail-closed
			status = "deny"
			resp.Message = fmt.Sprintf("unexpected exit code %d: %s", exitCode, resp.Message)
		}
	}

	return &CLIDecision{
		Status:   status,
		Guard:    resp.Guard,
		Severity: resp.Severity,
		Message:  resp.Message,
		Details:  resp.Details,
	}, nil
}

func denyDecision(guard, message string) *CLIDecision {
	return &CLIDecision{
		Status:   "deny",
		Guard:    guard,
		Severity: "critical",
		Message:  message,
	}
}

