package clawdstrike

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/backbay-labs/clawdstrike-go/guards"
	"github.com/backbay-labs/clawdstrike-go/internal"
)

type daemonChecker struct {
	url    string
	apiKey string
	client *http.Client
	retry  daemonRetryConfig
}

type daemonRetryConfig struct {
	attempts int
	backoff  time.Duration
}

type daemonCheckRequest struct {
	ActionType string                 `json:"action_type"`
	Target     string                 `json:"target"`
	Content    string                 `json:"content,omitempty"`
	Args       map[string]interface{} `json:"args,omitempty"`
	SessionID  string                 `json:"session_id,omitempty"`
	AgentID    string                 `json:"agent_id,omitempty"`
}

type daemonCheckResponse struct {
	Allowed  bool        `json:"allowed"`
	Guard    string      `json:"guard"`
	Severity string      `json:"severity"`
	Message  string      `json:"message"`
	Details  interface{} `json:"details,omitempty"`
}

func newDaemonChecker(rawURL string, cfg DaemonConfig) (*daemonChecker, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(rawURL), "/")
	if trimmed == "" {
		return nil, fmt.Errorf("daemon URL is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid daemon URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid daemon URL %q: expected absolute URL", rawURL)
	}

	client := cfg.HTTPClient
	if client == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = DefaultDaemonConfig().Timeout
		}
		client = &http.Client{Timeout: timeout}
	}
	if cfg.Timeout > 0 && cfg.HTTPClient != nil {
		cloned := *cfg.HTTPClient
		cloned.Timeout = cfg.Timeout
		client = &cloned
	}
	attempts := cfg.RetryAttempts
	if attempts < 1 {
		attempts = 1
	}

	return &daemonChecker{
		url:    trimmed,
		apiKey: cfg.APIKey,
		client: client,
		retry: daemonRetryConfig{
			attempts: attempts,
			backoff:  cfg.RetryBackoff,
		},
	}, nil
}

func (d *daemonChecker) CheckAction(action guards.GuardAction, guardCtx *guards.GuardContext) guards.GuardResult {
	reqBody, err := toDaemonRequest(action, guardCtx)
	if err != nil {
		return daemonFailure(fmt.Sprintf("Invalid daemon request: %v", err))
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return daemonFailure(fmt.Sprintf("Failed to encode daemon request: %v", err))
	}

	requestCtx := daemonRequestContext(guardCtx)

	var lastFailure string
	for attempt := 1; attempt <= d.retry.attempts; attempt++ {
		if err := requestCtx.Err(); err != nil {
			return daemonFailure(fmt.Sprintf("Daemon check canceled: %v", err))
		}
		result, retryable, failure := d.doRequest(requestCtx, body)
		if failure == "" {
			return result
		}
		lastFailure = failure
		if attempt == d.retry.attempts || !retryable {
			break
		}
		wait := daemonRetryDelay(d.retry.backoff, attempt)
		if wait > 0 {
			if !internal.SleepWithContext(requestCtx, wait) {
				return daemonFailure(fmt.Sprintf("Daemon check canceled: %v", requestCtx.Err()))
			}
		}
	}
	return daemonFailure(lastFailure)
}

func (d *daemonChecker) doRequest(requestCtx context.Context, body []byte) (guards.GuardResult, bool, string) {
	if requestCtx == nil {
		requestCtx = context.Background()
	}
	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodPost,
		d.url+"/api/v1/check",
		bytes.NewReader(body),
	)
	if err != nil {
		return guards.GuardResult{}, false, fmt.Sprintf("Failed to build daemon request: %v", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")
	if d.apiKey != "" {
		req.Header.Set("authorization", "Bearer "+d.apiKey)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return guards.GuardResult{}, true, fmt.Sprintf("Daemon check failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return guards.GuardResult{}, true, fmt.Sprintf("Daemon response read failed: %v", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		detail := strings.TrimSpace(string(respBody))
		if detail != "" {
			return guards.GuardResult{}, retryable, fmt.Sprintf("Daemon check failed with HTTP %d: %s", resp.StatusCode, detail)
		}
		return guards.GuardResult{}, retryable, fmt.Sprintf("Daemon check failed with HTTP %d", resp.StatusCode)
	}

	var parsed daemonCheckResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return guards.GuardResult{}, false, "Daemon returned invalid JSON"
	}
	if parsed.Guard == "" || parsed.Severity == "" || parsed.Message == "" {
		return guards.GuardResult{}, false, "Daemon returned malformed decision payload"
	}

	sev, err := guards.ParseSeverity(parsed.Severity)
	if err != nil {
		sev = guards.Error
	}
	return guards.GuardResult{
		Allowed:  parsed.Allowed,
		Guard:    parsed.Guard,
		Severity: sev,
		Message:  parsed.Message,
		Details:  parsed.Details,
	}, false, ""
}

func daemonFailure(message string) guards.GuardResult {
	return guards.Block("daemon", guards.Critical, message)
}

func toDaemonRequest(action guards.GuardAction, ctx *guards.GuardContext) (daemonCheckRequest, error) {
	req := daemonCheckRequest{}

	switch action.Type {
	case "file_access":
		req.ActionType = "file_access"
		req.Target = action.Path
	case "file_write":
		req.ActionType = "file_write"
		req.Target = action.Path
		req.Content = string(action.Content)
	case "network_egress":
		req.ActionType = "egress"
		if action.Host != "" {
			if action.Port > 0 {
				req.Target = action.Host + ":" + strconv.Itoa(action.Port)
			} else {
				req.Target = action.Host
			}
		}
	case "shell_command":
		req.ActionType = "shell"
		req.Target = action.Command
	case "mcp_tool":
		req.ActionType = "mcp_tool"
		req.Target = action.ToolName
		if action.ToolArgs != nil {
			args, err := toDaemonArgs(action.ToolArgs)
			if err != nil {
				return daemonCheckRequest{}, err
			}
			req.Args = args
		}
	case "patch":
		req.ActionType = "patch"
		req.Target = action.Path
		req.Content = action.Diff
	default:
		return daemonCheckRequest{}, fmt.Errorf("unsupported action type for daemon mode: %s", action.Type)
	}

	if req.Target == "" {
		return daemonCheckRequest{}, fmt.Errorf("%s requires a non-empty target", action.Type)
	}

	if ctx != nil {
		req.SessionID = ctx.SessionID
		req.AgentID = ctx.AgentID
	}

	return req, nil
}

func toDaemonArgs(v interface{}) (map[string]interface{}, error) {
	if args, ok := v.(map[string]interface{}); ok {
		return args, nil
	}

	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("args must be JSON-serializable: %w", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("args must be a JSON object")
	}
	return decoded, nil
}

func daemonRetryDelay(base time.Duration, attempt int) time.Duration {
	if base <= 0 || attempt <= 0 {
		return 0
	}
	return time.Duration(1<<(attempt-1)) * base
}

func daemonRequestContext(ctx *guards.GuardContext) context.Context {
	if ctx != nil && ctx.Context != nil {
		return ctx.Context
	}
	return context.Background()
}
