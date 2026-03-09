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
	Origin     *guards.OriginContext  `json:"origin,omitempty"`
	SessionID  string                 `json:"session_id,omitempty"`
	AgentID    string                 `json:"agent_id,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type daemonCheckResponse struct {
	Allowed  bool        `json:"allowed"`
	Guard    string      `json:"guard"`
	Severity string      `json:"severity"`
	Message  string      `json:"message"`
	Details  interface{} `json:"details,omitempty"`
}

type daemonEvalRequest struct {
	EventID   string                 `json:"eventId"`
	EventType string                 `json:"eventType"`
	Timestamp string                 `json:"timestamp"`
	SessionID string                 `json:"sessionId,omitempty"`
	Data      daemonEvalCustomData   `json:"data"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type daemonEvalCustomData struct {
	Type       string `json:"type"`
	CustomType string `json:"customType"`
	Text       string `json:"text"`
	Source     string `json:"source,omitempty"`
}

type daemonEvalResponse struct {
	Report struct {
		Overall daemonCheckResponse `json:"overall"`
	} `json:"report"`
}

type daemonResponseDecoder func([]byte) (guards.GuardResult, string)

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
	if action.Type == "custom" && isDaemonUntrustedTextCustomType(action.CustomType) {
		return d.checkUntrustedText(action, guardCtx)
	}

	reqBody, err := toDaemonRequest(action, guardCtx)
	if err != nil {
		return daemonFailure(fmt.Sprintf("Invalid daemon request: %v", err))
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return daemonFailure(fmt.Sprintf("Failed to encode daemon request: %v", err))
	}

	return d.executeWithRetry(
		daemonRequestContext(guardCtx),
		"/api/v1/check",
		body,
		decodeDaemonCheckResponse,
	)
}

func (d *daemonChecker) SupportsOriginRuntime() bool {
	return true
}

func (d *daemonChecker) checkUntrustedText(
	action guards.GuardAction,
	guardCtx *guards.GuardContext,
) guards.GuardResult {
	text, source, err := extractUntrustedTextPayload(action.CustomData)
	if err != nil {
		return daemonFailure(fmt.Sprintf("Invalid daemon request: %v", err))
	}

	customType := action.CustomType
	if customType == "" {
		customType = "untrusted_text"
	}

	reqBody := daemonEvalRequest{
		EventID:   internal.CreateID("evt"),
		EventType: "custom",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Data: daemonEvalCustomData{
			Type:       "custom",
			CustomType: customType,
			Text:       text,
			Source:     source,
		},
	}

	if guardCtx != nil {
		reqBody.SessionID = guardCtx.SessionID
		reqBody.Metadata = daemonEvalMetadata(guardCtx)
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return daemonFailure(fmt.Sprintf("Failed to encode daemon request: %v", err))
	}

	return d.executeWithRetry(
		daemonRequestContext(guardCtx),
		"/api/v1/eval",
		body,
		decodeDaemonEvalResponse,
	)
}

func (d *daemonChecker) executeWithRetry(
	requestCtx context.Context,
	path string,
	body []byte,
	decode daemonResponseDecoder,
) guards.GuardResult {
	if requestCtx == nil {
		requestCtx = context.Background()
	}
	var lastFailure string
	for attempt := 1; attempt <= d.retry.attempts; attempt++ {
		if err := requestCtx.Err(); err != nil {
			return daemonFailure(fmt.Sprintf("Daemon check canceled: %v", err))
		}
		result, retryable, failure := d.doJSONRequest(requestCtx, path, body, decode)
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

func (d *daemonChecker) doJSONRequest(
	requestCtx context.Context,
	path string,
	body []byte,
	decode daemonResponseDecoder,
) (guards.GuardResult, bool, string) {
	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodPost,
		d.url+path,
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

	result, failure := decode(respBody)
	if failure != "" {
		return guards.GuardResult{}, false, failure
	}
	return result, false, ""
}

func daemonFailure(message string) guards.GuardResult {
	return guards.Block("daemon", guards.Critical, message)
}

func decodeDaemonCheckResponse(respBody []byte) (guards.GuardResult, string) {
	var parsed daemonCheckResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return guards.GuardResult{}, "Daemon returned invalid JSON"
	}
	if parsed.Guard == "" || parsed.Severity == "" || parsed.Message == "" {
		return guards.GuardResult{}, "Daemon returned malformed decision payload"
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
	}, ""
}

func decodeDaemonEvalResponse(respBody []byte) (guards.GuardResult, string) {
	var parsed daemonEvalResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return guards.GuardResult{}, "Daemon returned invalid JSON"
	}
	if parsed.Report.Overall.Guard == "" ||
		parsed.Report.Overall.Severity == "" ||
		parsed.Report.Overall.Message == "" {
		return guards.GuardResult{}, "Daemon returned malformed eval payload"
	}

	sev, err := guards.ParseSeverity(parsed.Report.Overall.Severity)
	if err != nil {
		sev = guards.Error
	}
	return guards.GuardResult{
		Allowed:  parsed.Report.Overall.Allowed,
		Guard:    parsed.Report.Overall.Guard,
		Severity: sev,
		Message:  parsed.Report.Overall.Message,
		Details:  parsed.Report.Overall.Details,
	}, ""
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
	case "custom":
		if action.CustomType != "origin.output_send" {
			return daemonCheckRequest{}, fmt.Errorf("unsupported daemon custom action: %s", action.CustomType)
		}
		payload, err := toDaemonArgs(action.CustomData)
		if err != nil {
			return daemonCheckRequest{}, err
		}
		text, ok := payload["text"].(string)
		if !ok || strings.TrimSpace(text) == "" {
			return daemonCheckRequest{}, fmt.Errorf("origin.output_send requires a non-empty text field")
		}
		req.ActionType = "output_send"
		req.Content = text
		if target, ok := payload["target"].(string); ok {
			req.Target = target
		}
		args := make(map[string]interface{}, 2)
		if mimeType, ok := payload["mime_type"]; ok {
			args["mime_type"] = mimeType
		}
		if metadata, ok := payload["metadata"]; ok {
			args["metadata"] = metadata
		}
		if len(args) > 0 {
			req.Args = args
		}
	default:
		return daemonCheckRequest{}, fmt.Errorf("unsupported action type for daemon mode: %s", action.Type)
	}

	if req.Target == "" && req.ActionType != "output_send" {
		return daemonCheckRequest{}, fmt.Errorf("%s requires a non-empty target", action.Type)
	}

	if ctx != nil {
		req.Origin = ctx.Origin
		req.SessionID = ctx.SessionID
		req.AgentID = ctx.AgentID
		req.Metadata = daemonCheckMetadata(ctx)
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

func extractUntrustedTextPayload(payload interface{}) (string, string, error) {
	switch value := payload.(type) {
	case string:
		text := strings.TrimSpace(value)
		if text == "" {
			return "", "", fmt.Errorf("untrusted_text requires a non-empty string")
		}
		return text, "", nil
	case map[string]interface{}:
		text, ok := value["text"].(string)
		if !ok || strings.TrimSpace(text) == "" {
			return "", "", fmt.Errorf("untrusted_text requires payload.text to be a non-empty string")
		}
		source, _ := value["source"].(string)
		return text, source, nil
	default:
		raw, err := json.Marshal(value)
		if err != nil {
			return "", "", fmt.Errorf("untrusted_text payload must be JSON-serializable: %w", err)
		}
		var decoded map[string]interface{}
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return "", "", fmt.Errorf("untrusted_text payload must be a string or object")
		}
		return extractUntrustedTextPayload(decoded)
	}
}

func isDaemonUntrustedTextCustomType(customType string) bool {
	return customType == "untrusted_text" || customType == "hushclaw.untrusted_text"
}

func daemonCheckMetadata(ctx *guards.GuardContext) map[string]interface{} {
	if ctx == nil || len(ctx.Metadata) == 0 {
		return nil
	}

	metadata := make(map[string]interface{}, len(ctx.Metadata))
	for key, value := range ctx.Metadata {
		metadata[key] = value
	}
	return metadata
}

func daemonEvalMetadata(ctx *guards.GuardContext) map[string]interface{} {
	if ctx == nil {
		return nil
	}

	metadata := make(map[string]interface{})
	for key, value := range ctx.Metadata {
		metadata[key] = value
	}
	if ctx.Origin != nil {
		metadata["origin"] = ctx.Origin
	}
	if ctx.AgentID != "" {
		metadata["endpointAgentId"] = ctx.AgentID
	}
	if len(metadata) == 0 {
		return nil
	}
	return metadata
}
