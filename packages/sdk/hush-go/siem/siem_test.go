package siem_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/backbay-labs/clawdstrike-go/siem"
	"github.com/backbay-labs/clawdstrike-go/siem/transforms"
)

// mockExporter collects exported batches for assertions.
type mockExporter struct {
	mu      sync.Mutex
	batches [][]siem.SecurityEvent
}

func (m *mockExporter) Export(_ context.Context, events []siem.SecurityEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]siem.SecurityEvent, len(events))
	copy(cp, events)
	m.batches = append(m.batches, cp)
	return nil
}

func (m *mockExporter) Close() error { return nil }

func (m *mockExporter) totalEvents() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, b := range m.batches {
		n += len(b)
	}
	return n
}

type flakyExporter struct {
	mu        sync.Mutex
	failUntil int
	calls     int
}

func (f *flakyExporter) Export(_ context.Context, events []siem.SecurityEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failUntil {
		return errors.New("temporary exporter failure")
	}
	_ = events
	return nil
}

func (f *flakyExporter) Close() error { return nil }

func (f *flakyExporter) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func sampleEvent(id string) siem.SecurityEvent {
	return siem.SecurityEvent{
		SchemaVersion: "1.0.0",
		EventID:       id,
		EventType:     "guard.check",
		Timestamp:     time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC),
		Agent:         siem.AgentInfo{ID: "agent-1", Name: "test-agent", Type: "ai"},
		Session:       siem.SessionInfo{ID: "sess-1"},
		Outcome:       "deny",
		Decision:      &siem.DecisionInfo{Guard: "forbidden_path", Severity: "high", Message: "blocked /etc/shadow"},
		Resource:      &siem.ResourceInfo{Type: "file", Path: "/etc/shadow"},
		Threat:        &siem.ThreatInfo{Category: "filesystem_access", Confidence: 0.95},
	}
}

func TestEventBus_BatchExport(t *testing.T) {
	exp := &mockExporter{}

	bus := siem.NewEventBus(siem.WithBatchSize(3), siem.WithFlushInterval(50*time.Millisecond))
	bus.AddExporter(exp)

	ctx, cancel := context.WithCancel(context.Background())
	go bus.Start(ctx)

	// Emit 5 events: should trigger one batch of 3, then remainder flushed on stop.
	for i := 0; i < 5; i++ {
		bus.Emit(sampleEvent(string(rune('a' + i))))
	}

	// Wait for flush interval to pass.
	time.Sleep(100 * time.Millisecond)
	cancel()
	bus.Stop()

	total := exp.totalEvents()
	if total != 5 {
		t.Fatalf("expected 5 events exported, got %d", total)
	}
}

func TestEventBus_FlushOnStop(t *testing.T) {
	exp := &mockExporter{}

	bus := siem.NewEventBus(siem.WithBatchSize(100), siem.WithFlushInterval(10*time.Second))
	bus.AddExporter(exp)

	ctx := context.Background()
	go bus.Start(ctx)

	bus.Emit(sampleEvent("stop-test"))
	time.Sleep(20 * time.Millisecond) // let event be received
	bus.Stop()

	total := exp.totalEvents()
	if total != 1 {
		t.Fatalf("expected 1 event flushed on stop, got %d", total)
	}
}

func TestEventBus_DroppedCount(t *testing.T) {
	// Create a bus with a very small channel buffer.
	bus := siem.NewEventBus(siem.WithBatchSize(1000), siem.WithFlushInterval(10*time.Second))

	// Don't start the bus, so no events are consumed. Fill the channel.
	for i := 0; i < 1100; i++ {
		bus.Emit(sampleEvent("drop"))
	}

	dropped := bus.DroppedCount()
	if dropped == 0 {
		t.Fatal("expected dropped events but got 0")
	}
	// Default buffer is 1024, so at least 1100-1024=76 should be dropped.
	if dropped < 76 {
		t.Errorf("expected at least 76 dropped, got %d", dropped)
	}
}

func TestEventBus_StopWithoutStart(t *testing.T) {
	bus := siem.NewEventBus()
	// Should not panic or deadlock.
	bus.Stop()
}

func TestEventBus_StopIdempotent(t *testing.T) {
	bus := siem.NewEventBus(siem.WithFlushInterval(10 * time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	go bus.Start(ctx)

	time.Sleep(20 * time.Millisecond)
	cancel()
	bus.Stop()

	// Second stop must not panic.
	bus.Stop()
}

func TestEventBus_DoubleStart(t *testing.T) {
	bus := siem.NewEventBus(siem.WithFlushInterval(50 * time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First start in goroutine.
	go bus.Start(ctx)
	time.Sleep(10 * time.Millisecond) // let it start

	// Second start should return error.
	err := bus.Start(ctx)
	if err == nil {
		t.Fatal("expected error on double Start")
	}
	if err != siem.ErrAlreadyStarted {
		t.Fatalf("expected ErrAlreadyStarted, got: %v", err)
	}

	cancel()
}

func TestEventBus_ExporterRetryAndMetrics(t *testing.T) {
	exp := &flakyExporter{failUntil: 2}
	var hookCalls int
	var hookMu sync.Mutex

	bus := siem.NewEventBus(
		siem.WithBatchSize(1),
		siem.WithFlushInterval(5*time.Millisecond),
		siem.WithExportRetry(3, 1*time.Millisecond),
		siem.WithExportErrorHook(func(_ siem.ExportError) {
			hookMu.Lock()
			hookCalls++
			hookMu.Unlock()
		}),
	)
	bus.AddExporter(exp)

	ctx, cancel := context.WithCancel(context.Background())
	go bus.Start(ctx)

	bus.Emit(sampleEvent("retry-1"))
	time.Sleep(60 * time.Millisecond)
	cancel()
	bus.Stop()

	if exp.callCount() != 3 {
		t.Fatalf("expected 3 export attempts, got %d", exp.callCount())
	}

	hookMu.Lock()
	gotHookCalls := hookCalls
	hookMu.Unlock()
	if gotHookCalls != 2 {
		t.Fatalf("expected 2 hook calls for failed attempts, got %d", gotHookCalls)
	}

	metrics := bus.ExporterMetrics()
	if len(metrics) == 0 {
		t.Fatal("expected exporter metrics to be populated")
	}
	for _, m := range metrics {
		if m.Attempts != 3 {
			t.Fatalf("expected 3 attempts, got %d", m.Attempts)
		}
		if m.Failures != 2 {
			t.Fatalf("expected 2 failures, got %d", m.Failures)
		}
		if m.Retries != 2 {
			t.Fatalf("expected 2 retries, got %d", m.Retries)
		}
	}
}

func TestEventBus_ExporterRetryExhausted(t *testing.T) {
	exp := &flakyExporter{failUntil: 10}
	bus := siem.NewEventBus(
		siem.WithBatchSize(1),
		siem.WithFlushInterval(5*time.Millisecond),
		siem.WithExportRetry(2, 1*time.Millisecond),
	)
	bus.AddExporter(exp)

	ctx, cancel := context.WithCancel(context.Background())
	go bus.Start(ctx)

	bus.Emit(sampleEvent("retry-exhausted"))
	time.Sleep(50 * time.Millisecond)
	cancel()
	bus.Stop()

	if exp.callCount() != 2 {
		t.Fatalf("expected retry attempts to stop at 2, got %d", exp.callCount())
	}
}

func TestToECS(t *testing.T) {
	ev := sampleEvent("ecs-1")
	ecs := transforms.ToECS(ev)

	if ecs["@timestamp"] != "2026-03-02T12:00:00.000Z" {
		t.Errorf("unexpected @timestamp: %v", ecs["@timestamp"])
	}
	ecsVer, ok := ecs["ecs"].(map[string]string)
	if !ok || ecsVer["version"] == "" {
		t.Error("missing ecs.version")
	}
	eventMap, ok := ecs["event"].(map[string]interface{})
	if !ok {
		t.Fatal("missing event map")
	}
	if eventMap["outcome"] != "deny" {
		t.Errorf("expected outcome deny, got %v", eventMap["outcome"])
	}
	if _, ok := ecs["file"]; !ok {
		t.Error("expected file field for file resource")
	}
	if _, ok := ecs["rule"]; !ok {
		t.Error("expected rule field for decision")
	}
}

func TestToOCSF(t *testing.T) {
	ev := sampleEvent("ocsf-1")
	ocsf := transforms.ToOCSF(ev)

	if ocsf["class_uid"] != 2001 {
		t.Errorf("expected class_uid 2001, got %v", ocsf["class_uid"])
	}
	if ocsf["status_id"] != 2 { // deny -> Failure
		t.Errorf("expected status_id 2 for deny, got %v", ocsf["status_id"])
	}
	if ocsf["severity_id"] != 4 { // high
		t.Errorf("expected severity_id 4 for high, got %v", ocsf["severity_id"])
	}

	meta, ok := ocsf["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("missing metadata")
	}
	product, ok := meta["product"].(map[string]string)
	if !ok || product["name"] != "clawdstrike" {
		t.Error("expected product name clawdstrike")
	}
}

func TestToCEF(t *testing.T) {
	ev := sampleEvent("cef-1")
	cef := transforms.ToCEF(ev)

	if !strings.HasPrefix(cef, "CEF:0|Backbay|Clawdstrike|1.0|") {
		t.Errorf("unexpected CEF prefix: %s", cef)
	}
	if !strings.Contains(cef, "forbidden_path") {
		t.Error("expected guard name in CEF output")
	}
	if !strings.Contains(cef, "outcome=deny") {
		t.Error("expected outcome=deny in CEF extensions")
	}
	if !strings.Contains(cef, "filePath=/etc/shadow") {
		t.Error("expected filePath in CEF extensions")
	}
}

func TestSeverityMappingsIncludeSDKNativeValues(t *testing.T) {
	ev := sampleEvent("severity-1")
	ev.Decision = &siem.DecisionInfo{Guard: "x", Severity: "warning", Message: "warn message"}

	ocsf := transforms.ToOCSF(ev)
	if ocsf["severity_id"] != 3 {
		t.Errorf("expected severity_id 3 for warning, got %v", ocsf["severity_id"])
	}

	cef := transforms.ToCEF(ev)
	if !strings.Contains(cef, "|5|") {
		t.Errorf("expected CEF severity 5 for warning, got %s", cef)
	}

	ev.Decision.Severity = "error"
	ocsf = transforms.ToOCSF(ev)
	if ocsf["severity_id"] != 4 {
		t.Errorf("expected severity_id 4 for error, got %v", ocsf["severity_id"])
	}
	cef = transforms.ToCEF(ev)
	if !strings.Contains(cef, "|8|") {
		t.Errorf("expected CEF severity 8 for error, got %s", cef)
	}
}
