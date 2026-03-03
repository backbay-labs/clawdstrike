package siem_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/backbay-labs/clawdstrike-go/siem"
)

type closeAwareExporter struct {
	mockExporter
	closeErr error
	closed   int
}

func (c *closeAwareExporter) Close() error {
	c.closed++
	return c.closeErr
}

func TestExporterManagerFlushAndShutdown(t *testing.T) {
	exp := &closeAwareExporter{}
	manager := siem.NewExporterManager(siem.NewEventBus(
		siem.WithBatchSize(100),
		siem.WithFlushInterval(10*time.Second),
	))
	if err := manager.Register(siem.ManagedExporter{
		Name:     "mock",
		Exporter: exp,
		Enabled:  true,
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	manager.Emit(sampleEvent("manager-1"))
	manager.Emit(sampleEvent("manager-2"))

	metrics, err := manager.FlushAll(context.Background())
	if err != nil {
		t.Fatalf("FlushAll: %v", err)
	}
	if len(metrics) == 0 {
		t.Fatal("expected non-empty metrics snapshot")
	}
	if total := exp.totalEvents(); total != 2 {
		t.Fatalf("expected 2 exported events after flush, got %d", total)
	}

	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if exp.closed != 1 {
		t.Fatalf("expected exporter Close to be called once, got %d", exp.closed)
	}
}

func TestExporterManagerDisabledExporterNotStarted(t *testing.T) {
	enabled := &closeAwareExporter{}
	disabled := &closeAwareExporter{}
	manager := siem.NewExporterManager(nil)

	if err := manager.Register(siem.ManagedExporter{Name: "enabled", Exporter: enabled, Enabled: true}); err != nil {
		t.Fatalf("register enabled: %v", err)
	}
	if err := manager.Register(siem.ManagedExporter{Name: "disabled", Exporter: disabled, Enabled: false}); err != nil {
		t.Fatalf("register disabled: %v", err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	manager.Emit(sampleEvent("enabled-only"))
	if _, err := manager.FlushAll(context.Background()); err != nil {
		t.Fatalf("FlushAll: %v", err)
	}
	if enabled.totalEvents() == 0 {
		t.Fatal("expected enabled exporter to receive events")
	}
	if disabled.totalEvents() != 0 {
		t.Fatalf("expected disabled exporter to receive no events, got %d", disabled.totalEvents())
	}

	if err := manager.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if disabled.closed != 0 {
		t.Fatalf("expected disabled exporter to not be closed, got %d", disabled.closed)
	}
}

func TestExporterManagerRegisterRejectsNil(t *testing.T) {
	manager := siem.NewExporterManager(nil)
	err := manager.Register(siem.ManagedExporter{Name: "bad", Exporter: nil, Enabled: true})
	if err == nil {
		t.Fatal("expected error for nil exporter")
	}
}

func TestExporterManagerShutdownCollectsCloseErrors(t *testing.T) {
	exp := &closeAwareExporter{closeErr: errors.New("close failed")}
	manager := siem.NewExporterManager(nil)
	if err := manager.Register(siem.ManagedExporter{Name: "broken", Exporter: exp, Enabled: true}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	err := manager.Shutdown(context.Background())
	if err == nil {
		t.Fatal("expected shutdown error")
	}
}
