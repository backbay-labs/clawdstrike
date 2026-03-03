package siem

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ManagedExporter configures one exporter entry in ExporterManager.
type ManagedExporter struct {
	Name     string
	Exporter EventExporter
	Enabled  bool
}

// ExporterManager coordinates EventBus lifecycle with explicit flush/shutdown
// orchestration similar to SDK manager patterns in other languages.
type ExporterManager struct {
	bus *EventBus

	mu        sync.Mutex
	exporters []ManagedExporter
	started   bool
	runCtx    context.Context
	cancel    context.CancelFunc
}

// NewExporterManager creates an exporter manager using the provided bus, or a
// default EventBus if nil is passed.
func NewExporterManager(bus *EventBus) *ExporterManager {
	if bus == nil {
		bus = NewEventBus()
	}
	return &ExporterManager{bus: bus}
}

// Register adds an exporter entry.
func (m *ExporterManager) Register(entry ManagedExporter) error {
	if entry.Exporter == nil {
		return errors.New("siem: managed exporter is nil")
	}
	if entry.Name == "" {
		entry.Name = "exporter"
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.started && entry.Enabled {
		m.bus.AddExporter(entry.Exporter)
	}
	m.exporters = append(m.exporters, entry)
	return nil
}

// Start begins manager-owned EventBus execution.
func (m *ExporterManager) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}

	for _, entry := range m.exporters {
		if entry.Enabled {
			m.bus.AddExporter(entry.Exporter)
		}
	}
	m.runCtx, m.cancel = context.WithCancel(ctx)
	m.started = true
	m.mu.Unlock()

	go func() {
		_ = m.bus.Start(m.runCtx)
	}()

	for i := 0; i < 100; i++ {
		if m.bus.started.Load() {
			return nil
		}
		select {
		case <-m.runCtx.Done():
			return m.runCtx.Err()
		default:
			time.Sleep(1 * time.Millisecond)
		}
	}
	return nil
}

// Emit forwards an event to the managed bus.
func (m *ExporterManager) Emit(event SecurityEvent) {
	m.bus.Emit(event)
}

// FlushAll flushes in-memory events and returns a metrics snapshot.
func (m *ExporterManager) FlushAll(ctx context.Context) (map[string]ExporterMetrics, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := m.bus.Flush(ctx); err != nil {
		return nil, err
	}
	return m.bus.ExporterMetrics(), nil
}

// Shutdown flushes, stops the bus, and closes all enabled exporters.
func (m *ExporterManager) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var errs []error

	if _, err := m.FlushAll(ctx); err != nil {
		errs = append(errs, err)
	}

	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Unlock()

	m.bus.Stop()

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, entry := range m.exporters {
		if !entry.Enabled {
			continue
		}
		if err := entry.Exporter.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
