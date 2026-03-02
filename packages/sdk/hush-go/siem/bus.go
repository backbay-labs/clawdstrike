package siem

import (
	"context"
	"sync"
	"time"
)

// EventExporter sends batches of security events to an external system.
type EventExporter interface {
	Export(ctx context.Context, events []SecurityEvent) error
	Close() error
}

// EventBus collects security events and flushes them in batches to registered exporters.
type EventBus struct {
	ch            chan SecurityEvent
	exporters     []EventExporter
	mu            sync.RWMutex
	batchSize     int
	flushInterval time.Duration
	done          chan struct{}
	stopped       chan struct{}
}

// EventBusOption configures an EventBus.
type EventBusOption func(*EventBus)

// WithBatchSize sets the maximum number of events per export batch.
func WithBatchSize(n int) EventBusOption {
	return func(b *EventBus) {
		if n > 0 {
			b.batchSize = n
		}
	}
}

// WithFlushInterval sets the maximum time between flushes.
func WithFlushInterval(d time.Duration) EventBusOption {
	return func(b *EventBus) {
		if d > 0 {
			b.flushInterval = d
		}
	}
}

// NewEventBus creates a new event bus with the given options.
func NewEventBus(opts ...EventBusOption) *EventBus {
	b := &EventBus{
		ch:            make(chan SecurityEvent, 1024),
		batchSize:     100,
		flushInterval: 5 * time.Second,
		done:          make(chan struct{}),
		stopped:       make(chan struct{}),
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// AddExporter registers an exporter that will receive event batches.
func (b *EventBus) AddExporter(e EventExporter) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.exporters = append(b.exporters, e)
}

// Emit sends a security event to the bus for batched export. Non-blocking;
// events are dropped if the internal buffer is full.
func (b *EventBus) Emit(event SecurityEvent) {
	select {
	case b.ch <- event:
	default:
		// Drop event if channel is full to avoid blocking the caller.
	}
}

// Start begins the background flush loop. It blocks until Stop is called or
// the context is cancelled.
func (b *EventBus) Start(ctx context.Context) {
	defer close(b.stopped)

	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()

	var batch []SecurityEvent

	for {
		select {
		case ev := <-b.ch:
			batch = append(batch, ev)
			if len(batch) >= b.batchSize {
				b.flush(ctx, batch)
				batch = nil
			}
		case <-ticker.C:
			if len(batch) > 0 {
				b.flush(ctx, batch)
				batch = nil
			}
		case <-b.done:
			// Drain remaining events.
			for {
				select {
				case ev := <-b.ch:
					batch = append(batch, ev)
				default:
					if len(batch) > 0 {
						b.flush(ctx, batch)
					}
					return
				}
			}
		case <-ctx.Done():
			if len(batch) > 0 {
				b.flush(context.Background(), batch)
			}
			return
		}
	}
}

// Stop signals the event bus to flush remaining events and shut down.
func (b *EventBus) Stop() {
	close(b.done)
	<-b.stopped
}

func (b *EventBus) flush(ctx context.Context, batch []SecurityEvent) {
	b.mu.RLock()
	exporters := make([]EventExporter, len(b.exporters))
	copy(exporters, b.exporters)
	b.mu.RUnlock()

	for _, exp := range exporters {
		// Best-effort: ignore individual exporter errors to avoid blocking other exporters.
		_ = exp.Export(ctx, batch)
	}
}
