package siem

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ErrAlreadyStarted is returned when Start is called on an already-running EventBus.
var ErrAlreadyStarted = errors.New("siem: event bus already started")

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
	droppedCount  atomic.Int64
	started       atomic.Bool
}

// EventBusOption configures an EventBus.
type EventBusOption func(*EventBus)

func WithBatchSize(n int) EventBusOption {
	return func(b *EventBus) {
		if n > 0 {
			b.batchSize = n
		}
	}
}

func WithFlushInterval(d time.Duration) EventBusOption {
	return func(b *EventBus) {
		if d > 0 {
			b.flushInterval = d
		}
	}
}

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
		b.droppedCount.Add(1)
	}
}

func (b *EventBus) DroppedCount() int64 {
	return b.droppedCount.Load()
}

// Start begins the background flush loop. It blocks until Stop is called or
// the context is cancelled. Returns ErrAlreadyStarted if called more than once.
func (b *EventBus) Start(ctx context.Context) error {
	if !b.started.CompareAndSwap(false, true) {
		return ErrAlreadyStarted
	}
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
					return nil
				}
			}
		case <-ctx.Done():
			if len(batch) > 0 {
				b.flush(context.Background(), batch)
			}
			return nil
		}
	}
}

// Safe to call even if Start was never called.
func (b *EventBus) Stop() {
	if !b.started.Load() {
		return
	}
	close(b.done)
	<-b.stopped
}

func (b *EventBus) flush(ctx context.Context, batch []SecurityEvent) {
	b.mu.RLock()
	exporters := make([]EventExporter, len(b.exporters))
	copy(exporters, b.exporters)
	b.mu.RUnlock()

	for _, exp := range exporters {
		// Copy the batch so exporters don't share the backing array.
		batchCopy := make([]SecurityEvent, len(batch))
		copy(batchCopy, batch)
		// Best-effort: ignore individual exporter errors to avoid blocking other exporters.
		_ = exp.Export(ctx, batchCopy)
	}
}
