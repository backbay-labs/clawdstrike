package siem

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/backbay-labs/clawdstrike-go/internal"
)

// ErrAlreadyStarted is returned when Start is called on an already-running EventBus.
var ErrAlreadyStarted = errors.New("siem: event bus already started")

// EventExporter sends batches of security events to an external system.
type EventExporter interface {
	Export(ctx context.Context, events []SecurityEvent) error
	Close() error
}

// ExportError captures an exporter failure during a flush attempt.
type ExportError struct {
	Exporter string
	Attempt  int
	BatchLen int
	Err      error
}

// ExportErrorHook is called whenever an exporter attempt fails.
type ExportErrorHook func(ExportError)

// ExporterMetrics captures runtime observability for one exporter.
type ExporterMetrics struct {
	Attempts    int64
	Failures    int64
	Retries     int64
	LastError   string
	LastErrorAt time.Time
}

// EventBus collects security events and flushes them in batches to registered exporters.
type EventBus struct {
	ch            chan SecurityEvent
	flushReq      chan chan struct{}
	exporters     []EventExporter
	mu            sync.RWMutex
	batchSize     int
	flushInterval time.Duration
	done          chan struct{}
	stopped       chan struct{}
	stopOnce      sync.Once
	droppedCount  atomic.Int64
	started       atomic.Bool
	retryAttempts int
	retryBackoff  time.Duration
	errorHook     ExportErrorHook
	metricsMu     sync.Mutex
	metrics       map[string]ExporterMetrics
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

// WithExportRetry configures retry attempts and exponential backoff base duration.
// attempts includes the initial attempt; values less than 1 are ignored.
func WithExportRetry(attempts int, backoff time.Duration) EventBusOption {
	return func(b *EventBus) {
		if attempts > 0 {
			b.retryAttempts = attempts
		}
		if backoff >= 0 {
			b.retryBackoff = backoff
		}
	}
}

// WithExportErrorHook installs a callback for per-attempt exporter failures.
func WithExportErrorHook(hook ExportErrorHook) EventBusOption {
	return func(b *EventBus) {
		b.errorHook = hook
	}
}

func NewEventBus(opts ...EventBusOption) *EventBus {
	b := &EventBus{
		ch:            make(chan SecurityEvent, 1024),
		flushReq:      make(chan chan struct{}),
		batchSize:     100,
		flushInterval: 5 * time.Second,
		done:          make(chan struct{}),
		stopped:       make(chan struct{}),
		retryAttempts: 1,
		retryBackoff:  0,
		metrics:       make(map[string]ExporterMetrics),
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
		case ack := <-b.flushReq:
			for {
				select {
				case ev := <-b.ch:
					batch = append(batch, ev)
				default:
					goto drained
				}
			}
		drained:
			if len(batch) > 0 {
				b.flush(ctx, batch)
				batch = nil
			}
			close(ack)
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
	b.stopOnce.Do(func() {
		close(b.done)
	})
	<-b.stopped
}

// Flush forces immediate export of all buffered in-memory events currently held by
// the running batch loop. It is a no-op if the bus is not started.
func (b *EventBus) Flush(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if !b.started.Load() {
		return nil
	}

	ack := make(chan struct{})
	select {
	case b.flushReq <- ack:
	case <-b.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case <-ack:
		return nil
	case <-b.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *EventBus) flush(ctx context.Context, batch []SecurityEvent) {
	b.mu.RLock()
	exporters := make([]EventExporter, len(b.exporters))
	copy(exporters, b.exporters)
	b.mu.RUnlock()

	for idx, exp := range exporters {
		label := exporterLabel(exp, idx)
		for attempt := 1; attempt <= b.retryAttempts; attempt++ {
			b.recordAttempt(label)

			// Copy the batch so exporters don't share the backing array.
			batchCopy := make([]SecurityEvent, len(batch))
			copy(batchCopy, batch)

			err := exp.Export(ctx, batchCopy)
			if err == nil {
				break
			}

			b.recordFailure(label, err)
			if b.errorHook != nil {
				b.errorHook(ExportError{
					Exporter: label,
					Attempt:  attempt,
					BatchLen: len(batch),
					Err:      err,
				})
			}

			if attempt >= b.retryAttempts {
				break
			}
			b.recordRetry(label)
			wait := backoffDuration(b.retryBackoff, attempt)
			if wait > 0 && !internal.SleepWithContext(ctx, wait) {
				return
			}
		}
	}
}

// ExporterMetrics returns a point-in-time snapshot of per-exporter metrics.
func (b *EventBus) ExporterMetrics() map[string]ExporterMetrics {
	b.metricsMu.Lock()
	defer b.metricsMu.Unlock()

	out := make(map[string]ExporterMetrics, len(b.metrics))
	for k, v := range b.metrics {
		out[k] = v
	}
	return out
}

func exporterLabel(exp EventExporter, idx int) string {
	if named, ok := exp.(interface{ Name() string }); ok {
		if name := named.Name(); name != "" {
			return name
		}
	}
	return fmt.Sprintf("%T#%d", exp, idx)
}

func (b *EventBus) recordAttempt(exporter string) {
	b.metricsMu.Lock()
	defer b.metricsMu.Unlock()
	m := b.metrics[exporter]
	m.Attempts++
	b.metrics[exporter] = m
}

func (b *EventBus) recordFailure(exporter string, err error) {
	b.metricsMu.Lock()
	defer b.metricsMu.Unlock()
	m := b.metrics[exporter]
	m.Failures++
	m.LastError = err.Error()
	m.LastErrorAt = time.Now()
	b.metrics[exporter] = m
}

func (b *EventBus) recordRetry(exporter string) {
	b.metricsMu.Lock()
	defer b.metricsMu.Unlock()
	m := b.metrics[exporter]
	m.Retries++
	b.metrics[exporter] = m
}

func backoffDuration(base time.Duration, attempt int) time.Duration {
	if base <= 0 || attempt <= 0 {
		return 0
	}
	multiplier := 1 << (attempt - 1)
	return time.Duration(multiplier) * base
}
