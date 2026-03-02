package session

import (
	"sync"
	"testing"

	"github.com/backbay/clawdstrike-go/guards"
)

// mockEngine is a test double that returns configurable results.
type mockEngine struct {
	result guards.GuardResult
}

func (m *mockEngine) CheckAction(_ guards.GuardAction, _ *guards.GuardContext) guards.GuardResult {
	return m.result
}

func TestSessionCounters(t *testing.T) {
	eng := &mockEngine{result: guards.Allow("test")}
	sess := NewSession(eng, Options{})

	sess.Check(guards.FileAccess("/tmp/test"))
	sess.Check(guards.FileAccess("/tmp/test2"))

	summary := sess.GetSummary()
	if summary.CheckCount != 2 {
		t.Errorf("expected CheckCount=2, got %d", summary.CheckCount)
	}
	if summary.AllowCount != 2 {
		t.Errorf("expected AllowCount=2, got %d", summary.AllowCount)
	}
	if summary.DenyCount != 0 {
		t.Errorf("expected DenyCount=0, got %d", summary.DenyCount)
	}
}

func TestSessionDenyTracking(t *testing.T) {
	eng := &mockEngine{result: guards.Block("test", guards.Error, "blocked")}
	sess := NewSession(eng, Options{})

	d := sess.Check(guards.FileAccess("/etc/passwd"))

	if d.Status != StatusDeny {
		t.Errorf("expected deny, got %s", d.Status)
	}

	summary := sess.GetSummary()
	if summary.DenyCount != 1 {
		t.Errorf("expected DenyCount=1, got %d", summary.DenyCount)
	}
	if len(summary.BlockedActions) != 1 || summary.BlockedActions[0] != "file_access" {
		t.Errorf("expected blocked action 'file_access', got %v", summary.BlockedActions)
	}
}

func TestSessionWarnTracking(t *testing.T) {
	eng := &mockEngine{result: guards.Warn("test", "suspicious")}
	sess := NewSession(eng, Options{})

	d := sess.Check(guards.FileAccess("/tmp/test"))
	if d.Status != StatusWarn {
		t.Errorf("expected warn, got %s", d.Status)
	}

	summary := sess.GetSummary()
	if summary.WarnCount != 1 {
		t.Errorf("expected WarnCount=1, got %d", summary.WarnCount)
	}
}

func TestSessionID(t *testing.T) {
	eng := &mockEngine{result: guards.Allow("test")}

	// Auto-generated ID
	sess := NewSession(eng, Options{})
	if sess.ID() == "" {
		t.Error("expected non-empty auto-generated ID")
	}

	// Custom ID
	sess2 := NewSession(eng, Options{ID: "my-session"})
	if sess2.ID() != "my-session" {
		t.Errorf("expected 'my-session', got %q", sess2.ID())
	}
}

func TestSessionThreadSafety(t *testing.T) {
	eng := &mockEngine{result: guards.Allow("test")}
	sess := NewSession(eng, Options{})

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			sess.Check(guards.FileAccess("/tmp/test"))
		}()
	}
	wg.Wait()

	summary := sess.GetSummary()
	if summary.CheckCount != goroutines {
		t.Errorf("expected CheckCount=%d, got %d", goroutines, summary.CheckCount)
	}
	if summary.AllowCount != goroutines {
		t.Errorf("expected AllowCount=%d, got %d", goroutines, summary.AllowCount)
	}
}

func TestSessionConcurrentDenyTracking(t *testing.T) {
	eng := &mockEngine{result: guards.Block("test", guards.Critical, "denied")}
	sess := NewSession(eng, Options{})

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			sess.Check(guards.FileAccess("/etc/shadow"))
		}()
	}
	wg.Wait()

	summary := sess.GetSummary()
	if summary.DenyCount != goroutines {
		t.Errorf("expected DenyCount=%d, got %d", goroutines, summary.DenyCount)
	}
	if len(summary.BlockedActions) != goroutines {
		t.Errorf("expected %d blocked actions, got %d", goroutines, len(summary.BlockedActions))
	}
}
