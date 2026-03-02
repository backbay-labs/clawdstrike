package internal

import "testing"

func TestMalformedPatternReturnsFalse(t *testing.T) {
	// Malformed glob patterns should return false (fail-closed), not panic or match.
	if DoubleStarMatch("[invalid", "anything") {
		t.Error("expected malformed pattern to return false")
	}
	if DoubleStarMatch("abc/[bad", "abc/file") {
		t.Error("expected malformed pattern in segment to return false")
	}
}

func TestDoubleStarMatch(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Basic double star
		{"**/.ssh/**", "/home/user/.ssh/id_rsa", true},
		{"**/.ssh/**", "/home/user/.ssh/config", true},
		{"**/.ssh/**", "/home/user/.aws/config", false},

		// Double star at start
		{"**/id_rsa*", "/home/user/.ssh/id_rsa", true},
		{"**/id_rsa*", "/home/user/.ssh/id_rsa.pub", true},
		{"**/id_rsa*", "/home/user/.ssh/id_ed25519", false},

		// Double star with prefix
		{"**/.env", "/app/.env", true},
		{"**/.env", "/app/sub/.env", true},
		{"**/.env.*", "/app/.env.local", true},
		{"**/.env.*", "/app/.env", false},

		// Absolute paths
		{"/etc/shadow", "/etc/shadow", true},
		{"/etc/shadow", "/etc/passwd", false},

		// Single star
		{"*.go", "main.go", true},
		{"*.go", "test.rs", false},

		// Nested double star
		{"**/.gnupg/**", "/home/user/.gnupg/pubring.kbx", true},
	}

	for _, tt := range tests {
		got := DoubleStarMatch(tt.pattern, tt.path)
		if got != tt.want {
			t.Errorf("DoubleStarMatch(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestCreateID(t *testing.T) {
	id := CreateID("rcpt")
	if id[:5] != "rcpt_" {
		t.Errorf("expected prefix rcpt_, got %s", id[:5])
	}
	// Should have 3 parts: prefix, timestamp, random
	parts := 0
	for _, c := range id {
		if c == '_' {
			parts++
		}
	}
	if parts < 2 {
		t.Errorf("expected at least 2 underscores in %q", id)
	}
}
