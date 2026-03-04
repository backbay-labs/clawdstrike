package guards

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	sdkcrypto "github.com/backbay-labs/clawdstrike-go/crypto"
	"github.com/backbay-labs/clawdstrike-go/policy"
)

// Helpers for pointer literals in config structs.
func ptrF64(v float64) *float64 { return &v }
func ptrInt(v int) *int         { return &v }

type spiderSenseManifestTamperVector struct {
	Name  string `json:"name"`
	Field string `json:"field"`
	Value string `json:"value"`
}

func loadSpiderSenseManifestTamperVectors(t *testing.T) []spiderSenseManifestTamperVector {
	t.Helper()
	path := filepath.Clean(filepath.Join("..", "..", "..", "..", "fixtures", "spider-sense", "manifest_tamper_vectors.json"))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest tamper vectors: %v", err)
	}
	var vectors []spiderSenseManifestTamperVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decode manifest tamper vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("manifest tamper vectors must be non-empty")
	}
	return vectors
}

func TestSpiderSenseBuiltinPatternDBMatchesRulesetSource(t *testing.T) {
	embedded, err := spiderSensePatternFS.ReadFile("patterns/s2bench-v1.json")
	if err != nil {
		t.Fatalf("read embedded s2bench pattern DB: %v", err)
	}

	canonicalPath := filepath.Clean(
		filepath.Join("..", "..", "..", "..", "rulesets", "patterns", "s2bench-v1.json"),
	)
	canonical, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Fatalf("read canonical ruleset pattern DB: %v", err)
	}

	if !bytes.Equal(bytes.TrimSpace(embedded), bytes.TrimSpace(canonical)) {
		t.Fatalf("embedded go spider-sense pattern DB diverged from rulesets/patterns/s2bench-v1.json")
	}
}

// --- CosineSimilarityF32 ---

func TestCosineSimilarityF32(t *testing.T) {
	tests := []struct {
		name string
		a, b []float32
		want float64
		eps  float64
	}{
		{"identical", []float32{1, 0, 0}, []float32{1, 0, 0}, 1.0, 1e-10},
		{"orthogonal", []float32{1, 0, 0}, []float32{0, 1, 0}, 0.0, 1e-10},
		{"opposite", []float32{1, 0}, []float32{-1, 0}, -1.0, 1e-10},
		{"zero vector", []float32{0, 0, 0}, []float32{1, 2, 3}, 0.0, 1e-10},
		{"different lengths", []float32{1, 0}, []float32{1, 0, 0}, 0.0, 1e-10},
		{"both zero", []float32{0, 0}, []float32{0, 0}, 0.0, 1e-10},
		{"parallel", []float32{2, 0, 0}, []float32{5, 0, 0}, 1.0, 1e-10},
		{"anti-parallel", []float32{0, 3}, []float32{0, -7}, -1.0, 1e-10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CosineSimilarityF32(tt.a, tt.b)
			if math.Abs(got-tt.want) > tt.eps {
				t.Errorf("CosineSimilarityF32(%v, %v) = %v, want %v (eps=%v)",
					tt.a, tt.b, got, tt.want, tt.eps)
			}
		})
	}
}

func TestTruncateToUTF8Boundary(t *testing.T) {
	t.Run("does not split multi-byte rune", func(t *testing.T) {
		input := "éclair"
		got := truncateTo(input, 1)
		if got != "" {
			t.Fatalf("expected empty string when max cuts into rune boundary, got %q", got)
		}

		got = truncateTo(input, 2)
		if got != "é" {
			t.Fatalf("expected full rune at boundary, got %q", got)
		}
	})

	t.Run("preserves ascii truncation behavior", func(t *testing.T) {
		input := "hello world"
		got := truncateTo(input, 5)
		if got != "hello" {
			t.Fatalf("expected ascii truncation to remain unchanged, got %q", got)
		}
	})
}

// --- ParsePatternDB ---

func TestParsePatternDB(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		data := []byte(`[
			{"id":"p1","category":"prompt_injection","stage":"perception","label":"ignore previous","embedding":[1.0,0.0,0.0]},
			{"id":"p2","category":"data_exfiltration","stage":"action","label":"exfil data","embedding":[0.0,1.0,0.0]},
			{"id":"p3","category":"privilege_escalation","stage":"cognition","label":"escalate","embedding":[0.0,0.0,1.0]}
		]`)
		db, err := ParsePatternDB(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if db.Len() != 3 {
			t.Errorf("expected 3 entries, got %d", db.Len())
		}
		if db.ExpectedDim() != 3 {
			t.Errorf("expected dim=3, got %d", db.ExpectedDim())
		}
		if db.IsEmpty() {
			t.Error("expected non-empty database")
		}
	})

	t.Run("empty array", func(t *testing.T) {
		_, err := ParsePatternDB([]byte(`[]`))
		if err == nil {
			t.Fatal("expected error for empty array")
		}
		if got := err.Error(); got != "pattern DB must contain at least one entry" {
			t.Errorf("unexpected error: %v", got)
		}
	})

	t.Run("dimension mismatch", func(t *testing.T) {
		data := []byte(`[
			{"id":"p1","category":"a","stage":"b","label":"c","embedding":[0.1,0.2]},
			{"id":"p2","category":"a","stage":"b","label":"d","embedding":[0.1]}
		]`)
		_, err := ParsePatternDB(data)
		if err == nil {
			t.Fatal("expected error for dimension mismatch")
		}
	})

	t.Run("empty embedding", func(t *testing.T) {
		data := []byte(`[
			{"id":"p1","category":"a","stage":"b","label":"c","embedding":[]}
		]`)
		_, err := ParsePatternDB(data)
		if err == nil {
			t.Fatal("expected error for empty embedding")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := ParsePatternDB([]byte(`not json`))
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}

// --- PatternDb.Search ---

func TestPatternDbSearch(t *testing.T) {
	db := testPatternDB(t)

	t.Run("exact match is top result", func(t *testing.T) {
		results := db.Search([]float32{1, 0, 0}, 2)
		if len(results) != 2 {
			t.Fatalf("expected 2 results, got %d", len(results))
		}
		if results[0].Entry.ID != "p1" {
			t.Errorf("expected top match p1, got %s", results[0].Entry.ID)
		}
		if math.Abs(results[0].Score-1.0) > 1e-6 {
			t.Errorf("expected score ~1.0, got %v", results[0].Score)
		}
	})

	t.Run("top_k limits results", func(t *testing.T) {
		results := db.Search([]float32{1, 0, 0}, 1)
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
	})

	t.Run("top_k larger than entries", func(t *testing.T) {
		results := db.Search([]float32{1, 0, 0}, 100)
		if len(results) != 3 {
			t.Fatalf("expected 3 results (all entries), got %d", len(results))
		}
	})
}

// --- SpiderSenseGuard.Screen ---

func TestSpiderSenseGuardScreen(t *testing.T) {
	db := testPatternDB(t)

	t.Run("deny - identical vector", func(t *testing.T) {
		cfg := &policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.85),
			AmbiguityBand:       ptrF64(0.10),
			TopK:                ptrInt(5),
		}
		g, err := NewSpiderSenseGuardWithDB(db, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		result := g.Screen([]float32{1, 0, 0})
		if result.Verdict != VerdictDeny {
			t.Errorf("expected deny, got %s", result.Verdict)
		}
		if math.Abs(result.TopScore-1.0) > 1e-6 {
			t.Errorf("expected top_score ~1.0, got %v", result.TopScore)
		}
	})

	t.Run("allow - orthogonal", func(t *testing.T) {
		cfg := &policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.85),
			AmbiguityBand:       ptrF64(0.10),
			TopK:                ptrInt(5),
		}
		g, err := NewSpiderSenseGuardWithDB(db, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Equally similar to all three orthogonal patterns -> score ~0.577
		// which is below the lower bound of 0.75
		result := g.Screen([]float32{0.577, 0.577, 0.577})
		if result.Verdict != VerdictAllow {
			t.Errorf("expected allow, got %s (top_score=%v)", result.Verdict, result.TopScore)
		}
	})

	t.Run("ambiguous - partial similarity", func(t *testing.T) {
		cfg := &policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.50),
			AmbiguityBand:       ptrF64(0.10),
			TopK:                ptrInt(5),
		}
		g, err := NewSpiderSenseGuardWithDB(db, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Equally similar to all patterns -> score ~0.577, within [0.40, 0.60]
		result := g.Screen([]float32{0.577, 0.577, 0.577})
		if result.Verdict != VerdictAmbiguous {
			t.Errorf("expected ambiguous, got %s (top_score=%v)", result.Verdict, result.TopScore)
		}
	})

	t.Run("no pattern db returns allow", func(t *testing.T) {
		g, err := NewSpiderSenseGuard(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		result := g.Screen([]float32{1, 0, 0})
		if result.Verdict != VerdictAllow {
			t.Errorf("expected allow with no pattern DB, got %s", result.Verdict)
		}
	})
}

// --- SpiderSenseGuard.Check ---

func TestSpiderSenseGuardCheck(t *testing.T) {
	db := testPatternDB(t)

	t.Run("action with embedding - deny", func(t *testing.T) {
		cfg := &policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.85),
			AmbiguityBand:       ptrF64(0.10),
			TopK:                ptrInt(5),
		}
		g, err := NewSpiderSenseGuardWithDB(db, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		action := Custom("spider_sense", map[string]interface{}{
			"embedding": []interface{}{float64(1), float64(0), float64(0)},
		})
		result := g.Check(action, NewContext())
		if result.Allowed {
			t.Error("expected block for high-similarity embedding")
		}
		if result.Guard != "spider_sense" {
			t.Errorf("expected guard name spider_sense, got %s", result.Guard)
		}
	})

	t.Run("action with embedding - allow", func(t *testing.T) {
		cfg := &policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.85),
			AmbiguityBand:       ptrF64(0.10),
			TopK:                ptrInt(5),
		}
		g, err := NewSpiderSenseGuardWithDB(db, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		action := Custom("spider_sense", map[string]interface{}{
			"embedding": []interface{}{float64(0.577), float64(0.577), float64(0.577)},
		})
		result := g.Check(action, NewContext())
		if !result.Allowed {
			t.Errorf("expected allow for low-similarity embedding: %s", result.Message)
		}
	})

	t.Run("action without embedding - allow", func(t *testing.T) {
		cfg := &policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.85),
			AmbiguityBand:       ptrF64(0.10),
			TopK:                ptrInt(5),
		}
		g, err := NewSpiderSenseGuardWithDB(db, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		action := Custom("spider_sense", "not a map")
		result := g.Check(action, NewContext())
		if !result.Allowed {
			t.Error("expected allow when no embedding present")
		}
	})

	t.Run("action with map but no embedding key - allow", func(t *testing.T) {
		cfg := &policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.85),
			AmbiguityBand:       ptrF64(0.10),
			TopK:                ptrInt(5),
		}
		g, err := NewSpiderSenseGuardWithDB(db, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		action := Custom("spider_sense", map[string]interface{}{
			"other_key": "value",
		})
		result := g.Check(action, NewContext())
		if !result.Allowed {
			t.Error("expected allow when embedding key missing")
		}
	})

	t.Run("ambiguous returns warn (allowed)", func(t *testing.T) {
		cfg := &policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.50),
			AmbiguityBand:       ptrF64(0.10),
			TopK:                ptrInt(5),
		}
		g, err := NewSpiderSenseGuardWithDB(db, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		action := Custom("spider_sense", map[string]interface{}{
			"embedding": []interface{}{float64(0.577), float64(0.577), float64(0.577)},
		})
		result := g.Check(action, NewContext())
		if !result.Allowed {
			t.Error("expected warn (allowed=true) for ambiguous match")
		}
		if result.Severity != Warning {
			t.Errorf("expected Warning severity for ambiguous, got %v", result.Severity)
		}
	})

	t.Run("handles all action types", func(t *testing.T) {
		g, err := NewSpiderSenseGuard(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !g.Handles(FileAccess("/test")) {
			t.Error("expected Handles(file_access) = true")
		}
		if !g.Handles(NetworkEgress("example.com", 443)) {
			t.Error("expected Handles(network_egress) = true")
		}
		if !g.Handles(Custom("any", nil)) {
			t.Error("expected Handles(custom) = true")
		}
	})
}

// --- Config validation ---

func TestSpiderSenseConfigValidation(t *testing.T) {
	db := testPatternDB(t)

	t.Run("invalid threshold", func(t *testing.T) {
		cfg := &policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(1.5),
			AmbiguityBand:       ptrF64(0.10),
			TopK:                ptrInt(5),
		}
		_, err := NewSpiderSenseGuardWithDB(db, cfg)
		if err == nil {
			t.Fatal("expected error for threshold > 1.0")
		}
	})

	t.Run("out of range bounds", func(t *testing.T) {
		cfg := &policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.95),
			AmbiguityBand:       ptrF64(0.10),
			TopK:                ptrInt(5),
		}
		_, err := NewSpiderSenseGuardWithDB(db, cfg)
		if err == nil {
			t.Fatal("expected error when upper_bound > 1.0")
		}
	})

	t.Run("defaults used when nil config", func(t *testing.T) {
		g, err := NewSpiderSenseGuard(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if g.threshold != DefaultSimilarityThreshold {
			t.Errorf("expected default threshold %v, got %v", DefaultSimilarityThreshold, g.threshold)
		}
		if g.ambiguityBand != DefaultAmbiguityBand {
			t.Errorf("expected default ambiguity band %v, got %v", DefaultAmbiguityBand, g.ambiguityBand)
		}
		if g.topK != DefaultTopK {
			t.Errorf("expected default top_k %v, got %v", DefaultTopK, g.topK)
		}
	})

	t.Run("explicit empty patterns rejected", func(t *testing.T) {
		cfg := &policy.SpiderSenseConfig{
			Patterns: []policy.PatternEntryConfig{},
		}
		_, err := NewSpiderSenseGuard(cfg)
		if err == nil {
			t.Fatal("expected error for explicit empty patterns")
		}
	})

	t.Run("missing patterns and pattern_db_path rejected", func(t *testing.T) {
		cfg := &policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.85),
			AmbiguityBand:       ptrF64(0.10),
			TopK:                ptrInt(5),
		}
		_, err := NewSpiderSenseGuard(cfg)
		if err == nil {
			t.Fatal("expected error when spider_sense config lacks pattern source")
		}
	})
}

// --- Guard name ---

func TestSpiderSenseGuardName(t *testing.T) {
	g, err := NewSpiderSenseGuard(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Name() != "spider_sense" {
		t.Errorf("expected name spider_sense, got %s", g.Name())
	}
}

// --- Inline patterns via config ---

func TestSpiderSenseInlinePatterns(t *testing.T) {
	cfg := &policy.SpiderSenseConfig{
		SimilarityThreshold: ptrF64(0.85),
		AmbiguityBand:       ptrF64(0.10),
		TopK:                ptrInt(5),
		Patterns: []policy.PatternEntryConfig{
			{ID: "p1", Category: "test", Stage: "perception", Label: "test pattern", Embedding: []float32{1, 0, 0}},
		},
	}
	g, err := NewSpiderSenseGuard(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.patternDb == nil {
		t.Fatal("expected pattern DB to be initialized from inline patterns")
	}
	if g.patternDb.Len() != 1 {
		t.Errorf("expected 1 pattern, got %d", g.patternDb.Len())
	}
}

func TestSpiderSensePatternDBPath(t *testing.T) {
	t.Run("loads builtin pattern db", func(t *testing.T) {
		cfg := &policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.85),
			AmbiguityBand:       ptrF64(0.10),
			TopK:                ptrInt(5),
			PatternDBPath:       "builtin:s2bench-v1",
			PatternDBVersion:    "s2bench-v1",
			PatternDBChecksum:   "8943003a9de9619d2f8f0bf133c9c7690ab3a582cbcbe4cb9692d44ee9643a73",
		}
		g, err := NewSpiderSenseGuard(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if g.patternDb == nil {
			t.Fatal("expected pattern DB to be initialized from builtin path")
		}
		if g.patternDb.Len() == 0 {
			t.Fatal("expected builtin pattern DB to contain entries")
		}
	})

	t.Run("loads external pattern db file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "patterns.json")
		content := []byte(`[
			{"id":"p1","category":"test","stage":"perception","label":"test pattern","embedding":[1.0,0.0,0.0]}
		]`)
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatalf("write patterns: %v", err)
		}

		cfg := &policy.SpiderSenseConfig{
			PatternDBPath:     path,
			PatternDBVersion:  "test-v1",
			PatternDBChecksum: checksumHex(content),
		}
		g, err := NewSpiderSenseGuard(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if g.patternDb == nil {
			t.Fatal("expected pattern DB to be initialized from file path")
		}
		if g.patternDb.Len() != 1 {
			t.Fatalf("expected 1 pattern, got %d", g.patternDb.Len())
		}
	})
}

func TestSpiderSenseEmbeddingProvider(t *testing.T) {
	t.Run("uses provider embedding when action embedding missing", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"embedding":[1.0,0.0,0.0]}]}`))
		}))
		defer server.Close()

		cfg := &policy.SpiderSenseConfig{
			Patterns: []policy.PatternEntryConfig{
				{
					ID:        "p1",
					Category:  "prompt_injection",
					Stage:     "perception",
					Label:     "ignore previous",
					Embedding: []float32{1, 0, 0},
				},
			},
			EmbeddingAPIURL: server.URL,
			EmbeddingAPIKey: "test-key",
			EmbeddingModel:  "text-embedding-3-small",
		}
		guard, err := NewSpiderSenseGuard(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		result := guard.Check(Custom("spider_sense", map[string]interface{}{"text": "hello"}), NewContext())
		if result.Allowed {
			t.Fatal("expected provider-based deny")
		}

		details, ok := result.Details.(map[string]interface{})
		if !ok {
			t.Fatalf("expected details map, got %T", result.Details)
		}
		if got := details["embedding_from"]; got != "provider" {
			t.Fatalf("expected embedding_from provider, got %v", got)
		}
	})

	t.Run("provider failures are fail-closed", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer server.Close()

		cfg := &policy.SpiderSenseConfig{
			Patterns: []policy.PatternEntryConfig{
				{
					ID:        "p1",
					Category:  "prompt_injection",
					Stage:     "perception",
					Label:     "ignore previous",
					Embedding: []float32{1, 0, 0},
				},
			},
			EmbeddingAPIURL: server.URL,
			EmbeddingAPIKey: "test-key",
			EmbeddingModel:  "text-embedding-3-small",
		}
		guard, err := NewSpiderSenseGuard(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		result := guard.Check(Custom("spider_sense", map[string]interface{}{"text": "hello"}), NewContext())
		if result.Allowed {
			t.Fatal("expected deny on provider failure")
		}
		if result.Severity != Error {
			t.Fatalf("expected Error severity, got %v", result.Severity)
		}
	})
}

func TestSpiderSenseEmbeddingCache(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"embedding":[1.0,0.0,0.0]}]}`))
	}))
	defer server.Close()

	cfg := &policy.SpiderSenseConfig{
		Patterns: []policy.PatternEntryConfig{
			{
				ID:        "p1",
				Category:  "prompt_injection",
				Stage:     "perception",
				Label:     "ignore previous",
				Embedding: []float32{1, 0, 0},
			},
		},
		EmbeddingAPIURL: server.URL + "?unused=true",
		EmbeddingAPIKey: "test-key",
		EmbeddingModel:  "text-embedding-3-small",
		Async: map[string]interface{}{
			"cache": map[string]interface{}{
				"enabled":     true,
				"ttl_seconds": 3600,
			},
		},
	}
	guard, err := NewSpiderSenseGuard(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	action := Custom("spider_sense", map[string]interface{}{"text": "   hello world   "})
	first := guard.Check(action, NewContext())
	second := guard.Check(action, NewContext())
	if first.Allowed || second.Allowed {
		t.Fatal("expected deny from provider embedding")
	}
	if requests != 1 {
		t.Fatalf("expected 1 provider call due to cache, got %d", requests)
	}
}

func TestSpiderSenseProviderRetryBackoff(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests < 3 {
			http.Error(w, "temporary failure", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"embedding":[1.0,0.0,0.0]}]}`))
	}))
	defer server.Close()

	cfg := &policy.SpiderSenseConfig{
		Patterns: []policy.PatternEntryConfig{
			{
				ID:        "p1",
				Category:  "prompt_injection",
				Stage:     "perception",
				Label:     "ignore previous",
				Embedding: []float32{1, 0, 0},
			},
		},
		EmbeddingAPIURL: server.URL,
		EmbeddingAPIKey: "test-key",
		EmbeddingModel:  "text-embedding-3-small",
		Async: map[string]interface{}{
			"retry": map[string]interface{}{
				"max_retries":        2,
				"initial_backoff_ms": 1,
				"max_backoff_ms":     2,
				"multiplier":         1.0,
			},
		},
	}
	guard, err := NewSpiderSenseGuard(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := guard.Check(Custom("spider_sense", map[string]interface{}{"text": "hello"}), NewContext())
	if result.Allowed {
		t.Fatal("expected deny after successful provider retry path")
	}
	details, ok := result.Details.(map[string]interface{})
	if !ok {
		t.Fatalf("expected details map, got %T", result.Details)
	}
	if details["embedding_from"] != "provider" {
		t.Fatalf("expected embedding_from provider, got %v", details["embedding_from"])
	}
	if requests != 3 {
		t.Fatalf("expected 3 provider attempts, got %d", requests)
	}
}

func TestSpiderSenseProviderRetryAfterHeader(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"embedding":[1.0,0.0,0.0]}]}`))
	}))
	defer server.Close()

	cfg := &policy.SpiderSenseConfig{
		Patterns: []policy.PatternEntryConfig{
			{
				ID:        "p1",
				Category:  "prompt_injection",
				Stage:     "perception",
				Label:     "ignore previous",
				Embedding: []float32{1, 0, 0},
			},
		},
		EmbeddingAPIURL: server.URL,
		EmbeddingAPIKey: "test-key",
		EmbeddingModel:  "text-embedding-3-small",
		Async: map[string]interface{}{
			"retry": map[string]interface{}{
				"max_retries":            1,
				"initial_backoff_ms":     1,
				"max_backoff_ms":         2,
				"multiplier":             1.0,
				"honor_retry_after":      true,
				"retry_after_cap_ms":     5,
				"honor_rate_limit_reset": true,
			},
		},
	}
	guard, err := NewSpiderSenseGuard(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	start := time.Now()
	result := guard.Check(Custom("spider_sense", map[string]interface{}{"text": "hello"}), NewContext())
	elapsed := time.Since(start)
	if result.Allowed {
		t.Fatal("expected deny after provider retry path")
	}
	if requests != 2 {
		t.Fatalf("expected 2 provider attempts, got %d", requests)
	}
	// Retry-After=1s should be honored, but capped at 5ms.
	if elapsed < 4*time.Millisecond {
		t.Fatalf("expected retry delay >= 4ms when honoring Retry-After cap, got %s", elapsed)
	}
}

func TestSpiderSenseProviderCircuitBreakerWarnMode(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "failure", http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := &policy.SpiderSenseConfig{
		Patterns: []policy.PatternEntryConfig{
			{
				ID:        "p1",
				Category:  "prompt_injection",
				Stage:     "perception",
				Label:     "ignore previous",
				Embedding: []float32{1, 0, 0},
			},
		},
		EmbeddingAPIURL: server.URL,
		EmbeddingAPIKey: "test-key",
		EmbeddingModel:  "text-embedding-3-small",
		Async: map[string]interface{}{
			"retry": map[string]interface{}{
				"max_retries": 0,
			},
			"circuit_breaker": map[string]interface{}{
				"failure_threshold": 1,
				"reset_timeout_ms":  60000,
				"success_threshold": 1,
				"on_open":           "warn",
			},
		},
	}
	guard, err := NewSpiderSenseGuard(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	first := guard.Check(Custom("spider_sense", map[string]interface{}{"text": "first"}), NewContext())
	if first.Allowed {
		t.Fatal("expected first provider failure to deny")
	}

	second := guard.Check(Custom("spider_sense", map[string]interface{}{"text": "second"}), NewContext())
	if !second.Allowed || second.Severity != Warning {
		t.Fatalf("expected warn result on open circuit, got allowed=%v severity=%v", second.Allowed, second.Severity)
	}
	details, ok := second.Details.(map[string]interface{})
	if !ok {
		t.Fatalf("expected details map, got %T", second.Details)
	}
	if details["on_open"] != "warn" {
		t.Fatalf("expected on_open=warn, got %v", details["on_open"])
	}
	if requests != 1 {
		t.Fatalf("expected second check to short-circuit provider call, got %d calls", requests)
	}
}

func TestSpiderSenseTrustStoreSignatureKeyID(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "patterns.json")
	dbContent := []byte(`[
		{"id":"p1","category":"test","stage":"perception","label":"test pattern","embedding":[1.0,0.0,0.0]}
	]`)
	if err := os.WriteFile(dbPath, dbContent, 0o644); err != nil {
		t.Fatalf("write db: %v", err)
	}
	checksum := checksumHex(dbContent)

	kp, err := sdkcrypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	publicKeyHex := kp.PublicKey().Hex()
	sum := sha256.Sum256([]byte(publicKeyHex))
	keyID := hex.EncodeToString(sum[:])[:16]
	message := []byte("spider_sense_db:v1:test-v1:" + checksum)
	sig, err := kp.Sign(message)
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}

	trustStorePath := filepath.Join(dir, "trust-store.json")
	trustStoreRaw, err := json.Marshal(map[string]interface{}{
		"keys": []map[string]string{
			{
				"key_id":     keyID,
				"public_key": publicKeyHex,
				"status":     "active",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal trust store: %v", err)
	}
	if err := os.WriteFile(trustStorePath, trustStoreRaw, 0o644); err != nil {
		t.Fatalf("write trust store: %v", err)
	}

	guard, err := NewSpiderSenseGuard(&policy.SpiderSenseConfig{
		PatternDBPath:           dbPath,
		PatternDBVersion:        "test-v1",
		PatternDBChecksum:       checksum,
		PatternDBSignature:      sig.Hex(),
		PatternDBSignatureKeyID: keyID,
		PatternDBTrustStorePath: trustStorePath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := guard.Check(Custom("spider_sense", map[string]interface{}{
		"embedding": []interface{}{float64(1), float64(0), float64(0)},
	}), NewContext())
	if result.Allowed {
		t.Fatal("expected deny against trust-store validated pattern DB")
	}
}

func TestSpiderSenseSignedPatternManifest(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "patterns.json")
	dbContent := []byte(`[
		{"id":"p1","category":"test","stage":"perception","label":"test pattern","embedding":[1.0,0.0,0.0]}
	]`)
	if err := os.WriteFile(dbPath, dbContent, 0o644); err != nil {
		t.Fatalf("write db: %v", err)
	}
	checksum := checksumHex(dbContent)

	dbKeyPair, err := sdkcrypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate db keypair: %v", err)
	}
	dbPublicKeyHex := dbKeyPair.PublicKey().Hex()
	dbKeyID := deriveSpiderSenseKeyID(dbPublicKeyHex)
	dbMessage := []byte("spider_sense_db:v1:test-v1:" + checksum)
	dbSignature, err := dbKeyPair.Sign(dbMessage)
	if err != nil {
		t.Fatalf("sign db message: %v", err)
	}

	trustStorePath := filepath.Join(dir, "trust-store.json")
	trustStoreRaw, err := json.Marshal(map[string]interface{}{
		"keys": []map[string]string{
			{
				"key_id":     dbKeyID,
				"public_key": dbPublicKeyHex,
				"status":     "active",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal trust store: %v", err)
	}
	if err := os.WriteFile(trustStorePath, trustStoreRaw, 0o644); err != nil {
		t.Fatalf("write trust store: %v", err)
	}

	rootKeyPair, err := sdkcrypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate root keypair: %v", err)
	}
	rootPublicKeyHex := rootKeyPair.PublicKey().Hex()
	rootKeyID := deriveSpiderSenseKeyID(rootPublicKeyHex)

	manifest := spiderSensePatternManifest{
		PatternDBPath:         filepath.Base(dbPath),
		PatternDBVersion:      "test-v1",
		PatternDBChecksum:     checksum,
		PatternDBSignature:    dbSignature.Hex(),
		PatternDBSignatureKey: dbKeyID,
		PatternDBTrustStore:   filepath.Base(trustStorePath),
		ManifestSignatureKey:  rootKeyID,
	}
	manifestSignature, err := rootKeyPair.Sign(spiderSenseManifestSigningMessage(manifest))
	if err != nil {
		t.Fatalf("sign manifest message: %v", err)
	}
	manifest.ManifestSignature = manifestSignature.Hex()

	manifestPath := filepath.Join(dir, "manifest.json")
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, manifestRaw, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	guard, err := NewSpiderSenseGuard(&policy.SpiderSenseConfig{
		PatternDBManifestPath:        manifestPath,
		PatternDBManifestTrustedKeys: []policy.SpiderSenseTrustedKeyConfig{{KeyID: rootKeyID, PublicKey: rootPublicKeyHex, Status: "active"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := guard.Check(Custom("spider_sense", map[string]interface{}{
		"embedding": []interface{}{float64(1), float64(0), float64(0)},
	}), NewContext())
	if result.Allowed {
		t.Fatal("expected deny against manifest-validated pattern DB")
	}

	assertManifestTamperFails := func(tampered spiderSensePatternManifest) {
		tamperedRaw, err := json.Marshal(tampered)
		if err != nil {
			t.Fatalf("marshal tampered manifest: %v", err)
		}
		if err := os.WriteFile(manifestPath, tamperedRaw, 0o644); err != nil {
			t.Fatalf("write tampered manifest: %v", err)
		}
		_, err = NewSpiderSenseGuard(&policy.SpiderSenseConfig{
			PatternDBManifestPath:        manifestPath,
			PatternDBManifestTrustedKeys: []policy.SpiderSenseTrustedKeyConfig{{KeyID: rootKeyID, PublicKey: rootPublicKeyHex, Status: "active"}},
		})
		if err == nil {
			t.Fatal("expected manifest signature verification failure after tamper")
		}
	}

	for _, vector := range loadSpiderSenseManifestTamperVectors(t) {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			tampered := manifest
			switch vector.Field {
			case "pattern_db_version":
				tampered.PatternDBVersion = vector.Value
			case "not_before":
				tampered.NotBefore = vector.Value
			case "not_after":
				tampered.NotAfter = vector.Value
			default:
				t.Fatalf("unsupported tamper field %q", vector.Field)
			}
			assertManifestTamperFails(tampered)
		})
	}
}

func TestSpiderSenseDeepPath(t *testing.T) {
	t.Run("ambiguous is denied by deep path verdict", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"choices": [
					{
						"message": {
							"content": "{\"verdict\":\"deny\",\"reason\":\"policy confidence high\"}"
						}
					}
				]
			}`))
		}))
		defer server.Close()

		guard, err := NewSpiderSenseGuard(&policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.50),
			AmbiguityBand:       ptrF64(0.10),
			Patterns: []policy.PatternEntryConfig{
				{ID: "p1", Category: "prompt_injection", Stage: "perception", Label: "ignore previous", Embedding: []float32{1, 0, 0}},
				{ID: "p2", Category: "data_exfiltration", Stage: "action", Label: "exfil data", Embedding: []float32{0, 1, 0}},
				{ID: "p3", Category: "privilege_escalation", Stage: "cognition", Label: "escalate", Embedding: []float32{0, 0, 1}},
			},
			LlmAPIURL:                server.URL,
			LlmAPIKey:                "llm-key",
			LlmModel:                 "gpt-4.1-mini",
			LlmPromptTemplateID:      "spider_sense.deep_path.json_classifier",
			LlmPromptTemplateVersion: "1.0.0",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		result := guard.Check(Custom("spider_sense", map[string]interface{}{
			"embedding": []interface{}{float64(0.577), float64(0.577), float64(0.577)},
		}), NewContext())
		if result.Allowed {
			t.Fatal("expected deep path deny")
		}
		details, ok := result.Details.(map[string]interface{})
		if !ok {
			t.Fatalf("expected details map, got %T", result.Details)
		}
		if details["analysis"] != "deep_path" {
			t.Fatalf("expected deep_path analysis, got %v", details["analysis"])
		}
		if details["verdict"] != "deny" {
			t.Fatalf("expected deep path verdict deny, got %v", details["verdict"])
		}
	})

	t.Run("deep path fail mode allow", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "llm down", http.StatusServiceUnavailable)
		}))
		defer server.Close()

		guard, err := NewSpiderSenseGuard(&policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.50),
			AmbiguityBand:       ptrF64(0.10),
			Patterns: []policy.PatternEntryConfig{
				{ID: "p1", Category: "prompt_injection", Stage: "perception", Label: "ignore previous", Embedding: []float32{1, 0, 0}},
				{ID: "p2", Category: "data_exfiltration", Stage: "action", Label: "exfil data", Embedding: []float32{0, 1, 0}},
				{ID: "p3", Category: "privilege_escalation", Stage: "cognition", Label: "escalate", Embedding: []float32{0, 0, 1}},
			},
			LlmAPIURL:                server.URL,
			LlmAPIKey:                "llm-key",
			LlmFailMode:              "allow",
			LlmPromptTemplateID:      "spider_sense.deep_path.json_classifier",
			LlmPromptTemplateVersion: "1.0.0",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		result := guard.Check(Custom("spider_sense", map[string]interface{}{
			"embedding": []interface{}{float64(0.577), float64(0.577), float64(0.577)},
		}), NewContext())
		if !result.Allowed {
			t.Fatal("expected allow when deep path fail mode=allow")
		}
		details, ok := result.Details.(map[string]interface{})
		if !ok {
			t.Fatalf("expected details map, got %T", result.Details)
		}
		if details["analysis"] != "deep_path_error" {
			t.Fatalf("expected deep_path_error analysis, got %v", details["analysis"])
		}
		if details["fail_mode"] != "allow" {
			t.Fatalf("expected fail_mode=allow, got %v", details["fail_mode"])
		}
	})

	t.Run("deep path requires template id/version", func(t *testing.T) {
		_, err := NewSpiderSenseGuard(&policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.50),
			AmbiguityBand:       ptrF64(0.10),
			Patterns: []policy.PatternEntryConfig{
				{ID: "p1", Category: "prompt_injection", Stage: "perception", Label: "ignore previous", Embedding: []float32{1, 0, 0}},
			},
			LlmAPIURL: "https://example.invalid/v1/chat/completions",
			LlmAPIKey: "llm-key",
		})
		if err == nil {
			t.Fatal("expected template id/version validation error")
		}
	})

	t.Run("deep path rejects unknown template", func(t *testing.T) {
		_, err := NewSpiderSenseGuard(&policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.50),
			AmbiguityBand:       ptrF64(0.10),
			Patterns: []policy.PatternEntryConfig{
				{ID: "p1", Category: "prompt_injection", Stage: "perception", Label: "ignore previous", Embedding: []float32{1, 0, 0}},
			},
			LlmAPIURL:                "https://example.invalid/v1/chat/completions",
			LlmAPIKey:                "llm-key",
			LlmPromptTemplateID:      "spider_sense.deep_path.unknown",
			LlmPromptTemplateVersion: "9.9.9",
		})
		if err == nil {
			t.Fatal("expected unknown template validation error")
		}
	})
}

func TestSpiderSensePatternDBIntegrityControls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "patterns.json")
	content := []byte(`[
		{"id":"p1","category":"test","stage":"perception","label":"test pattern","embedding":[1.0,0.0,0.0]}
	]`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write patterns: %v", err)
	}

	t.Run("version and checksum are required", func(t *testing.T) {
		_, err := NewSpiderSenseGuard(&policy.SpiderSenseConfig{
			PatternDBPath: path,
		})
		if err == nil {
			t.Fatal("expected missing integrity fields error")
		}
	})

	t.Run("signature/public key pair must be complete", func(t *testing.T) {
		_, err := NewSpiderSenseGuard(&policy.SpiderSenseConfig{
			PatternDBPath:      path,
			PatternDBVersion:   "test-v1",
			PatternDBChecksum:  checksumHex(content),
			PatternDBSignature: "abcd",
		})
		if err == nil {
			t.Fatal("expected signature/public key pairing error")
		}
	})

	t.Run("valid checksum without signature is accepted", func(t *testing.T) {
		guard, err := NewSpiderSenseGuard(&policy.SpiderSenseConfig{
			PatternDBPath:     path,
			PatternDBVersion:  "test-v1",
			PatternDBChecksum: checksumHex(content),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if guard.patternDb == nil {
			t.Fatal("expected pattern db to load")
		}
	})
}

func TestSpiderSenseMetricsHook(t *testing.T) {
	cfg := &policy.SpiderSenseConfig{
		SimilarityThreshold: ptrF64(0.85),
		AmbiguityBand:       ptrF64(0.10),
		TopK:                ptrInt(5),
		Patterns: []policy.PatternEntryConfig{
			{ID: "p1", Category: "test", Stage: "perception", Label: "test pattern", Embedding: []float32{1, 0, 0}},
		},
	}

	var mu sync.Mutex
	events := make([]SpiderSenseMetrics, 0, 2)
	guard, err := NewSpiderSenseGuardWithOptions(cfg, SpiderSenseGuardOptions{
		MetricsHook: func(event SpiderSenseMetrics) {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, event)
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_ = guard.Check(Custom("spider_sense", map[string]interface{}{
		"embedding": []interface{}{float64(1), float64(0), float64(0)},
	}), NewContext())
	_ = guard.Check(Custom("spider_sense", map[string]interface{}{
		"embedding": []interface{}{float64(0.2), float64(0.8), float64(0.0)},
	}), NewContext())

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("expected 2 metrics events, got %d", len(events))
	}
	if events[1].TotalCount != 2 {
		t.Fatalf("expected total_count=2, got %d", events[1].TotalCount)
	}
	if events[1].AmbiguityRate < 0 {
		t.Fatalf("expected non-negative ambiguity rate, got %f", events[1].AmbiguityRate)
	}
}

// --- Helper ---

func testPatternDB(t *testing.T) *PatternDb {
	t.Helper()
	data := []byte(`[
		{"id":"p1","category":"prompt_injection","stage":"perception","label":"ignore previous","embedding":[1.0,0.0,0.0]},
		{"id":"p2","category":"data_exfiltration","stage":"action","label":"exfil data","embedding":[0.0,1.0,0.0]},
		{"id":"p3","category":"privilege_escalation","stage":"cognition","label":"escalate","embedding":[0.0,0.0,1.0]}
	]`)
	db, err := ParsePatternDB(data)
	if err != nil {
		t.Fatalf("failed to parse test pattern DB: %v", err)
	}
	return db
}

func checksumHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
