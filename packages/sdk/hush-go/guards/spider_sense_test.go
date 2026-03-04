package guards

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/backbay-labs/clawdstrike-go/policy"
)

// Helpers for pointer literals in config structs.
func ptrF64(v float64) *float64 { return &v }
func ptrInt(v int) *int         { return &v }

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
		cfg := &policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.85),
			AmbiguityBand:       ptrF64(0.10),
			TopK:                ptrInt(5),
		}
		g, err := NewSpiderSenseGuard(cfg)
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
		cfg := &policy.SpiderSenseConfig{
			SimilarityThreshold: ptrF64(0.85),
			AmbiguityBand:       ptrF64(0.10),
			TopK:                ptrInt(5),
		}
		g, err := NewSpiderSenseGuard(cfg)
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

	t.Run("defaults used when nil values", func(t *testing.T) {
		cfg := &policy.SpiderSenseConfig{}
		g, err := NewSpiderSenseGuard(cfg)
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
}

// --- Guard name ---

func TestSpiderSenseGuardName(t *testing.T) {
	cfg := &policy.SpiderSenseConfig{}
	g, err := NewSpiderSenseGuard(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Name() != "spider_sense" {
		t.Errorf("expected name spider_sense, got %s", g.Name())
	}
}

// --- Inline patterns via config ---

func TestSpiderSenseInlinePatterns(t *testing.T) {
	patterns := []PatternEntry{
		{ID: "p1", Category: "test", Stage: "perception", Label: "test pattern", Embedding: []float32{1, 0, 0}},
	}
	patternJSON, err := json.Marshal(patterns)
	if err != nil {
		t.Fatalf("marshal patterns: %v", err)
	}

	cfg := &policy.SpiderSenseConfig{
		SimilarityThreshold: ptrF64(0.85),
		AmbiguityBand:       ptrF64(0.10),
		TopK:                ptrInt(5),
		Patterns:            json.RawMessage(patternJSON),
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
