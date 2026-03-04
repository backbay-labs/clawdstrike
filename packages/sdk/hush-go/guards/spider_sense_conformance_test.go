package guards

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/backbay-labs/clawdstrike-go/policy"
)

type spiderSenseConformanceConfig struct {
	SimilarityThreshold float64                     `json:"similarity_threshold"`
	AmbiguityBand       float64                     `json:"ambiguity_band"`
	TopK                int                         `json:"top_k"`
	Patterns            []policy.PatternEntryConfig `json:"patterns"`
}

type spiderSenseConformanceCheck struct {
	Name                  string    `json:"name"`
	Embedding             []float64 `json:"embedding"`
	ExpectedAllowed       bool      `json:"expected_allowed"`
	ExpectedSeverity      string    `json:"expected_severity"`
	ExpectedVerdict       string    `json:"expected_verdict"`
	ExpectedEmbeddingFrom string    `json:"expected_embedding_from"`
	ExpectedAnalysis      string    `json:"expected_analysis"`
	ExpectedTopMatchesLen int       `json:"expected_top_matches_len"`
	TopScoreMin           float64   `json:"top_score_min"`
	TopScoreMax           float64   `json:"top_score_max"`
}

type spiderSenseConformanceVector struct {
	Name   string                        `json:"name"`
	Config spiderSenseConformanceConfig  `json:"config"`
	Checks []spiderSenseConformanceCheck `json:"checks"`
}

func TestSpiderSenseConformanceVectors(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "..", "..", "fixtures", "spider-sense", "conformance_vectors.json"))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var vectors []spiderSenseConformanceVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}

	for _, vector := range vectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			cfg := &policy.SpiderSenseConfig{
				SimilarityThreshold: &vector.Config.SimilarityThreshold,
				AmbiguityBand:       &vector.Config.AmbiguityBand,
				TopK:                &vector.Config.TopK,
				Patterns:            vector.Config.Patterns,
			}
			guard, err := NewSpiderSenseGuard(cfg)
			if err != nil {
				t.Fatalf("new guard: %v", err)
			}

			for _, check := range vector.Checks {
				check := check
				t.Run(check.Name, func(t *testing.T) {
					embedding := make([]interface{}, len(check.Embedding))
					for i, v := range check.Embedding {
						embedding[i] = v
					}
					result := guard.Check(
						Custom("spider_sense", map[string]interface{}{"embedding": embedding}),
						NewContext(),
					)
					if result.Allowed != check.ExpectedAllowed {
						t.Fatalf("allowed mismatch: expected=%v got=%v", check.ExpectedAllowed, result.Allowed)
					}
					if got := result.Severity.String(); got != check.ExpectedSeverity {
						t.Fatalf("severity mismatch: expected=%s got=%s", check.ExpectedSeverity, got)
					}

					details, ok := result.Details.(map[string]interface{})
					if !ok {
						t.Fatalf("expected details map, got %T", result.Details)
					}
					if got, _ := details["verdict"].(string); got != check.ExpectedVerdict {
						t.Fatalf("verdict mismatch: expected=%s got=%s", check.ExpectedVerdict, got)
					}
					if got, _ := details["embedding_from"].(string); got != check.ExpectedEmbeddingFrom {
						t.Fatalf("embedding_from mismatch: expected=%s got=%s", check.ExpectedEmbeddingFrom, got)
					}
					if got, _ := details["analysis"].(string); got != check.ExpectedAnalysis {
						t.Fatalf("analysis mismatch: expected=%s got=%s", check.ExpectedAnalysis, got)
					}

					topScore, ok := details["top_score"].(float64)
					if !ok {
						t.Fatalf("expected top_score float64, got %T", details["top_score"])
					}
					if topScore < check.TopScoreMin || topScore > check.TopScoreMax {
						t.Fatalf(
							"top_score out of range: got=%f expected in [%f, %f]",
							topScore, check.TopScoreMin, check.TopScoreMax,
						)
					}

					var topMatches []map[string]interface{}
					switch typed := details["top_matches"].(type) {
					case []map[string]interface{}:
						topMatches = typed
					case []interface{}:
						topMatches = make([]map[string]interface{}, 0, len(typed))
						for _, item := range typed {
							entry, ok := item.(map[string]interface{})
							if !ok {
								t.Fatalf("expected top_matches entry object, got %T", item)
							}
							topMatches = append(topMatches, entry)
						}
					default:
						t.Fatalf("expected top_matches array, got %T", details["top_matches"])
					}
					if check.ExpectedTopMatchesLen > 0 && len(topMatches) != check.ExpectedTopMatchesLen {
						t.Fatalf("top_matches length mismatch: expected=%d got=%d", check.ExpectedTopMatchesLen, len(topMatches))
					}
					if len(topMatches) == 0 {
						t.Fatal("expected non-empty top_matches")
					}
					first := topMatches[0]
					required := []string{"id", "category", "stage", "label", "score"}
					for _, key := range required {
						if _, exists := first[key]; !exists {
							t.Fatalf("expected top_matches[0].%s", key)
						}
					}
				})
			}
		})
	}
}
