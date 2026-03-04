package guards

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"

	"github.com/backbay-labs/clawdstrike-go/policy"
)

// Default configuration values matching the Rust core.
const (
	DefaultSimilarityThreshold = 0.85
	DefaultAmbiguityBand       = 0.10
	DefaultTopK                = 5
)

// CosineSimilarityF32 computes the cosine similarity between two float32
// vectors, using float64 precision for accumulation. Returns 0.0 if either
// vector has zero norm or the vectors have different lengths.
func CosineSimilarityF32(a, b []float32) float64 {
	if len(a) != len(b) {
		return 0.0
	}

	var dot, normA, normB float64
	for i := range a {
		xd := float64(a[i])
		yd := float64(b[i])
		dot += xd * yd
		normA += xd * xd
		normB += yd * yd
	}

	denom := math.Sqrt(normA) * math.Sqrt(normB)
	if denom == 0.0 {
		return 0.0
	}
	return dot / denom
}

// PatternEntry is a single entry in the pattern database.
type PatternEntry struct {
	ID        string    `json:"id"`
	Category  string    `json:"category"`
	Stage     string    `json:"stage"`
	Label     string    `json:"label"`
	Embedding []float32 `json:"embedding"`
}

// PatternMatch is a scored match from the pattern database.
type PatternMatch struct {
	Entry PatternEntry `json:"entry"`
	Score float64      `json:"score"`
}

// PatternDb is an in-memory pattern database for vector similarity search.
type PatternDb struct {
	entries     []PatternEntry
	expectedDim int
}

// ParsePatternDB parses a JSON byte slice containing a pattern array.
// Returns an error if the array is empty or embedding dimensions are
// inconsistent (fail-closed).
func ParsePatternDB(jsonData []byte) (*PatternDb, error) {
	var entries []PatternEntry
	if err := json.Unmarshal(jsonData, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse pattern DB: %w", err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("pattern DB must contain at least one entry")
	}

	dim := len(entries[0].Embedding)
	if dim == 0 {
		return nil, fmt.Errorf("pattern DB entries must have non-empty embeddings")
	}

	for i, entry := range entries {
		if len(entry.Embedding) != dim {
			return nil, fmt.Errorf(
				"pattern DB dimension mismatch at index %d: expected %d, got %d",
				i, dim, len(entry.Embedding),
			)
		}
	}

	return &PatternDb{
		entries:     entries,
		expectedDim: dim,
	}, nil
}

// Search performs brute-force cosine similarity search and returns the
// top-k matches sorted by descending similarity score.
func (db *PatternDb) Search(query []float32, topK int) []PatternMatch {
	scored := make([]PatternMatch, len(db.entries))
	for i, entry := range db.entries {
		scored[i] = PatternMatch{
			Entry: entry,
			Score: CosineSimilarityF32(query, entry.Embedding),
		}
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].Score > scored[j].Score
	})

	if topK < len(scored) {
		scored = scored[:topK]
	}
	return scored
}

// Len returns the number of entries in the database.
func (db *PatternDb) Len() int {
	return len(db.entries)
}

// IsEmpty reports whether the database contains no entries.
func (db *PatternDb) IsEmpty() bool {
	return len(db.entries) == 0
}

// ExpectedDim returns the expected embedding dimension.
func (db *PatternDb) ExpectedDim() int {
	return db.expectedDim
}

// ScreeningVerdict represents the outcome of Spider-Sense screening.
type ScreeningVerdict string

const (
	VerdictDeny      ScreeningVerdict = "deny"
	VerdictAmbiguous ScreeningVerdict = "ambiguous"
	VerdictAllow     ScreeningVerdict = "allow"
)

// ScreeningResult is the result of a Spider-Sense screening operation.
type ScreeningResult struct {
	Verdict      ScreeningVerdict `json:"verdict"`
	TopScore     float64          `json:"top_score"`
	Threshold    float64          `json:"threshold"`
	AmbiguityBand float64         `json:"ambiguity_band"`
	TopMatches   []PatternMatch   `json:"top_matches"`
}

// SpiderSenseGuard implements embedding-based threat detection using cosine
// similarity against a pattern database. It wraps a PatternDb and screening
// thresholds. Fail-closed: invalid configuration causes an error at
// construction time.
type SpiderSenseGuard struct {
	patternDb    *PatternDb
	upperBound   float64
	lowerBound   float64
	topK         int
	threshold    float64
	ambiguityBand float64
}

// NewSpiderSenseGuard creates a new SpiderSenseGuard from policy config.
// Returns an error if the config is invalid or the pattern database cannot
// be parsed.
func NewSpiderSenseGuard(cfg *policy.SpiderSenseConfig) (*SpiderSenseGuard, error) {
	threshold := DefaultSimilarityThreshold
	ambiguityBand := DefaultAmbiguityBand
	topK := DefaultTopK

	if cfg != nil {
		if cfg.SimilarityThreshold != nil {
			threshold = *cfg.SimilarityThreshold
		}
		if cfg.AmbiguityBand != nil {
			ambiguityBand = *cfg.AmbiguityBand
		}
		if cfg.TopK != nil {
			topK = *cfg.TopK
		}
	}

	// Validate threshold range.
	if math.IsNaN(threshold) || math.IsInf(threshold, 0) {
		return nil, fmt.Errorf("spider_sense: similarity_threshold must be a finite number")
	}
	if threshold < 0.0 || threshold > 1.0 {
		return nil, fmt.Errorf("spider_sense: similarity_threshold must be in [0.0, 1.0], got %v", threshold)
	}

	// Validate ambiguity band range.
	if math.IsNaN(ambiguityBand) || math.IsInf(ambiguityBand, 0) {
		return nil, fmt.Errorf("spider_sense: ambiguity_band must be a finite number")
	}
	if ambiguityBand < 0.0 || ambiguityBand > 1.0 {
		return nil, fmt.Errorf("spider_sense: ambiguity_band must be in [0.0, 1.0], got %v", ambiguityBand)
	}

	upperBound := threshold + ambiguityBand
	lowerBound := threshold - ambiguityBand

	if lowerBound < 0.0 || lowerBound > 1.0 || upperBound < 0.0 || upperBound > 1.0 {
		return nil, fmt.Errorf(
			"spider_sense: threshold/band produce invalid decision range: lower=%.3f, upper=%.3f; expected both in [0.0, 1.0]",
			lowerBound, upperBound,
		)
	}

	if topK < 1 {
		return nil, fmt.Errorf("spider_sense: top_k must be at least 1")
	}

	var db *PatternDb
	if cfg != nil && len(cfg.Patterns) > 0 {
		var err error
		db, err = ParsePatternDB(cfg.Patterns)
		if err != nil {
			return nil, fmt.Errorf("spider_sense: %w", err)
		}
	}

	return &SpiderSenseGuard{
		patternDb:     db,
		upperBound:    upperBound,
		lowerBound:    lowerBound,
		topK:          topK,
		threshold:     threshold,
		ambiguityBand: ambiguityBand,
	}, nil
}

// NewSpiderSenseGuardWithDB creates a SpiderSenseGuard with a pre-parsed
// PatternDb. This is useful when the pattern database is loaded externally.
func NewSpiderSenseGuardWithDB(db *PatternDb, cfg *policy.SpiderSenseConfig) (*SpiderSenseGuard, error) {
	g, err := NewSpiderSenseGuard(cfg)
	if err != nil {
		return nil, err
	}
	g.patternDb = db
	return g, nil
}

func (g *SpiderSenseGuard) Name() string { return "spider_sense" }

// Handles returns true for all action types. Spider-Sense screens embeddings
// passed via CustomData on any action.
func (g *SpiderSenseGuard) Handles(_ GuardAction) bool {
	return true
}

// Check evaluates the action by extracting an embedding from CustomData and
// screening it against the pattern database. If no embedding is present or
// no pattern database is loaded, the action is allowed (can't screen without
// data).
func (g *SpiderSenseGuard) Check(action GuardAction, _ *GuardContext) GuardResult {
	if g.patternDb == nil {
		return Allow(g.Name())
	}

	embedding, ok := extractEmbedding(action)
	if !ok {
		return Allow(g.Name())
	}

	result := g.Screen(embedding)

	details := map[string]interface{}{
		"verdict":        string(result.Verdict),
		"top_score":      result.TopScore,
		"threshold":      result.Threshold,
		"ambiguity_band": result.AmbiguityBand,
		"match_count":    len(result.TopMatches),
	}

	switch result.Verdict {
	case VerdictDeny:
		topLabel := ""
		if len(result.TopMatches) > 0 {
			topLabel = result.TopMatches[0].Entry.Label
		}
		return Block(g.Name(), Error,
			fmt.Sprintf("Spider-Sense threat detected (score=%.3f, label=%q)", result.TopScore, topLabel)).
			WithDetails(details)
	case VerdictAmbiguous:
		return Warn(g.Name(),
			fmt.Sprintf("Spider-Sense ambiguous match detected (score=%.3f)", result.TopScore)).
			WithDetails(details)
	default:
		return Allow(g.Name()).WithDetails(details)
	}
}

// Screen performs standalone screening of an embedding vector against the
// pattern database. This is exported for direct SDK use without going
// through the Guard interface.
func (g *SpiderSenseGuard) Screen(embedding []float32) ScreeningResult {
	if g.patternDb == nil {
		return ScreeningResult{
			Verdict:       VerdictAllow,
			TopScore:      0.0,
			Threshold:     g.threshold,
			AmbiguityBand: g.ambiguityBand,
		}
	}

	matches := g.patternDb.Search(embedding, g.topK)
	topScore := 0.0
	if len(matches) > 0 {
		topScore = matches[0].Score
	}

	var verdict ScreeningVerdict
	if topScore >= g.upperBound {
		verdict = VerdictDeny
	} else if topScore <= g.lowerBound {
		verdict = VerdictAllow
	} else {
		verdict = VerdictAmbiguous
	}

	return ScreeningResult{
		Verdict:       verdict,
		TopScore:      topScore,
		Threshold:     g.threshold,
		AmbiguityBand: g.ambiguityBand,
		TopMatches:    matches,
	}
}

// extractEmbedding attempts to extract a []float32 embedding from the
// action's CustomData. It expects CustomData to be a map[string]interface{}
// with an "embedding" key containing a []interface{} of float64 values
// (standard JSON number representation in Go).
func extractEmbedding(action GuardAction) ([]float32, bool) {
	data, ok := action.CustomData.(map[string]interface{})
	if !ok {
		return nil, false
	}

	rawEmb, ok := data["embedding"]
	if !ok {
		return nil, false
	}

	switch emb := rawEmb.(type) {
	case []interface{}:
		result := make([]float32, len(emb))
		for i, v := range emb {
			f, ok := v.(float64)
			if !ok {
				return nil, false
			}
			result[i] = float32(f)
		}
		return result, true
	case []float64:
		result := make([]float32, len(emb))
		for i, v := range emb {
			result[i] = float32(v)
		}
		return result, true
	case []float32:
		return emb, true
	default:
		return nil, false
	}
}
