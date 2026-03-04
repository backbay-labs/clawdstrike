package guards

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sdkcrypto "github.com/backbay-labs/clawdstrike-go/crypto"
	"github.com/backbay-labs/clawdstrike-go/policy"
)

// Default configuration values matching the Rust core.
const (
	DefaultSimilarityThreshold = 0.85
	DefaultAmbiguityBand       = 0.10
	DefaultTopK                = 5
)

const (
	defaultEmbeddingTimeout  = 15 * time.Second
	defaultMaxEmbeddingBytes = 2 << 20 // 2 MiB
)

//go:embed patterns/s2bench-v1.json
var spiderSensePatternFS embed.FS

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
	if denom == 0.0 || math.IsNaN(denom) || math.IsInf(denom, 0) {
		return 0.0
	}
	result := dot / denom
	if math.IsNaN(result) || math.IsInf(result, 0) {
		return 0.0
	}
	return result
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
		for j, v := range entry.Embedding {
			if !isFiniteF32(v) {
				return nil, fmt.Errorf("pattern DB non-finite embedding value at entry=%d dim=%d", i, j)
			}
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
	Verdict       ScreeningVerdict `json:"verdict"`
	TopScore      float64          `json:"top_score"`
	Threshold     float64          `json:"threshold"`
	AmbiguityBand float64          `json:"ambiguity_band"`
	TopMatches    []PatternMatch   `json:"top_matches"`
}

// SpiderSenseMetrics contains one point-in-time metric snapshot per check.
type SpiderSenseMetrics struct {
	Verdict         ScreeningVerdict `json:"verdict"`
	TopScore        float64          `json:"top_score"`
	Severity        string           `json:"severity"`
	DBSource        string           `json:"db_source"`
	DBVersion       string           `json:"db_version"`
	AllowCount      int              `json:"allow_count"`
	AmbiguousCount  int              `json:"ambiguous_count"`
	DenyCount       int              `json:"deny_count"`
	TotalCount      int              `json:"total_count"`
	AmbiguityRate   float64          `json:"ambiguity_rate"`
	Screened        bool             `json:"screened"`
	SkipReason      string           `json:"skip_reason,omitempty"`
	EmbeddingSource string           `json:"embedding_source,omitempty"`
}

// SpiderSenseMetricsHook is invoked after each check.
type SpiderSenseMetricsHook func(SpiderSenseMetrics)

// SpiderSenseGuardOptions configures optional runtime behavior.
type SpiderSenseGuardOptions struct {
	HTTPClient  *http.Client
	MetricsHook SpiderSenseMetricsHook
}

type spiderSenseProvider string

const (
	providerOpenAI spiderSenseProvider = "openai"
	providerCohere spiderSenseProvider = "cohere"
	providerVoyage spiderSenseProvider = "voyage"
)

// SpiderSenseGuard implements embedding-based threat detection using cosine
// similarity against a pattern database. It wraps a PatternDb and screening
// thresholds. Fail-closed: invalid configuration causes an error at
// construction time.
type SpiderSenseGuard struct {
	patternDb     *PatternDb
	upperBound    float64
	lowerBound    float64
	topK          int
	threshold     float64
	ambiguityBand float64
	dbSource      string
	dbVersion     string

	embeddingEnabled bool
	embeddingAPIURL  string
	embeddingAPIKey  string
	embeddingModel   string
	embeddingProv    spiderSenseProvider
	httpClient       *http.Client

	metricsHook SpiderSenseMetricsHook
	metricsMu   sync.Mutex
	totalCount  int
	allowCount  int
	warnCount   int
	denyCount   int
}

// NewSpiderSenseGuard creates a new SpiderSenseGuard from policy config.
// Returns an error if the config is invalid or the pattern database cannot
// be parsed.
func NewSpiderSenseGuard(cfg *policy.SpiderSenseConfig) (*SpiderSenseGuard, error) {
	return NewSpiderSenseGuardWithOptions(cfg, SpiderSenseGuardOptions{})
}

// NewSpiderSenseGuardWithOptions creates a new SpiderSenseGuard with optional
// runtime hooks.
func NewSpiderSenseGuardWithOptions(cfg *policy.SpiderSenseConfig, opts SpiderSenseGuardOptions) (*SpiderSenseGuard, error) {
	return newSpiderSenseGuard(cfg, nil, opts)
}

func newSpiderSenseGuard(cfg *policy.SpiderSenseConfig, patternDB *PatternDb, opts SpiderSenseGuardOptions) (*SpiderSenseGuard, error) {
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

	if math.IsNaN(threshold) || math.IsInf(threshold, 0) {
		return nil, fmt.Errorf("spider_sense: similarity_threshold must be a finite number")
	}
	if threshold < 0.0 || threshold > 1.0 {
		return nil, fmt.Errorf("spider_sense: similarity_threshold must be in [0.0, 1.0], got %v", threshold)
	}

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

	db := patternDB
	dbSource := ""
	dbVersion := ""
	if cfg != nil && db == nil {
		hasInlinePatterns := cfg.Patterns != nil
		hasPatternPath := strings.TrimSpace(cfg.PatternDBPath) != ""

		switch {
		case hasInlinePatterns && len(cfg.Patterns) == 0:
			return nil, fmt.Errorf("spider_sense: patterns must contain at least one entry when set")
		case hasInlinePatterns:
			jsonBytes, err := json.Marshal(cfg.Patterns)
			if err != nil {
				return nil, fmt.Errorf("spider_sense: failed to serialize patterns: %w", err)
			}
			db, err = ParsePatternDB(jsonBytes)
			if err != nil {
				return nil, fmt.Errorf("spider_sense: %w", err)
			}
			dbSource = "inline"
			dbVersion = "inline"
		case hasPatternPath:
			var err error
			db, dbSource, dbVersion, err = loadPatternDBFromPath(cfg)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf(
				"spider_sense: patterns or pattern_db_path must be set when spider_sense guard is enabled",
			)
		}
	}

	embeddingEnabled, provider, err := validateEmbeddingProviderConfig(cfg)
	if err != nil {
		return nil, err
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultEmbeddingTimeout}
	}

	if cfg != nil {
		if dbSource == "" {
			dbSource = strings.TrimSpace(cfg.PatternDBPath)
		}
		if dbVersion == "" {
			dbVersion = strings.TrimSpace(cfg.PatternDBVersion)
		}
	}

	return &SpiderSenseGuard{
		patternDb:        db,
		upperBound:       upperBound,
		lowerBound:       lowerBound,
		topK:             topK,
		threshold:        threshold,
		ambiguityBand:    ambiguityBand,
		dbSource:         dbSource,
		dbVersion:        dbVersion,
		embeddingEnabled: embeddingEnabled,
		embeddingProv:    provider,
		httpClient:       client,
		metricsHook:      opts.MetricsHook,
		embeddingAPIURL:  strings.TrimSpace(cfgOrEmpty(cfg, func(c *policy.SpiderSenseConfig) string { return c.EmbeddingAPIURL })),
		embeddingAPIKey:  strings.TrimSpace(cfgOrEmpty(cfg, func(c *policy.SpiderSenseConfig) string { return c.EmbeddingAPIKey })),
		embeddingModel:   strings.TrimSpace(cfgOrEmpty(cfg, func(c *policy.SpiderSenseConfig) string { return c.EmbeddingModel })),
	}, nil
}

func cfgOrEmpty(cfg *policy.SpiderSenseConfig, getter func(*policy.SpiderSenseConfig) string) string {
	if cfg == nil {
		return ""
	}
	return getter(cfg)
}

// NewSpiderSenseGuardWithDB creates a SpiderSenseGuard with a pre-parsed
// PatternDb. This is useful when the pattern database is loaded externally.
func NewSpiderSenseGuardWithDB(db *PatternDb, cfg *policy.SpiderSenseConfig) (*SpiderSenseGuard, error) {
	if db == nil {
		return nil, fmt.Errorf("spider_sense: pattern DB cannot be nil")
	}
	return newSpiderSenseGuard(cfg, db, SpiderSenseGuardOptions{})
}

func (g *SpiderSenseGuard) Name() string { return "spider_sense" }

// Handles returns true for all action types. Spider-Sense screens embeddings
// passed via CustomData on any action.
func (g *SpiderSenseGuard) Handles(_ GuardAction) bool {
	return true
}

// Check evaluates the action by extracting an embedding from CustomData and
// screening it against the pattern database.
func (g *SpiderSenseGuard) Check(action GuardAction, ctx *GuardContext) GuardResult {
	if g.patternDb == nil {
		result := Allow(g.Name())
		g.emitMetrics(VerdictAllow, 0, result.Severity, false, "", "pattern_db_missing")
		return result
	}

	embedding, ok := extractEmbedding(action)
	embeddingSource := "action"
	if !ok {
		if !g.embeddingEnabled {
			result := Allow(g.Name())
			g.emitMetrics(VerdictAllow, 0, result.Severity, false, "", "embedding_missing")
			return result
		}

		text := actionToText(action)
		fetched, err := g.fetchEmbedding(text, ctx)
		if err != nil {
			details := map[string]interface{}{
				"analysis":       "provider",
				"error":          err.Error(),
				"db_source":      g.dbSource,
				"db_version":     g.dbVersion,
				"embedding_from": "provider",
			}
			result := Block(g.Name(), Error, "Spider-Sense embedding provider error (fail-closed)").WithDetails(details)
			g.emitMetrics(VerdictDeny, 0, result.Severity, true, "provider_error", "provider")
			return result
		}
		embedding = fetched
		embeddingSource = "provider"
	}

	expectedDim := g.patternDb.ExpectedDim()
	if expectedDim > 0 && len(embedding) != expectedDim {
		details := map[string]interface{}{
			"analysis":       "validation",
			"error":          fmt.Sprintf("embedding dimension mismatch: got %d, expected %d", len(embedding), expectedDim),
			"db_source":      g.dbSource,
			"db_version":     g.dbVersion,
			"embedding_from": embeddingSource,
		}
		result := Block(g.Name(), Error, "Spider-Sense embedding dimension mismatch (fail-closed)").WithDetails(details)
		g.emitMetrics(VerdictDeny, 0, result.Severity, true, "dimension_mismatch", embeddingSource)
		return result
	}

	result := g.Screen(embedding)
	details := g.resultDetails(result, embeddingSource)

	switch result.Verdict {
	case VerdictDeny:
		topLabel := ""
		if len(result.TopMatches) > 0 {
			topLabel = result.TopMatches[0].Entry.Label
		}
		guardResult := Block(g.Name(), Error,
			fmt.Sprintf("Spider-Sense threat detected (score=%.3f, label=%q)", result.TopScore, topLabel)).
			WithDetails(details)
		g.emitMetrics(result.Verdict, result.TopScore, guardResult.Severity, true, "", embeddingSource)
		return guardResult
	case VerdictAmbiguous:
		guardResult := Warn(g.Name(),
			fmt.Sprintf("Spider-Sense ambiguous match detected (score=%.3f)", result.TopScore)).
			WithDetails(details)
		g.emitMetrics(result.Verdict, result.TopScore, guardResult.Severity, true, "", embeddingSource)
		return guardResult
	default:
		guardResult := Allow(g.Name()).WithDetails(details)
		g.emitMetrics(result.Verdict, result.TopScore, guardResult.Severity, true, "", embeddingSource)
		return guardResult
	}
}

func (g *SpiderSenseGuard) resultDetails(result ScreeningResult, embeddingSource string) map[string]interface{} {
	matches := make([]map[string]interface{}, 0, len(result.TopMatches))
	for _, m := range result.TopMatches {
		matches = append(matches, map[string]interface{}{
			"id":       m.Entry.ID,
			"category": m.Entry.Category,
			"stage":    m.Entry.Stage,
			"label":    m.Entry.Label,
			"score":    m.Score,
		})
	}

	details := map[string]interface{}{
		"analysis":       "fast_path",
		"verdict":        string(result.Verdict),
		"top_score":      result.TopScore,
		"threshold":      result.Threshold,
		"ambiguity_band": result.AmbiguityBand,
		"top_matches":    matches,
		"db_source":      g.dbSource,
		"db_version":     g.dbVersion,
		"embedding_from": embeddingSource,
	}
	if len(matches) > 0 {
		details["top_match"] = matches[0]
	}
	return details
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

func (g *SpiderSenseGuard) emitMetrics(
	verdict ScreeningVerdict,
	topScore float64,
	severity Severity,
	screened bool,
	skipReason string,
	embeddingSource string,
) {
	if g.metricsHook == nil {
		return
	}

	g.metricsMu.Lock()
	g.totalCount++
	switch verdict {
	case VerdictDeny:
		g.denyCount++
	case VerdictAmbiguous:
		g.warnCount++
	default:
		g.allowCount++
	}
	ambiguityRate := 0.0
	if g.totalCount > 0 {
		ambiguityRate = float64(g.warnCount) / float64(g.totalCount)
	}
	event := SpiderSenseMetrics{
		Verdict:         verdict,
		TopScore:        topScore,
		Severity:        severity.String(),
		DBSource:        g.dbSource,
		DBVersion:       g.dbVersion,
		AllowCount:      g.allowCount,
		AmbiguousCount:  g.warnCount,
		DenyCount:       g.denyCount,
		TotalCount:      g.totalCount,
		AmbiguityRate:   ambiguityRate,
		Screened:        screened,
		SkipReason:      skipReason,
		EmbeddingSource: embeddingSource,
	}
	g.metricsMu.Unlock()

	defer func() {
		_ = recover()
	}()
	g.metricsHook(event)
}

func validateEmbeddingProviderConfig(cfg *policy.SpiderSenseConfig) (bool, spiderSenseProvider, error) {
	if cfg == nil {
		return false, providerOpenAI, nil
	}

	urlValue := strings.TrimSpace(cfg.EmbeddingAPIURL)
	key := strings.TrimSpace(cfg.EmbeddingAPIKey)
	model := strings.TrimSpace(cfg.EmbeddingModel)

	hasURL := urlValue != ""
	hasKey := key != ""
	hasModel := model != ""
	if !hasURL && !hasKey && !hasModel {
		return false, providerOpenAI, nil
	}
	if !hasURL || !hasKey || !hasModel {
		return false, providerOpenAI, fmt.Errorf(
			"spider_sense: embedding_api_url, embedding_api_key, and embedding_model must all be set when any is provided",
		)
	}

	parsed, err := url.Parse(urlValue)
	if err != nil {
		return false, providerOpenAI, fmt.Errorf("spider_sense: invalid embedding_api_url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return false, providerOpenAI, fmt.Errorf("spider_sense: embedding_api_url must be absolute and include host")
	}

	host := strings.ToLower(parsed.Host)
	switch {
	case strings.Contains(host, "cohere"):
		return true, providerCohere, nil
	case strings.Contains(host, "voyage"):
		return true, providerVoyage, nil
	default:
		return true, providerOpenAI, nil
	}
}

func (g *SpiderSenseGuard) fetchEmbedding(text string, guardCtx *GuardContext) ([]float32, error) {
	requestCtx := context.Background()
	if guardCtx != nil && guardCtx.Context != nil {
		requestCtx = guardCtx.Context
	}

	body, err := g.providerRequestBody(text)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, g.embeddingAPIURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build embedding request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+g.embeddingAPIKey)
	if g.embeddingProv == providerCohere {
		req.Header.Set("X-Client-Name", "clawdstrike-go")
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("embedding request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, defaultMaxEmbeddingBytes))
	if err != nil {
		return nil, fmt.Errorf("read embedding response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(respBody))
		if msg == "" {
			msg = "empty response body"
		}
		return nil, fmt.Errorf("embedding API returned HTTP %d: %s", resp.StatusCode, msg)
	}

	embedding, err := g.parseProviderEmbedding(respBody)
	if err != nil {
		return nil, err
	}
	if len(embedding) == 0 {
		return nil, fmt.Errorf("embedding API returned an empty embedding")
	}
	return embedding, nil
}

func (g *SpiderSenseGuard) providerRequestBody(text string) ([]byte, error) {
	switch g.embeddingProv {
	case providerCohere:
		payload := map[string]interface{}{
			"texts":           []string{text},
			"model":           g.embeddingModel,
			"embedding_types": []string{"float"},
			"input_type":      "classification",
		}
		return json.Marshal(payload)
	case providerVoyage:
		payload := map[string]interface{}{
			"input": []string{text},
			"model": g.embeddingModel,
		}
		return json.Marshal(payload)
	default:
		payload := map[string]interface{}{
			"input": text,
			"model": g.embeddingModel,
		}
		return json.Marshal(payload)
	}
}

func (g *SpiderSenseGuard) parseProviderEmbedding(body []byte) ([]float32, error) {
	switch g.embeddingProv {
	case providerCohere:
		return parseCohereEmbedding(body)
	default:
		return parseOpenAICompatibleEmbedding(body)
	}
}

func parseOpenAICompatibleEmbedding(body []byte) ([]float32, error) {
	var payload struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parse embedding response: %w", err)
	}
	if len(payload.Data) == 0 {
		return nil, fmt.Errorf("parse embedding response: missing data[0].embedding")
	}
	return float64sToFloat32(payload.Data[0].Embedding)
}

func parseCohereEmbedding(body []byte) ([]float32, error) {
	var payload struct {
		Embeddings json.RawMessage `json:"embeddings"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parse cohere embedding response: %w", err)
	}
	if len(payload.Embeddings) == 0 {
		return nil, fmt.Errorf("parse cohere embedding response: missing embeddings field")
	}

	var v1 [][]float64
	if err := json.Unmarshal(payload.Embeddings, &v1); err == nil && len(v1) > 0 {
		return float64sToFloat32(v1[0])
	}

	var v2 struct {
		Float [][]float64 `json:"float"`
	}
	if err := json.Unmarshal(payload.Embeddings, &v2); err == nil && len(v2.Float) > 0 {
		return float64sToFloat32(v2.Float[0])
	}

	return nil, fmt.Errorf("parse cohere embedding response: unsupported embeddings format")
}

func float64sToFloat32(values []float64) ([]float32, error) {
	out := make([]float32, len(values))
	for i, v := range values {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, fmt.Errorf("embedding element at index %d is non-finite", i)
		}
		out[i] = float32(v)
	}
	return out, nil
}

// extractEmbedding attempts to extract a []float32 embedding from the
// action's CustomData.
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
			f, ok := coerceToFloat32(v)
			if !ok {
				return nil, false
			}
			result[i] = f
		}
		return result, true
	case []float64:
		result, err := float64sToFloat32(emb)
		if err != nil {
			return nil, false
		}
		return result, true
	case []float32:
		for _, v := range emb {
			if !isFiniteF32(v) {
				return nil, false
			}
		}
		return emb, true
	default:
		return nil, false
	}
}

func coerceToFloat32(value interface{}) (float32, bool) {
	switch v := value.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		return float32(v), true
	case float32:
		if !isFiniteF32(v) {
			return 0, false
		}
		return v, true
	case int:
		return float32(v), true
	case int8:
		return float32(v), true
	case int16:
		return float32(v), true
	case int32:
		return float32(v), true
	case int64:
		return float32(v), true
	case uint:
		return float32(v), true
	case uint8:
		return float32(v), true
	case uint16:
		return float32(v), true
	case uint32:
		return float32(v), true
	case uint64:
		return float32(v), true
	case json.Number:
		f, err := strconv.ParseFloat(v.String(), 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return float32(f), true
	default:
		return 0, false
	}
}

func isFiniteF32(v float32) bool {
	f := float64(v)
	return !math.IsNaN(f) && !math.IsInf(f, 0)
}

func actionToText(action GuardAction) string {
	switch action.Type {
	case "custom":
		label := strings.TrimSpace(action.CustomType)
		if label == "" {
			label = "custom"
		}
		return fmt.Sprintf("[custom:%s] %s", label, jsonString(action.CustomData))
	case "mcp_tool":
		name := strings.TrimSpace(action.ToolName)
		if name == "" {
			name = "tool"
		}
		return fmt.Sprintf("[mcp_tool:%s] %s", name, jsonString(action.ToolArgs))
	case "shell_command":
		return fmt.Sprintf("[shell_command] %s", strings.TrimSpace(action.Command))
	case "file_write":
		preview := truncateTo(string(action.Content), 512)
		return fmt.Sprintf("[file_write:%s] %s", strings.TrimSpace(action.Path), preview)
	case "network_egress":
		return fmt.Sprintf("[network_egress:%s:%d]", strings.TrimSpace(action.Host), action.Port)
	case "file_access":
		return fmt.Sprintf("[file_access] %s", strings.TrimSpace(action.Path))
	case "patch":
		preview := truncateTo(action.Diff, 512)
		return fmt.Sprintf("[patch:%s] %s", strings.TrimSpace(action.Path), preview)
	default:
		return fmt.Sprintf("[action:%s] %s", action.Type, jsonString(map[string]interface{}{
			"path":   action.Path,
			"host":   action.Host,
			"port":   action.Port,
			"tool":   action.ToolName,
			"diff":   action.Diff,
			"custom": action.CustomType,
		}))
	}
}

func truncateTo(value string, max int) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) <= max {
		return trimmed
	}
	return trimmed[:max]
}

func jsonString(value interface{}) string {
	if value == nil {
		return "null"
	}
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(data)
}

func loadPatternDBFromPath(cfg *policy.SpiderSenseConfig) (*PatternDb, string, string, error) {
	trimmed := strings.TrimSpace(cfg.PatternDBPath)
	if trimmed == "" {
		return nil, "", "", fmt.Errorf("spider_sense: pattern_db_path cannot be empty")
	}

	integrity, err := requiredIntegrityFields(cfg)
	if err != nil {
		return nil, "", "", err
	}

	var data []byte
	source := trimmed
	switch trimmed {
	case "builtin:s2bench-v1":
		data, err = spiderSensePatternFS.ReadFile("patterns/s2bench-v1.json")
		if err != nil {
			return nil, "", "", fmt.Errorf("spider_sense: load builtin pattern DB %q: %w", trimmed, err)
		}
		source = "builtin:s2bench-v1"
	default:
		data, err = os.ReadFile(trimmed)
		if err != nil {
			return nil, "", "", fmt.Errorf("spider_sense: read pattern DB %q: %w", trimmed, err)
		}
	}

	if err := verifyPatternDBIntegrity(data, integrity); err != nil {
		return nil, "", "", err
	}

	db, err := ParsePatternDB(data)
	if err != nil {
		return nil, "", "", fmt.Errorf("spider_sense: %w", err)
	}
	return db, source, integrity.Version, nil
}

type patternDBIntegrity struct {
	Version   string
	Checksum  string
	Signature string
	PublicKey string
}

func requiredIntegrityFields(cfg *policy.SpiderSenseConfig) (patternDBIntegrity, error) {
	version := strings.TrimSpace(cfg.PatternDBVersion)
	checksum := strings.TrimSpace(cfg.PatternDBChecksum)
	signature := strings.TrimSpace(cfg.PatternDBSignature)
	publicKey := strings.TrimSpace(cfg.PatternDBPublicKey)
	if version == "" || checksum == "" {
		return patternDBIntegrity{}, fmt.Errorf(
			"spider_sense: pattern_db_version and pattern_db_checksum are required when pattern_db_path is set",
		)
	}
	if (signature == "") != (publicKey == "") {
		return patternDBIntegrity{}, fmt.Errorf(
			"spider_sense: pattern_db_signature and pattern_db_public_key must either both be set or both be omitted",
		)
	}
	return patternDBIntegrity{
		Version:   version,
		Checksum:  checksum,
		Signature: signature,
		PublicKey: publicKey,
	}, nil
}

func verifyPatternDBIntegrity(data []byte, integrity patternDBIntegrity) error {
	sum := sha256.Sum256(data)
	actualChecksum := strings.ToLower(hex.EncodeToString(sum[:]))
	normalizedExpected := strings.TrimPrefix(strings.ToLower(integrity.Checksum), "0x")
	if actualChecksum != normalizedExpected {
		return fmt.Errorf("spider_sense: pattern DB checksum mismatch: expected %s, got %s", normalizedExpected, actualChecksum)
	}

	if integrity.Signature != "" && integrity.PublicKey != "" {
		pk, err := sdkcrypto.PublicKeyFromHex(integrity.PublicKey)
		if err != nil {
			return fmt.Errorf("spider_sense: invalid pattern DB public key: %w", err)
		}
		sig, err := sdkcrypto.SignatureFromHex(integrity.Signature)
		if err != nil {
			return fmt.Errorf("spider_sense: invalid pattern DB signature: %w", err)
		}

		message := []byte(fmt.Sprintf("spider_sense_db:v1:%s:%s", integrity.Version, normalizedExpected))
		if !pk.Verify(message, &sig) {
			return fmt.Errorf("spider_sense: pattern DB signature verification failed")
		}
	}
	return nil
}
