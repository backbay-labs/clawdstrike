package guards

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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
	defaultEmbeddingTimeout    = 15 * time.Second
	defaultMaxEmbeddingBytes   = 2 << 20 // 2 MiB
	defaultAsyncTimeout        = 5 * time.Second
	defaultAsyncCacheTTL       = time.Hour
	defaultAsyncCacheMaxSize   = 64 * 1024 * 1024
	defaultRetryInitialBackoff = 250 * time.Millisecond
	defaultRetryMaxBackoff     = 2 * time.Second
	defaultRetryMultiplier     = 2.0
	defaultRetryAfterCap       = 10 * time.Second
	defaultRateLimitResetGrace = 250 * time.Millisecond
	defaultLLMTimeout          = 1500 * time.Millisecond
	defaultLLMOpenAIModel      = "gpt-4.1-mini"
	defaultLLMAnthropicModel   = "claude-haiku-4-5-20251001"
)

type spiderSenseCircuitOpenAction string

const (
	circuitOpenDeny  spiderSenseCircuitOpenAction = "deny"
	circuitOpenWarn  spiderSenseCircuitOpenAction = "warn"
	circuitOpenAllow spiderSenseCircuitOpenAction = "allow"
)

type spiderSenseDeepPathFailMode string

const (
	deepPathFailWarn  spiderSenseDeepPathFailMode = "warn"
	deepPathFailDeny  spiderSenseDeepPathFailMode = "deny"
	deepPathFailAllow spiderSenseDeepPathFailMode = "allow"
)

type spiderSenseAsyncRuntimeConfig struct {
	timeout         time.Duration
	cacheEnabled    bool
	cacheTTL        time.Duration
	cacheMaxSizeB   int
	retry           spiderSenseRetryConfig
	circuitBreaker  *spiderSenseCircuitBreakerConfig
	onCircuitOpen   spiderSenseCircuitOpenAction
	hasAsyncTimeout bool
}

type spiderSenseRetryConfig struct {
	enabled             bool
	maxRetries          int
	initialBackoff      time.Duration
	maxBackoff          time.Duration
	multiplier          float64
	honorRetryAfter     bool
	retryAfterCap       time.Duration
	honorRateLimitReset bool
	rateLimitResetGrace time.Duration
}

type spiderSenseCircuitBreakerConfig struct {
	failureThreshold int
	resetTimeout     time.Duration
	successThreshold int
}

type spiderSenseCircuitState string

const (
	spiderSenseCircuitClosed   spiderSenseCircuitState = "closed"
	spiderSenseCircuitOpen     spiderSenseCircuitState = "open"
	spiderSenseCircuitHalfOpen spiderSenseCircuitState = "half_open"
)

type spiderSenseCircuitBreaker struct {
	cfg       spiderSenseCircuitBreakerConfig
	mu        sync.Mutex
	state     spiderSenseCircuitState
	failures  int
	successes int
	openedAt  time.Time
	openUntil time.Time
}

type spiderSenseProviderStats struct {
	cacheHit      bool
	attempts      int
	retries       int
	circuitState  string
	latencyMs     int64
	circuitOpened bool
}

type spiderSenseDeepPathStats struct {
	used         bool
	attempts     int
	retries      int
	circuitState string
	latencyMs    int64
	verdict      string
	failMode     string
}

type spiderSenseMetricRuntime struct {
	cacheHit         bool
	providerAttempts int
	retryCount       int
	circuitState     string
	deepPathUsed     bool
	deepPathVerdict  string
	trustKeyID       string
	embeddingLatency int64
	deepPathLatency  int64
}

type spiderSenseProviderCallError struct {
	cause      error
	retryable  bool
	status     int
	retryAfter time.Duration
}

func (e *spiderSenseProviderCallError) Error() string {
	if e == nil || e.cause == nil {
		return "provider call failed"
	}
	return e.cause.Error()
}

func (e *spiderSenseProviderCallError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

type spiderSenseCacheEntry struct {
	key       string
	embedding []float32
	expiresAt time.Time
	sizeBytes int
	element   *list.Element
}

type spiderSenseEmbeddingCache struct {
	enabled      bool
	ttl          time.Duration
	maxSizeBytes int
	mu           sync.Mutex
	currentSize  int
	entries      map[string]*spiderSenseCacheEntry
	lru          *list.List
}

type spiderSenseLLMProvider string

const (
	spiderSenseLLMOpenAI    spiderSenseLLMProvider = "openai"
	spiderSenseLLMAnthropic spiderSenseLLMProvider = "anthropic"
)

type spiderSenseTrustedKeyStatus string

const (
	spiderSenseKeyActive     spiderSenseTrustedKeyStatus = "active"
	spiderSenseKeyDeprecated spiderSenseTrustedKeyStatus = "deprecated"
	spiderSenseKeyRevoked    spiderSenseTrustedKeyStatus = "revoked"
)

type spiderSenseTrustedKey struct {
	KeyID        string
	PublicKey    string
	NotBefore    time.Time
	HasNotBefore bool
	NotAfter     time.Time
	HasNotAfter  bool
	Status       spiderSenseTrustedKeyStatus
}

type spiderSenseTrustStore struct {
	Keys map[string]spiderSenseTrustedKey
}

type spiderSensePatternManifest struct {
	PatternDBPath         string                               `json:"pattern_db_path"`
	PatternDBVersion      string                               `json:"pattern_db_version"`
	PatternDBChecksum     string                               `json:"pattern_db_checksum"`
	PatternDBSignature    string                               `json:"pattern_db_signature"`
	PatternDBPublicKey    string                               `json:"pattern_db_public_key"`
	PatternDBSignatureKey string                               `json:"pattern_db_signature_key_id"`
	PatternDBTrustStore   string                               `json:"pattern_db_trust_store_path"`
	PatternDBTrustedKeys  []policy.SpiderSenseTrustedKeyConfig `json:"pattern_db_trusted_keys"`
	ManifestSignature     string                               `json:"manifest_signature"`
	ManifestSignatureKey  string                               `json:"manifest_signature_key_id"`
	NotBefore             string                               `json:"not_before"`
	NotAfter              string                               `json:"not_after"`
}

type spiderSensePromptTemplate struct {
	id      string
	version string
	render  func(string) string
}

var spiderSensePromptTemplates = map[string]spiderSensePromptTemplate{
	spiderSensePromptTemplateKey("spider_sense.deep_path.json_classifier", "1.0.0"): {
		id:      "spider_sense.deep_path.json_classifier",
		version: "1.0.0",
		render: func(actionText string) string {
			return strings.TrimSpace(fmt.Sprintf(
				"You are a security classifier. Classify the AI-agent action below and return JSON only.\n"+
					"Allowed verdicts: allow, warn, deny.\n"+
					"JSON schema: {\"verdict\":\"allow|warn|deny\",\"reason\":\"...\"}\n\n"+
					"Action:\n%s",
				actionText,
			))
		},
	},
}

func spiderSensePromptTemplateKey(id, version string) string {
	return strings.ToLower(strings.TrimSpace(id)) + "@" + strings.TrimSpace(version)
}

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
	Verdict            ScreeningVerdict `json:"verdict"`
	TopScore           float64          `json:"top_score"`
	Severity           string           `json:"severity"`
	DBSource           string           `json:"db_source"`
	DBVersion          string           `json:"db_version"`
	AllowCount         int              `json:"allow_count"`
	AmbiguousCount     int              `json:"ambiguous_count"`
	DenyCount          int              `json:"deny_count"`
	TotalCount         int              `json:"total_count"`
	AmbiguityRate      float64          `json:"ambiguity_rate"`
	Screened           bool             `json:"screened"`
	SkipReason         string           `json:"skip_reason,omitempty"`
	EmbeddingSource    string           `json:"embedding_source,omitempty"`
	CacheHit           bool             `json:"cache_hit,omitempty"`
	ProviderAttempts   int              `json:"provider_attempts,omitempty"`
	RetryCount         int              `json:"retry_count,omitempty"`
	CircuitState       string           `json:"circuit_state,omitempty"`
	DeepPathUsed       bool             `json:"deep_path_used,omitempty"`
	DeepPathVerdict    string           `json:"deep_path_verdict,omitempty"`
	TrustKeyID         string           `json:"trust_key_id,omitempty"`
	EmbeddingLatencyMs int64            `json:"embedding_latency_ms,omitempty"`
	DeepPathLatencyMs  int64            `json:"deep_path_latency_ms,omitempty"`
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
	asyncCfg         spiderSenseAsyncRuntimeConfig
	embeddingCache   *spiderSenseEmbeddingCache
	embeddingBreaker *spiderSenseCircuitBreaker
	llmBreaker       *spiderSenseCircuitBreaker
	trustKeyID       string

	llmEnabled        bool
	llmAPIURL         string
	llmAPIKey         string
	llmModel          string
	llmProvider       spiderSenseLLMProvider
	llmTimeout        time.Duration
	llmFailMode       spiderSenseDeepPathFailMode
	llmPromptTemplate spiderSensePromptTemplate

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
	asyncCfg, err := parseSpiderSenseAsyncRuntimeConfig(cfg)
	if err != nil {
		return nil, err
	}

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
	trustKeyID := ""
	if cfg != nil && db == nil {
		hasInlinePatterns := cfg.Patterns != nil
		hasPatternPath := strings.TrimSpace(cfg.PatternDBPath) != "" || strings.TrimSpace(cfg.PatternDBManifestPath) != ""

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
			db, dbSource, dbVersion, trustKeyID, err = loadPatternDBFromPath(cfg)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf(
				"spider_sense: patterns, pattern_db_path, or pattern_db_manifest_path must be set when spider_sense guard is enabled",
			)
		}
	}

	embeddingEnabled, provider, err := validateEmbeddingProviderConfig(cfg)
	if err != nil {
		return nil, err
	}

	llmEnabled, llmCfg, err := validateDeepPathConfig(cfg, asyncCfg)
	if err != nil {
		return nil, err
	}

	client := opts.HTTPClient
	if client == nil {
		timeout := defaultEmbeddingTimeout
		if asyncCfg.hasAsyncTimeout {
			timeout = asyncCfg.timeout
		}
		client = &http.Client{Timeout: timeout}
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
		patternDb:         db,
		upperBound:        upperBound,
		lowerBound:        lowerBound,
		topK:              topK,
		threshold:         threshold,
		ambiguityBand:     ambiguityBand,
		dbSource:          dbSource,
		dbVersion:         dbVersion,
		embeddingEnabled:  embeddingEnabled,
		embeddingProv:     provider,
		httpClient:        client,
		asyncCfg:          asyncCfg,
		embeddingCache:    newSpiderSenseEmbeddingCache(asyncCfg.cacheEnabled, asyncCfg.cacheTTL, asyncCfg.cacheMaxSizeB),
		embeddingBreaker:  newSpiderSenseCircuitBreaker(asyncCfg.circuitBreaker),
		llmBreaker:        newSpiderSenseCircuitBreaker(asyncCfg.circuitBreaker),
		trustKeyID:        trustKeyID,
		llmEnabled:        llmEnabled,
		llmAPIURL:         llmCfg.apiURL,
		llmAPIKey:         llmCfg.apiKey,
		llmModel:          llmCfg.model,
		llmProvider:       llmCfg.provider,
		llmTimeout:        llmCfg.timeout,
		llmFailMode:       llmCfg.failMode,
		llmPromptTemplate: llmCfg.template,
		metricsHook:       opts.MetricsHook,
		embeddingAPIURL:   strings.TrimSpace(cfgOrEmpty(cfg, func(c *policy.SpiderSenseConfig) string { return c.EmbeddingAPIURL })),
		embeddingAPIKey:   strings.TrimSpace(cfgOrEmpty(cfg, func(c *policy.SpiderSenseConfig) string { return c.EmbeddingAPIKey })),
		embeddingModel:    strings.TrimSpace(cfgOrEmpty(cfg, func(c *policy.SpiderSenseConfig) string { return c.EmbeddingModel })),
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
	runtime := spiderSenseMetricRuntime{trustKeyID: g.trustKeyID}

	if g.patternDb == nil {
		result := Allow(g.Name())
		g.emitMetrics(VerdictAllow, 0, result.Severity, false, "pattern_db_missing", "", runtime)
		return result
	}

	embedding, ok := extractEmbedding(action)
	embeddingSource := "action"
	if !ok {
		if !g.embeddingEnabled {
			result := Allow(g.Name())
			g.emitMetrics(VerdictAllow, 0, result.Severity, false, "embedding_missing", "", runtime)
			return result
		}

		text := actionToText(action)
		cacheKey := spiderSenseEmbeddingCacheKey(g.embeddingAPIURL, g.embeddingModel, text)
		if cached, ok := g.embeddingCache.Get(cacheKey); ok {
			embedding = cached
			embeddingSource = "provider"
			runtime.cacheHit = true
			runtime.circuitState = string(g.circuitState(g.embeddingBreaker))
		} else {
			fetched, stats, err := g.fetchEmbedding(text, ctx)
			runtime.providerAttempts = stats.attempts
			runtime.retryCount = stats.retries
			runtime.circuitState = stats.circuitState
			runtime.embeddingLatency = stats.latencyMs
			if err != nil {
				if stats.circuitOpened {
					result := g.circuitOpenProviderResult(err)
					skipReason := "provider_circuit_open"
					verdict := verdictFromGuardResult(result)
					g.emitMetrics(verdict, 0, result.Severity, false, skipReason, "provider", runtime)
					return result
				}
				details := map[string]interface{}{
					"analysis":       "provider",
					"error":          err.Error(),
					"db_source":      g.dbSource,
					"db_version":     g.dbVersion,
					"embedding_from": "provider",
				}
				result := Block(g.Name(), Error, "Spider-Sense embedding provider error (fail-closed)").WithDetails(details)
				g.emitMetrics(VerdictDeny, 0, result.Severity, false, "provider_error", "provider", runtime)
				return result
			}
			embedding = fetched
			embeddingSource = "provider"
			g.embeddingCache.Set(cacheKey, embedding)
		}
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
		g.emitMetrics(VerdictDeny, 0, result.Severity, true, "dimension_mismatch", embeddingSource, runtime)
		return result
	}

	result := g.Screen(embedding)
	details := g.resultDetails(result, embeddingSource)
	if result.Verdict == VerdictAmbiguous && g.llmEnabled {
		text := actionToText(action)
		deepResult, deepStats, err := g.deepPathResult(text, result, embeddingSource, ctx)
		runtime.deepPathUsed = deepStats.used
		runtime.deepPathVerdict = deepStats.verdict
		runtime.deepPathLatency = deepStats.latencyMs
		runtime.retryCount += deepStats.retries
		if runtime.circuitState == "" {
			runtime.circuitState = deepStats.circuitState
		}
		if err != nil {
			failResult := g.deepPathFailureResult(err, result, embeddingSource, details)
			verdict := verdictFromGuardResult(failResult)
			g.emitMetrics(
				verdict,
				result.TopScore,
				failResult.Severity,
				true,
				"deep_path_error",
				embeddingSource,
				runtime,
			)
			return failResult
		}
		verdict := verdictFromGuardResult(deepResult)
		g.emitMetrics(
			verdict,
			result.TopScore,
			deepResult.Severity,
			true,
			"",
			embeddingSource,
			runtime,
		)
		return deepResult
	}

	switch result.Verdict {
	case VerdictDeny:
		topLabel := ""
		if len(result.TopMatches) > 0 {
			topLabel = result.TopMatches[0].Entry.Label
		}
		guardResult := Block(g.Name(), Error,
			fmt.Sprintf("Spider-Sense threat detected (score=%.3f, label=%q)", result.TopScore, topLabel)).
			WithDetails(details)
		g.emitMetrics(result.Verdict, result.TopScore, guardResult.Severity, true, "", embeddingSource, runtime)
		return guardResult
	case VerdictAmbiguous:
		guardResult := Warn(g.Name(),
			fmt.Sprintf("Spider-Sense ambiguous match detected (score=%.3f)", result.TopScore)).
			WithDetails(details)
		g.emitMetrics(result.Verdict, result.TopScore, guardResult.Severity, true, "", embeddingSource, runtime)
		return guardResult
	default:
		guardResult := Allow(g.Name()).WithDetails(details)
		g.emitMetrics(result.Verdict, result.TopScore, guardResult.Severity, true, "", embeddingSource, runtime)
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
	runtime spiderSenseMetricRuntime,
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
		Verdict:            verdict,
		TopScore:           topScore,
		Severity:           severity.String(),
		DBSource:           g.dbSource,
		DBVersion:          g.dbVersion,
		AllowCount:         g.allowCount,
		AmbiguousCount:     g.warnCount,
		DenyCount:          g.denyCount,
		TotalCount:         g.totalCount,
		AmbiguityRate:      ambiguityRate,
		Screened:           screened,
		SkipReason:         skipReason,
		EmbeddingSource:    embeddingSource,
		CacheHit:           runtime.cacheHit,
		ProviderAttempts:   runtime.providerAttempts,
		RetryCount:         runtime.retryCount,
		CircuitState:       runtime.circuitState,
		DeepPathUsed:       runtime.deepPathUsed,
		DeepPathVerdict:    runtime.deepPathVerdict,
		TrustKeyID:         runtime.trustKeyID,
		EmbeddingLatencyMs: runtime.embeddingLatency,
		DeepPathLatencyMs:  runtime.deepPathLatency,
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

func (g *SpiderSenseGuard) fetchEmbedding(text string, guardCtx *GuardContext) ([]float32, spiderSenseProviderStats, error) {
	stats := spiderSenseProviderStats{
		circuitState: string(g.circuitState(g.embeddingBreaker)),
	}

	allow, state := g.circuitAllow(g.embeddingBreaker)
	stats.circuitState = string(state)
	if !allow {
		stats.circuitOpened = true
		return nil, stats, fmt.Errorf("embedding provider circuit breaker open")
	}

	maxRetries := 0
	if g.asyncCfg.retry.enabled {
		maxRetries = g.asyncCfg.retry.maxRetries
	}
	backoff := g.asyncCfg.retry.initialBackoff
	start := time.Now()
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		stats.attempts = attempt + 1
		embedding, err := g.fetchEmbeddingOnce(text, guardCtx)
		if err == nil {
			g.circuitRecordSuccess(g.embeddingBreaker)
			stats.retries = attempt
			stats.latencyMs = time.Since(start).Milliseconds()
			stats.circuitState = string(g.circuitState(g.embeddingBreaker))
			return embedding, stats, nil
		}

		lastErr = err
		providerErr := &spiderSenseProviderCallError{}
		retryable := errors.As(err, &providerErr) && providerErr.retryable
		if attempt >= maxRetries || !retryable {
			g.circuitRecordFailure(g.embeddingBreaker)
			stats.retries = attempt
			stats.latencyMs = time.Since(start).Milliseconds()
			stats.circuitState = string(g.circuitState(g.embeddingBreaker))
			return nil, stats, lastErr
		}

		wait := resolveProviderRetryDelay(backoff, providerErr, g.asyncCfg.retry)
		if err := sleepWithGuardContext(guardCtx, wait); err != nil {
			g.circuitRecordFailure(g.embeddingBreaker)
			stats.retries = attempt
			stats.latencyMs = time.Since(start).Milliseconds()
			stats.circuitState = string(g.circuitState(g.embeddingBreaker))
			return nil, stats, fmt.Errorf("embedding retry interrupted: %w", err)
		}
		backoff = nextBackoff(wait, g.asyncCfg.retry)
	}

	g.circuitRecordFailure(g.embeddingBreaker)
	stats.retries = maxRetries
	stats.latencyMs = time.Since(start).Milliseconds()
	stats.circuitState = string(g.circuitState(g.embeddingBreaker))
	if lastErr == nil {
		lastErr = fmt.Errorf("embedding request failed")
	}
	return nil, stats, lastErr
}

func (g *SpiderSenseGuard) fetchEmbeddingOnce(text string, guardCtx *GuardContext) ([]float32, error) {
	requestCtx := context.Background()
	if guardCtx != nil && guardCtx.Context != nil {
		requestCtx = guardCtx.Context
	}
	requestCtx, cancel := context.WithTimeout(requestCtx, g.requestTimeout())
	defer cancel()

	body, err := g.providerRequestBody(text)
	if err != nil {
		return nil, &spiderSenseProviderCallError{
			cause:     fmt.Errorf("build embedding payload: %w", err),
			retryable: false,
		}
	}

	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, g.embeddingAPIURL, bytes.NewReader(body))
	if err != nil {
		return nil, &spiderSenseProviderCallError{
			cause:     fmt.Errorf("build embedding request: %w", err),
			retryable: false,
		}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+g.embeddingAPIKey)
	if g.embeddingProv == providerCohere {
		req.Header.Set("X-Client-Name", "clawdstrike-go")
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, &spiderSenseProviderCallError{
			cause:     fmt.Errorf("embedding request failed: %w", err),
			retryable: isRetryableTransportError(err) || errors.Is(err, context.DeadlineExceeded),
		}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, defaultMaxEmbeddingBytes))
	if err != nil {
		return nil, &spiderSenseProviderCallError{
			cause:     fmt.Errorf("read embedding response: %w", err),
			retryable: true,
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(respBody))
		if msg == "" {
			msg = "empty response body"
		}
		retryAfter := parseRateLimitRetryDelay(resp.Header, time.Now(), g.asyncCfg.retry)
		return nil, &spiderSenseProviderCallError{
			cause:      fmt.Errorf("embedding API returned HTTP %d: %s", resp.StatusCode, msg),
			retryable:  isRetryableHTTPStatus(resp.StatusCode),
			status:     resp.StatusCode,
			retryAfter: retryAfter,
		}
	}

	embedding, err := g.parseProviderEmbedding(respBody)
	if err != nil {
		return nil, &spiderSenseProviderCallError{
			cause:     err,
			retryable: false,
		}
	}
	if len(embedding) == 0 {
		return nil, &spiderSenseProviderCallError{
			cause:     fmt.Errorf("embedding API returned an empty embedding"),
			retryable: false,
		}
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

type spiderSenseLLMVerdict struct {
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
}

func (g *SpiderSenseGuard) deepPathResult(
	text string,
	fast ScreeningResult,
	embeddingSource string,
	guardCtx *GuardContext,
) (GuardResult, spiderSenseDeepPathStats, error) {
	stats := spiderSenseDeepPathStats{
		used:         true,
		circuitState: string(g.circuitState(g.llmBreaker)),
	}

	allow, state := g.circuitAllow(g.llmBreaker)
	stats.circuitState = string(state)
	if !allow {
		return GuardResult{}, stats, fmt.Errorf("deep path circuit breaker open")
	}

	maxRetries := 0
	if g.asyncCfg.retry.enabled {
		maxRetries = g.asyncCfg.retry.maxRetries
	}
	backoff := g.asyncCfg.retry.initialBackoff
	start := time.Now()
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		stats.attempts = attempt + 1
		verdict, err := g.deepPathVerdictOnce(text, guardCtx)
		if err == nil {
			g.circuitRecordSuccess(g.llmBreaker)
			stats.retries = attempt
			stats.latencyMs = time.Since(start).Milliseconds()
			stats.circuitState = string(g.circuitState(g.llmBreaker))
			stats.verdict = verdict.Verdict
			return g.deepPathDecision(verdict, fast, embeddingSource), stats, nil
		}

		lastErr = err
		providerErr := &spiderSenseProviderCallError{}
		retryable := errors.As(err, &providerErr) && providerErr.retryable
		if attempt >= maxRetries || !retryable {
			g.circuitRecordFailure(g.llmBreaker)
			stats.retries = attempt
			stats.latencyMs = time.Since(start).Milliseconds()
			stats.circuitState = string(g.circuitState(g.llmBreaker))
			return GuardResult{}, stats, lastErr
		}

		wait := resolveProviderRetryDelay(backoff, providerErr, g.asyncCfg.retry)
		if err := sleepWithGuardContext(guardCtx, wait); err != nil {
			g.circuitRecordFailure(g.llmBreaker)
			stats.retries = attempt
			stats.latencyMs = time.Since(start).Milliseconds()
			stats.circuitState = string(g.circuitState(g.llmBreaker))
			return GuardResult{}, stats, fmt.Errorf("deep-path retry interrupted: %w", err)
		}
		backoff = nextBackoff(wait, g.asyncCfg.retry)
	}

	g.circuitRecordFailure(g.llmBreaker)
	stats.retries = maxRetries
	stats.latencyMs = time.Since(start).Milliseconds()
	stats.circuitState = string(g.circuitState(g.llmBreaker))
	if lastErr == nil {
		lastErr = fmt.Errorf("deep-path request failed")
	}
	return GuardResult{}, stats, lastErr
}

func (g *SpiderSenseGuard) deepPathVerdictOnce(text string, guardCtx *GuardContext) (spiderSenseLLMVerdict, error) {
	requestCtx := context.Background()
	if guardCtx != nil && guardCtx.Context != nil {
		requestCtx = guardCtx.Context
	}
	requestCtx, cancel := context.WithTimeout(requestCtx, g.llmTimeout)
	defer cancel()

	prompt := g.deepPathPrompt(text)
	body, headers, err := g.deepPathRequestMaterial(prompt)
	if err != nil {
		return spiderSenseLLMVerdict{}, &spiderSenseProviderCallError{
			cause:     err,
			retryable: false,
		}
	}

	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, g.llmAPIURL, bytes.NewReader(body))
	if err != nil {
		return spiderSenseLLMVerdict{}, &spiderSenseProviderCallError{
			cause:     fmt.Errorf("build deep-path request: %w", err),
			retryable: false,
		}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return spiderSenseLLMVerdict{}, &spiderSenseProviderCallError{
			cause:     fmt.Errorf("deep-path request failed: %w", err),
			retryable: isRetryableTransportError(err) || errors.Is(err, context.DeadlineExceeded),
		}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, defaultMaxEmbeddingBytes))
	if err != nil {
		return spiderSenseLLMVerdict{}, &spiderSenseProviderCallError{
			cause:     fmt.Errorf("read deep-path response: %w", err),
			retryable: true,
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(raw))
		if msg == "" {
			msg = "empty response body"
		}
		retryAfter := parseRateLimitRetryDelay(resp.Header, time.Now(), g.asyncCfg.retry)
		return spiderSenseLLMVerdict{}, &spiderSenseProviderCallError{
			cause:      fmt.Errorf("deep-path API returned HTTP %d: %s", resp.StatusCode, msg),
			retryable:  isRetryableHTTPStatus(resp.StatusCode),
			status:     resp.StatusCode,
			retryAfter: retryAfter,
		}
	}

	content, err := g.deepPathContent(raw)
	if err != nil {
		return spiderSenseLLMVerdict{}, &spiderSenseProviderCallError{
			cause:     err,
			retryable: false,
		}
	}

	verdict, err := parseSpiderSenseLLMVerdict(content)
	if err != nil {
		return spiderSenseLLMVerdict{}, &spiderSenseProviderCallError{
			cause:     err,
			retryable: false,
		}
	}
	return verdict, nil
}

func (g *SpiderSenseGuard) deepPathDecision(
	verdict spiderSenseLLMVerdict,
	fast ScreeningResult,
	embeddingSource string,
) GuardResult {
	topMatches := spiderSenseMatchesForDetails(fast.TopMatches)
	reason := strings.TrimSpace(verdict.Reason)
	if reason == "" {
		reason = "no reason provided"
	}
	details := map[string]interface{}{
		"analysis":         "deep_path",
		"verdict":          verdict.Verdict,
		"reason":           reason,
		"template_id":      g.llmPromptTemplate.id,
		"template_version": g.llmPromptTemplate.version,
		"top_score":        fast.TopScore,
		"threshold":        fast.Threshold,
		"ambiguity_band":   fast.AmbiguityBand,
		"top_matches":      topMatches,
		"db_source":        g.dbSource,
		"db_version":       g.dbVersion,
		"embedding_from":   embeddingSource,
	}
	if len(topMatches) > 0 {
		details["top_match"] = topMatches[0]
	}

	switch strings.ToLower(strings.TrimSpace(verdict.Verdict)) {
	case "deny":
		return Block(g.Name(), Error,
			fmt.Sprintf("Spider-Sense deep analysis: threat confirmed - %s", reason)).
			WithDetails(details)
	case "allow":
		return Allow(g.Name()).WithDetails(details)
	default:
		details["verdict"] = "warn"
		return Warn(g.Name(),
			fmt.Sprintf("Spider-Sense deep analysis: suspicious/ambiguous - %s", reason)).
			WithDetails(details)
	}
}

func (g *SpiderSenseGuard) deepPathFailureResult(
	err error,
	fast ScreeningResult,
	embeddingSource string,
	baseDetails map[string]interface{},
) GuardResult {
	topMatches := baseDetails["top_matches"]
	details := map[string]interface{}{
		"analysis":         "deep_path_error",
		"error":            err.Error(),
		"fail_mode":        string(g.llmFailMode),
		"template_id":      g.llmPromptTemplate.id,
		"template_version": g.llmPromptTemplate.version,
		"top_score":        fast.TopScore,
		"threshold":        fast.Threshold,
		"ambiguity_band":   fast.AmbiguityBand,
		"top_matches":      topMatches,
		"db_source":        g.dbSource,
		"db_version":       g.dbVersion,
		"embedding_from":   embeddingSource,
	}
	if topMatch, ok := baseDetails["top_match"]; ok {
		details["top_match"] = topMatch
	}

	switch g.llmFailMode {
	case deepPathFailAllow:
		return Allow(g.Name()).WithDetails(details)
	case deepPathFailDeny:
		return Block(g.Name(), Error, "Spider-Sense deep-path error (fail-closed)").WithDetails(details)
	default:
		return Warn(g.Name(), "Spider-Sense deep-path error; treating as ambiguous").WithDetails(details)
	}
}

func (g *SpiderSenseGuard) circuitOpenProviderResult(err error) GuardResult {
	details := map[string]interface{}{
		"analysis":       "provider",
		"error":          err.Error(),
		"on_open":        string(g.asyncCfg.onCircuitOpen),
		"db_source":      g.dbSource,
		"db_version":     g.dbVersion,
		"embedding_from": "provider",
	}
	switch g.asyncCfg.onCircuitOpen {
	case circuitOpenAllow:
		return Allow(g.Name()).WithDetails(details)
	case circuitOpenWarn:
		return Warn(g.Name(), "Spider-Sense provider circuit breaker open").WithDetails(details)
	default:
		return Block(g.Name(), Error, "Spider-Sense embedding provider circuit breaker open").WithDetails(details)
	}
}

func (g *SpiderSenseGuard) deepPathPrompt(text string) string {
	if g.llmPromptTemplate.render != nil {
		return g.llmPromptTemplate.render(text)
	}
	return spiderSensePromptTemplates[spiderSensePromptTemplateKey("spider_sense.deep_path.json_classifier", "1.0.0")].render(text)
}

func (g *SpiderSenseGuard) deepPathRequestMaterial(prompt string) ([]byte, map[string]string, error) {
	switch g.llmProvider {
	case spiderSenseLLMAnthropic:
		payload := map[string]interface{}{
			"model":      g.llmModel,
			"max_tokens": 256,
			"messages": []map[string]string{
				{
					"role":    "user",
					"content": prompt,
				},
			},
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, fmt.Errorf("build anthropic payload: %w", err)
		}
		return body, map[string]string{
			"x-api-key":         g.llmAPIKey,
			"anthropic-version": "2023-06-01",
		}, nil
	default:
		payload := map[string]interface{}{
			"model":      g.llmModel,
			"max_tokens": 256,
			"response_format": map[string]string{
				"type": "json_object",
			},
			"messages": []map[string]string{
				{
					"role":    "system",
					"content": "Return JSON only.",
				},
				{
					"role":    "user",
					"content": prompt,
				},
			},
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, fmt.Errorf("build openai payload: %w", err)
		}
		return body, map[string]string{
			"Authorization": "Bearer " + g.llmAPIKey,
		}, nil
	}
}

func (g *SpiderSenseGuard) deepPathContent(raw []byte) (string, error) {
	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("parse deep-path response: %w", err)
	}

	switch g.llmProvider {
	case spiderSenseLLMAnthropic:
		content, ok := payload["content"].([]interface{})
		if !ok || len(content) == 0 {
			return "", fmt.Errorf("parse deep-path response: missing content[0].text")
		}
		item, ok := content[0].(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("parse deep-path response: invalid content[0]")
		}
		text, ok := item["text"].(string)
		if !ok {
			return "", fmt.Errorf("parse deep-path response: missing content[0].text")
		}
		return text, nil
	default:
		choices, ok := payload["choices"].([]interface{})
		if !ok || len(choices) == 0 {
			return "", fmt.Errorf("parse deep-path response: missing choices[0].message.content")
		}
		choice, ok := choices[0].(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("parse deep-path response: invalid choices[0]")
		}
		message, ok := choice["message"].(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("parse deep-path response: missing choices[0].message")
		}
		text, ok := message["content"].(string)
		if !ok {
			return "", fmt.Errorf("parse deep-path response: missing choices[0].message.content")
		}
		return text, nil
	}
}

func parseSpiderSenseLLMVerdict(content string) (spiderSenseLLMVerdict, error) {
	raw := strings.TrimSpace(content)
	if raw == "" {
		return spiderSenseLLMVerdict{}, fmt.Errorf("parse deep-path verdict: empty response")
	}

	var verdict spiderSenseLLMVerdict
	if err := json.Unmarshal([]byte(raw), &verdict); err != nil {
		extracted := extractJSONObject(raw)
		if extracted == "" {
			return spiderSenseLLMVerdict{}, fmt.Errorf("parse deep-path verdict: %w", err)
		}
		if err := json.Unmarshal([]byte(extracted), &verdict); err != nil {
			return spiderSenseLLMVerdict{}, fmt.Errorf("parse deep-path verdict: %w", err)
		}
	}

	verdict.Verdict = strings.ToLower(strings.TrimSpace(verdict.Verdict))
	switch verdict.Verdict {
	case "allow", "warn", "deny":
	default:
		if verdict.Verdict == "" {
			verdict.Verdict = "warn"
		} else {
			verdict.Reason = strings.TrimSpace(verdict.Reason + "; unknown verdict " + verdict.Verdict)
			verdict.Verdict = "warn"
		}
	}
	return verdict, nil
}

func extractJSONObject(raw string) string {
	start := strings.Index(raw, "{")
	if start < 0 {
		return ""
	}
	depth := 0
	for i := start; i < len(raw); i++ {
		switch raw[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return raw[start : i+1]
			}
		}
	}
	return ""
}

func spiderSenseMatchesForDetails(matches []PatternMatch) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(matches))
	for _, m := range matches {
		out = append(out, map[string]interface{}{
			"id":       m.Entry.ID,
			"category": m.Entry.Category,
			"stage":    m.Entry.Stage,
			"label":    m.Entry.Label,
			"score":    m.Score,
		})
	}
	return out
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
	if max <= 0 {
		return ""
	}
	if len(trimmed) <= max {
		return trimmed
	}
	end := max
	for end > 0 && !utf8.RuneStart(trimmed[end]) {
		end--
	}
	return trimmed[:end]
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

type spiderSenseDeepPathConfig struct {
	apiURL   string
	apiKey   string
	model    string
	provider spiderSenseLLMProvider
	timeout  time.Duration
	failMode spiderSenseDeepPathFailMode
	template spiderSensePromptTemplate
}

func parseSpiderSenseAsyncRuntimeConfig(cfg *policy.SpiderSenseConfig) (spiderSenseAsyncRuntimeConfig, error) {
	out := spiderSenseAsyncRuntimeConfig{
		timeout:       defaultEmbeddingTimeout,
		cacheEnabled:  true,
		cacheTTL:      defaultAsyncCacheTTL,
		cacheMaxSizeB: defaultAsyncCacheMaxSize,
		retry: spiderSenseRetryConfig{
			enabled:             false,
			maxRetries:          0,
			initialBackoff:      defaultRetryInitialBackoff,
			maxBackoff:          defaultRetryMaxBackoff,
			multiplier:          defaultRetryMultiplier,
			honorRetryAfter:     true,
			retryAfterCap:       defaultRetryAfterCap,
			honorRateLimitReset: true,
			rateLimitResetGrace: defaultRateLimitResetGrace,
		},
		circuitBreaker: nil,
		onCircuitOpen:  circuitOpenDeny,
	}

	if cfg == nil || cfg.Async == nil {
		return out, nil
	}

	asyncMap := map[string]interface{}(cfg.Async)
	if timeoutMs, ok := intFromUnknown(asyncMap["timeout_ms"]); ok && timeoutMs > 0 {
		out.timeout = time.Duration(timeoutMs) * time.Millisecond
		out.hasAsyncTimeout = true
	}

	if cacheMap, ok := asMap(asyncMap["cache"]); ok {
		if enabled, ok := boolFromUnknown(cacheMap["enabled"]); ok {
			out.cacheEnabled = enabled
		}
		if ttlSec, ok := intFromUnknown(cacheMap["ttl_seconds"]); ok && ttlSec > 0 {
			out.cacheTTL = time.Duration(ttlSec) * time.Second
		}
		if maxMB, ok := intFromUnknown(cacheMap["max_size_mb"]); ok && maxMB > 0 {
			maxInt := int(^uint(0) >> 1)
			if maxMB > maxInt/(1024*1024) {
				maxMB = maxInt / (1024 * 1024)
			}
			out.cacheMaxSizeB = maxMB * 1024 * 1024
		}
	}

	if retryMap, ok := asMap(asyncMap["retry"]); ok {
		out.retry.enabled = true
		out.retry.maxRetries = 2
		if retries, ok := intFromUnknown(retryMap["max_retries"]); ok && retries >= 0 {
			out.retry.maxRetries = retries
		}
		if initial, ok := intFromUnknown(retryMap["initial_backoff_ms"]); ok && initial > 0 {
			out.retry.initialBackoff = time.Duration(initial) * time.Millisecond
		}
		if maxBackoff, ok := intFromUnknown(retryMap["max_backoff_ms"]); ok && maxBackoff > 0 {
			out.retry.maxBackoff = time.Duration(maxBackoff) * time.Millisecond
		}
		if mult, ok := floatFromUnknown(retryMap["multiplier"]); ok && mult >= 1.0 {
			out.retry.multiplier = mult
		}
		if honorRetryAfter, ok := boolFromUnknown(retryMap["honor_retry_after"]); ok {
			out.retry.honorRetryAfter = honorRetryAfter
		}
		if capMs, ok := intFromUnknown(retryMap["retry_after_cap_ms"]); ok && capMs > 0 {
			out.retry.retryAfterCap = time.Duration(capMs) * time.Millisecond
		}
		if honorReset, ok := boolFromUnknown(retryMap["honor_rate_limit_reset"]); ok {
			out.retry.honorRateLimitReset = honorReset
		}
		if graceMs, ok := intFromUnknown(retryMap["rate_limit_reset_grace_ms"]); ok && graceMs >= 0 {
			out.retry.rateLimitResetGrace = time.Duration(graceMs) * time.Millisecond
		}
		if out.retry.maxBackoff < out.retry.initialBackoff {
			out.retry.maxBackoff = out.retry.initialBackoff
		}
		if out.retry.retryAfterCap <= 0 {
			out.retry.retryAfterCap = out.retry.maxBackoff
		}
	}

	if cbMap, ok := asMap(asyncMap["circuit_breaker"]); ok {
		cfg := &spiderSenseCircuitBreakerConfig{
			failureThreshold: 5,
			resetTimeout:     30 * time.Second,
			successThreshold: 2,
		}
		if threshold, ok := intFromUnknown(cbMap["failure_threshold"]); ok && threshold > 0 {
			cfg.failureThreshold = threshold
		}
		if timeoutMs, ok := intFromUnknown(cbMap["reset_timeout_ms"]); ok && timeoutMs > 0 {
			cfg.resetTimeout = time.Duration(timeoutMs) * time.Millisecond
		}
		if success, ok := intFromUnknown(cbMap["success_threshold"]); ok && success > 0 {
			cfg.successThreshold = success
		}
		if mode, ok := stringFromUnknown(cbMap["on_open"]); ok {
			switch strings.ToLower(strings.TrimSpace(mode)) {
			case "allow":
				out.onCircuitOpen = circuitOpenAllow
			case "warn":
				out.onCircuitOpen = circuitOpenWarn
			case "deny", "":
				out.onCircuitOpen = circuitOpenDeny
			default:
				return out, fmt.Errorf("spider_sense: async.circuit_breaker.on_open must be one of allow|warn|deny")
			}
		}
		out.circuitBreaker = cfg
	}

	return out, nil
}

func validateDeepPathConfig(
	cfg *policy.SpiderSenseConfig,
	asyncCfg spiderSenseAsyncRuntimeConfig,
) (bool, spiderSenseDeepPathConfig, error) {
	out := spiderSenseDeepPathConfig{
		timeout:  defaultLLMTimeout,
		failMode: deepPathFailWarn,
		template: spiderSensePromptTemplate{},
	}
	if asyncCfg.hasAsyncTimeout {
		out.timeout = asyncCfg.timeout
	}
	if cfg == nil {
		return false, out, nil
	}

	urlValue := strings.TrimSpace(cfg.LlmAPIURL)
	key := strings.TrimSpace(cfg.LlmAPIKey)
	model := strings.TrimSpace(cfg.LlmModel)
	templateID := strings.TrimSpace(cfg.LlmPromptTemplateID)
	templateVersion := strings.TrimSpace(cfg.LlmPromptTemplateVersion)
	hasURL := urlValue != ""
	hasKey := key != ""
	hasModel := model != ""
	hasTemplateID := templateID != ""
	hasTemplateVersion := templateVersion != ""
	if hasTemplateID != hasTemplateVersion {
		return false, out, fmt.Errorf(
			"spider_sense: llm_prompt_template_id and llm_prompt_template_version must be set together",
		)
	}
	if !hasURL && !hasKey && !hasModel {
		if hasTemplateID || hasTemplateVersion {
			return false, out, fmt.Errorf(
				"spider_sense: llm_prompt_template_id/version require llm_api_url and llm_api_key",
			)
		}
		return false, out, nil
	}
	if !hasURL || !hasKey {
		return false, out, fmt.Errorf(
			"spider_sense: llm_api_url and llm_api_key must both be set when deep path is configured",
		)
	}
	if !hasTemplateID || !hasTemplateVersion {
		return false, out, fmt.Errorf(
			"spider_sense: llm_prompt_template_id and llm_prompt_template_version are required when deep path is configured",
		)
	}
	template, ok := spiderSensePromptTemplates[spiderSensePromptTemplateKey(templateID, templateVersion)]
	if !ok {
		return false, out, fmt.Errorf(
			"spider_sense: unsupported llm prompt template %q version %q",
			templateID,
			templateVersion,
		)
	}
	parsed, err := url.Parse(urlValue)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false, out, fmt.Errorf("spider_sense: llm_api_url must be absolute and include host")
	}

	out.apiURL = urlValue
	out.apiKey = key
	out.template = template
	out.provider = parseLLMProvider(urlValue)
	if hasModel {
		out.model = model
	} else if out.provider == spiderSenseLLMAnthropic {
		out.model = defaultLLMAnthropicModel
	} else {
		out.model = defaultLLMOpenAIModel
	}

	if cfg.LlmTimeoutMs != nil && *cfg.LlmTimeoutMs > 0 {
		out.timeout = time.Duration(*cfg.LlmTimeoutMs) * time.Millisecond
	}
	switch strings.ToLower(strings.TrimSpace(cfg.LlmFailMode)) {
	case "", "warn":
		out.failMode = deepPathFailWarn
	case "deny":
		out.failMode = deepPathFailDeny
	case "allow":
		out.failMode = deepPathFailAllow
	default:
		return false, out, fmt.Errorf("spider_sense: llm_fail_mode must be one of allow|warn|deny")
	}

	return true, out, nil
}

func parseLLMProvider(urlValue string) spiderSenseLLMProvider {
	parsed, err := url.Parse(urlValue)
	if err != nil {
		return spiderSenseLLMOpenAI
	}
	host := strings.ToLower(parsed.Host)
	if strings.Contains(host, "anthropic") {
		return spiderSenseLLMAnthropic
	}
	return spiderSenseLLMOpenAI
}

func asMap(value interface{}) (map[string]interface{}, bool) {
	switch typed := value.(type) {
	case map[string]interface{}:
		return typed, true
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(typed))
		for k, v := range typed {
			out[fmt.Sprint(k)] = v
		}
		return out, true
	default:
		return nil, false
	}
}

func boolFromUnknown(value interface{}) (bool, bool) {
	v, ok := value.(bool)
	return v, ok
}

func stringFromUnknown(value interface{}) (string, bool) {
	v, ok := value.(string)
	return v, ok
}

func intFromUnknown(value interface{}) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int8:
		return int(v), true
	case int16:
		return int(v), true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case uint:
		return int(v), true
	case uint8:
		return int(v), true
	case uint16:
		return int(v), true
	case uint32:
		return int(v), true
	case uint64:
		if v > uint64(^uint(0)>>1) {
			return 0, false
		}
		return int(v), true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		return int(v), true
	case float32:
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return int(v), true
	case json.Number:
		n, err := strconv.Atoi(v.String())
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

func floatFromUnknown(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		return v, true
	case float32:
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		n, err := strconv.ParseFloat(v.String(), 64)
		if err != nil {
			return 0, false
		}
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

func newSpiderSenseCircuitBreaker(cfg *spiderSenseCircuitBreakerConfig) *spiderSenseCircuitBreaker {
	if cfg == nil {
		return nil
	}
	return &spiderSenseCircuitBreaker{
		cfg:   *cfg,
		state: spiderSenseCircuitClosed,
	}
}

func (cb *spiderSenseCircuitBreaker) allow(now time.Time) (bool, spiderSenseCircuitState) {
	if cb == nil {
		return true, spiderSenseCircuitClosed
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case spiderSenseCircuitOpen:
		if now.Before(cb.openUntil) {
			return false, cb.state
		}
		cb.state = spiderSenseCircuitHalfOpen
		cb.failures = 0
		cb.successes = 0
		return true, cb.state
	default:
		return true, cb.state
	}
}

func (cb *spiderSenseCircuitBreaker) recordSuccess() {
	if cb == nil {
		return
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == spiderSenseCircuitHalfOpen {
		cb.successes++
		if cb.successes >= cb.cfg.successThreshold {
			cb.state = spiderSenseCircuitClosed
			cb.failures = 0
			cb.successes = 0
		}
		return
	}
	cb.state = spiderSenseCircuitClosed
	cb.failures = 0
	cb.successes = 0
}

func (cb *spiderSenseCircuitBreaker) recordFailure(now time.Time) {
	if cb == nil {
		return
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == spiderSenseCircuitHalfOpen {
		cb.state = spiderSenseCircuitOpen
		cb.openedAt = now
		cb.openUntil = now.Add(cb.cfg.resetTimeout)
		cb.failures = 0
		cb.successes = 0
		return
	}
	cb.failures++
	if cb.failures >= cb.cfg.failureThreshold {
		cb.state = spiderSenseCircuitOpen
		cb.openedAt = now
		cb.openUntil = now.Add(cb.cfg.resetTimeout)
		cb.failures = 0
		cb.successes = 0
	}
}

func (cb *spiderSenseCircuitBreaker) currentState() spiderSenseCircuitState {
	if cb == nil {
		return spiderSenseCircuitClosed
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

func (g *SpiderSenseGuard) circuitAllow(cb *spiderSenseCircuitBreaker) (bool, spiderSenseCircuitState) {
	return cb.allow(time.Now())
}

func (g *SpiderSenseGuard) circuitRecordSuccess(cb *spiderSenseCircuitBreaker) {
	if cb == nil {
		return
	}
	cb.recordSuccess()
}

func (g *SpiderSenseGuard) circuitRecordFailure(cb *spiderSenseCircuitBreaker) {
	if cb == nil {
		return
	}
	cb.recordFailure(time.Now())
}

func (g *SpiderSenseGuard) circuitState(cb *spiderSenseCircuitBreaker) spiderSenseCircuitState {
	if cb == nil {
		return spiderSenseCircuitClosed
	}
	return cb.currentState()
}

func newSpiderSenseEmbeddingCache(enabled bool, ttl time.Duration, maxSizeBytes int) *spiderSenseEmbeddingCache {
	if ttl <= 0 {
		ttl = defaultAsyncCacheTTL
	}
	if maxSizeBytes <= 0 {
		maxSizeBytes = defaultAsyncCacheMaxSize
	}
	return &spiderSenseEmbeddingCache{
		enabled:      enabled,
		ttl:          ttl,
		maxSizeBytes: maxSizeBytes,
		entries:      make(map[string]*spiderSenseCacheEntry),
		lru:          list.New(),
	}
}

func (c *spiderSenseEmbeddingCache) Get(key string) ([]float32, bool) {
	if c == nil || !c.enabled {
		return nil, false
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !entry.expiresAt.After(now) {
		c.removeLocked(entry)
		return nil, false
	}
	c.lru.MoveToBack(entry.element)
	copyEmbedding := make([]float32, len(entry.embedding))
	copy(copyEmbedding, entry.embedding)
	return copyEmbedding, true
}

func (c *spiderSenseEmbeddingCache) Set(key string, embedding []float32) {
	if c == nil || !c.enabled || len(embedding) == 0 {
		return
	}
	approxSize := len(key) + len(embedding)*4 + 64
	if approxSize > c.maxSizeBytes {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	if existing, ok := c.entries[key]; ok {
		c.removeLocked(existing)
	}
	for c.currentSize+approxSize > c.maxSizeBytes {
		front := c.lru.Front()
		if front == nil {
			break
		}
		oldKey, _ := front.Value.(string)
		entry := c.entries[oldKey]
		c.removeLocked(entry)
	}

	copyEmbedding := make([]float32, len(embedding))
	copy(copyEmbedding, embedding)
	element := c.lru.PushBack(key)
	entry := &spiderSenseCacheEntry{
		key:       key,
		embedding: copyEmbedding,
		expiresAt: now.Add(c.ttl),
		sizeBytes: approxSize,
		element:   element,
	}
	c.entries[key] = entry
	c.currentSize += approxSize
}

func (c *spiderSenseEmbeddingCache) removeLocked(entry *spiderSenseCacheEntry) {
	if entry == nil {
		return
	}
	delete(c.entries, entry.key)
	if entry.element != nil {
		c.lru.Remove(entry.element)
	}
	c.currentSize -= entry.sizeBytes
	if c.currentSize < 0 {
		c.currentSize = 0
	}
}

func spiderSenseEmbeddingCacheKey(providerURL, model, text string) string {
	normalizedURL := normalizeProviderURL(providerURL)
	normalizedModel := strings.TrimSpace(model)
	payload := "v1|" + normalizedURL + "|" + normalizedModel + "|" + strings.TrimSpace(text)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func normalizeProviderURL(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return strings.ToLower(trimmed)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.RawQuery = ""
	parsed.Fragment = ""
	pathValue := strings.TrimSpace(parsed.Path)
	if pathValue == "" {
		parsed.Path = "/"
	} else {
		parsed.Path = "/" + strings.Trim(pathValue, "/")
	}
	return parsed.String()
}

func nextBackoff(current time.Duration, cfg spiderSenseRetryConfig) time.Duration {
	next := float64(current) * cfg.multiplier
	if next > float64(cfg.maxBackoff) {
		return cfg.maxBackoff
	}
	return time.Duration(next)
}

func resolveProviderRetryDelay(
	fallback time.Duration,
	providerErr *spiderSenseProviderCallError,
	cfg spiderSenseRetryConfig,
) time.Duration {
	delay := fallback
	if providerErr != nil && providerErr.retryAfter > 0 {
		hint := providerErr.retryAfter
		if cfg.retryAfterCap > 0 && hint > cfg.retryAfterCap {
			hint = cfg.retryAfterCap
		}
		if hint > delay {
			delay = hint
		}
	}
	if delay <= 0 {
		return fallback
	}
	return delay
}

func parseRateLimitRetryDelay(
	headers http.Header,
	now time.Time,
	cfg spiderSenseRetryConfig,
) time.Duration {
	var retryDelay time.Duration
	if cfg.honorRetryAfter {
		if parsed, ok := parseRetryAfterHeader(headers.Get("Retry-After"), now); ok && parsed > retryDelay {
			retryDelay = parsed
		}
	}
	if cfg.honorRateLimitReset {
		candidates := []string{
			headers.Get("RateLimit-Reset"),
			headers.Get("X-RateLimit-Reset"),
			headers.Get("X-Rate-Limit-Reset"),
			headers.Get("x-ratelimit-reset-requests"),
		}
		for _, candidate := range candidates {
			if parsed, ok := parseRateLimitResetHeader(candidate, now, cfg.rateLimitResetGrace); ok && parsed > retryDelay {
				retryDelay = parsed
			}
		}
	}
	if cfg.retryAfterCap > 0 && retryDelay > cfg.retryAfterCap {
		retryDelay = cfg.retryAfterCap
	}
	return retryDelay
}

func parseRetryAfterHeader(raw string, now time.Time) (time.Duration, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil {
		if seconds <= 0 {
			return 0, false
		}
		return time.Duration(seconds * float64(time.Second)), true
	}
	layouts := []string{time.RFC1123, time.RFC1123Z, time.RFC850, time.ANSIC}
	for _, layout := range layouts {
		t, err := time.Parse(layout, value)
		if err != nil {
			continue
		}
		delta := time.Until(t)
		if !t.IsZero() {
			delta = t.Sub(now)
		}
		if delta <= 0 {
			return 0, false
		}
		return delta, true
	}
	return 0, false
}

func parseRateLimitResetHeader(raw string, now time.Time, grace time.Duration) (time.Duration, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, false
	}

	// RFC-ish relative seconds fallback.
	if seconds, err := strconv.ParseFloat(value, 64); err == nil {
		delay := rateLimitSecondsToDelay(seconds, now, grace)
		if delay > 0 {
			return delay, true
		}
		return 0, false
	}

	layouts := []string{time.RFC3339, time.RFC1123, time.RFC1123Z}
	for _, layout := range layouts {
		t, err := time.Parse(layout, value)
		if err != nil {
			continue
		}
		delay := t.Sub(now) + grace
		if delay <= 0 {
			return 0, false
		}
		return delay, true
	}
	return 0, false
}

func rateLimitSecondsToDelay(raw float64, now time.Time, grace time.Duration) time.Duration {
	if raw <= 0 || math.IsNaN(raw) || math.IsInf(raw, 0) {
		return 0
	}

	// Heuristic:
	// - large values are interpreted as epoch timestamps (sec or ms),
	// - small values are interpreted as relative seconds until reset.
	var target time.Time
	switch {
	case raw >= 1e12:
		target = time.UnixMilli(int64(raw))
	case raw >= 1e9:
		target = time.Unix(int64(raw), 0)
	default:
		return time.Duration(raw*float64(time.Second)) + grace
	}

	delay := target.Sub(now) + grace
	if delay <= 0 {
		return 0
	}
	return delay
}

func sleepWithGuardContext(guardCtx *GuardContext, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	ctx := context.Background()
	if guardCtx != nil && guardCtx.Context != nil {
		ctx = guardCtx.Context
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isRetryableHTTPStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return true
	default:
		return status >= 500 && status <= 599
	}
}

func isRetryableTransportError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	return false
}

func verdictFromGuardResult(result GuardResult) ScreeningVerdict {
	if !result.Allowed {
		return VerdictDeny
	}
	if result.Severity == Warning {
		return VerdictAmbiguous
	}
	return VerdictAllow
}

func (g *SpiderSenseGuard) requestTimeout() time.Duration {
	if g.asyncCfg.hasAsyncTimeout {
		return g.asyncCfg.timeout
	}
	return defaultEmbeddingTimeout
}

func loadPatternDBFromPath(cfg *policy.SpiderSenseConfig) (*PatternDb, string, string, string, error) {
	material, err := spiderSensePatternDBMaterialFromConfig(cfg)
	if err != nil {
		return nil, "", "", "", err
	}

	data, source, err := spiderSenseReadPatternDB(material.path)
	if err != nil {
		return nil, "", "", "", err
	}

	trustKeyID, err := verifyPatternDBIntegrity(data, material.integrity)
	if err != nil {
		return nil, "", "", "", err
	}

	db, err := ParsePatternDB(data)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("spider_sense: %w", err)
	}
	return db, source, material.integrity.Version, trustKeyID, nil
}

type spiderSensePatternDBMaterial struct {
	path      string
	integrity patternDBIntegrity
}

func spiderSensePatternDBMaterialFromConfig(cfg *policy.SpiderSenseConfig) (spiderSensePatternDBMaterial, error) {
	manifestPath := strings.TrimSpace(cfg.PatternDBManifestPath)
	if manifestPath != "" {
		return spiderSensePatternDBMaterialFromManifest(cfg, manifestPath)
	}

	trimmed := strings.TrimSpace(cfg.PatternDBPath)
	if trimmed == "" {
		return spiderSensePatternDBMaterial{}, fmt.Errorf("spider_sense: pattern_db_path cannot be empty")
	}
	integrity, err := requiredIntegrityFields(cfg)
	if err != nil {
		return spiderSensePatternDBMaterial{}, err
	}
	return spiderSensePatternDBMaterial{
		path:      trimmed,
		integrity: integrity,
	}, nil
}

func spiderSensePatternDBMaterialFromManifest(
	cfg *policy.SpiderSenseConfig,
	manifestPath string,
) (spiderSensePatternDBMaterial, error) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return spiderSensePatternDBMaterial{}, fmt.Errorf(
			"spider_sense: read pattern DB manifest %q: %w",
			manifestPath,
			err,
		)
	}

	var manifest spiderSensePatternManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return spiderSensePatternDBMaterial{}, fmt.Errorf(
			"spider_sense: parse pattern DB manifest %q: %w",
			manifestPath,
			err,
		)
	}

	if strings.TrimSpace(manifest.PatternDBPath) == "" {
		return spiderSensePatternDBMaterial{}, fmt.Errorf(
			"spider_sense: pattern DB manifest %q missing pattern_db_path",
			manifestPath,
		)
	}

	manifestRootsPath := spiderSenseResolvePath(
		manifestPath,
		strings.TrimSpace(cfg.PatternDBManifestTrustStorePath),
	)
	manifestRootsInline := cfg.PatternDBManifestTrustedKeys
	if manifestRootsPath == "" && len(manifestRootsInline) == 0 {
		return spiderSensePatternDBMaterial{}, fmt.Errorf(
			"spider_sense: pattern_db_manifest_path requires pattern_db_manifest_trust_store_path or pattern_db_manifest_trusted_keys",
		)
	}

	now := time.Now()
	if err := spiderSenseVerifyManifestWindow(manifest, now); err != nil {
		return spiderSensePatternDBMaterial{}, err
	}
	if err := spiderSenseVerifyPatternManifestSignature(
		manifest,
		manifestRootsPath,
		manifestRootsInline,
		now,
	); err != nil {
		return spiderSensePatternDBMaterial{}, err
	}

	patternTrustStorePath := spiderSenseResolvePath(
		manifestPath,
		strings.TrimSpace(manifest.PatternDBTrustStore),
	)
	patternPath := spiderSenseResolvePath(
		manifestPath,
		strings.TrimSpace(manifest.PatternDBPath),
	)

	manifestCfg := &policy.SpiderSenseConfig{
		PatternDBPath:           patternPath,
		PatternDBVersion:        strings.TrimSpace(manifest.PatternDBVersion),
		PatternDBChecksum:       strings.TrimSpace(manifest.PatternDBChecksum),
		PatternDBSignature:      strings.TrimSpace(manifest.PatternDBSignature),
		PatternDBPublicKey:      strings.TrimSpace(manifest.PatternDBPublicKey),
		PatternDBSignatureKeyID: strings.TrimSpace(manifest.PatternDBSignatureKey),
		PatternDBTrustStorePath: patternTrustStorePath,
		PatternDBTrustedKeys:    manifest.PatternDBTrustedKeys,
	}
	integrity, err := requiredIntegrityFields(manifestCfg)
	if err != nil {
		return spiderSensePatternDBMaterial{}, err
	}

	return spiderSensePatternDBMaterial{
		path:      patternPath,
		integrity: integrity,
	}, nil
}

func spiderSenseReadPatternDB(path string) ([]byte, string, error) {
	switch path {
	case "builtin:s2bench-v1":
		data, err := spiderSensePatternFS.ReadFile("patterns/s2bench-v1.json")
		if err != nil {
			return nil, "", fmt.Errorf("spider_sense: load builtin pattern DB %q: %w", path, err)
		}
		return data, "builtin:s2bench-v1", nil
	default:
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, "", fmt.Errorf("spider_sense: read pattern DB %q: %w", path, err)
		}
		return data, path, nil
	}
}

func spiderSenseResolvePath(baseFile, value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.HasPrefix(trimmed, "builtin:") {
		return trimmed
	}
	if filepath.IsAbs(trimmed) {
		return trimmed
	}
	return filepath.Clean(filepath.Join(filepath.Dir(baseFile), trimmed))
}

func spiderSenseVerifyManifestWindow(manifest spiderSensePatternManifest, now time.Time) error {
	if trimmed := strings.TrimSpace(manifest.NotBefore); trimmed != "" {
		notBefore, err := time.Parse(time.RFC3339, trimmed)
		if err != nil {
			return fmt.Errorf("spider_sense: invalid pattern DB manifest not_before: %w", err)
		}
		if now.Before(notBefore) {
			return fmt.Errorf("spider_sense: pattern DB manifest not yet valid")
		}
	}
	if trimmed := strings.TrimSpace(manifest.NotAfter); trimmed != "" {
		notAfter, err := time.Parse(time.RFC3339, trimmed)
		if err != nil {
			return fmt.Errorf("spider_sense: invalid pattern DB manifest not_after: %w", err)
		}
		if now.After(notAfter) {
			return fmt.Errorf("spider_sense: pattern DB manifest expired")
		}
	}
	return nil
}

func spiderSenseVerifyPatternManifestSignature(
	manifest spiderSensePatternManifest,
	rootsPath string,
	inlineRoots []policy.SpiderSenseTrustedKeyConfig,
	now time.Time,
) error {
	manifestSignature := strings.TrimSpace(manifest.ManifestSignature)
	manifestSignatureKeyID := normalizeHexValue(manifest.ManifestSignatureKey)
	if manifestSignature == "" {
		return fmt.Errorf("spider_sense: pattern DB manifest missing manifest_signature")
	}
	if manifestSignatureKeyID == "" {
		return fmt.Errorf("spider_sense: pattern DB manifest missing manifest_signature_key_id")
	}

	store, err := loadSpiderSenseTrustStore(rootsPath, inlineRoots)
	if err != nil {
		return fmt.Errorf("spider_sense: load pattern DB manifest trust store: %w", err)
	}
	key, err := store.SelectKey(manifestSignatureKeyID, now)
	if err != nil {
		return fmt.Errorf("spider_sense: %w", err)
	}
	pk, err := sdkcrypto.PublicKeyFromHex(key.PublicKey)
	if err != nil {
		return fmt.Errorf(
			"spider_sense: invalid pattern DB manifest trust key material for key_id %q: %w",
			key.KeyID,
			err,
		)
	}
	sig, err := sdkcrypto.SignatureFromHex(manifestSignature)
	if err != nil {
		return fmt.Errorf("spider_sense: invalid pattern DB manifest signature: %w", err)
	}
	message := spiderSenseManifestSigningMessage(manifest)
	if !pk.Verify(message, &sig) {
		return fmt.Errorf(
			"spider_sense: pattern DB manifest signature verification failed for key_id %q",
			key.KeyID,
		)
	}
	return nil
}

func spiderSenseManifestSigningMessage(manifest spiderSensePatternManifest) []byte {
	return []byte(fmt.Sprintf(
		"spider_sense_manifest:v1:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
		strings.TrimSpace(manifest.PatternDBPath),
		strings.TrimSpace(manifest.PatternDBVersion),
		normalizeHexValue(manifest.PatternDBChecksum),
		normalizeHexValue(manifest.PatternDBSignature),
		normalizeHexValue(manifest.PatternDBSignatureKey),
		normalizeHexValue(manifest.PatternDBPublicKey),
		strings.TrimSpace(manifest.PatternDBTrustStore),
		spiderSenseTrustedKeysDigest(manifest.PatternDBTrustedKeys),
		strings.TrimSpace(manifest.NotBefore),
		strings.TrimSpace(manifest.NotAfter),
	))
}

func spiderSenseTrustedKeysDigest(entries []policy.SpiderSenseTrustedKeyConfig) string {
	if len(entries) == 0 {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:])
	}

	parts := make([]string, 0, len(entries))
	for _, entry := range entries {
		parts = append(parts, fmt.Sprintf(
			"%s|%s|%s|%s|%s",
			strings.ToLower(strings.TrimSpace(entry.KeyID)),
			normalizeHexValue(entry.PublicKey),
			strings.ToLower(strings.TrimSpace(entry.Status)),
			strings.TrimSpace(entry.NotBefore),
			strings.TrimSpace(entry.NotAfter),
		))
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, ";")))
	return hex.EncodeToString(sum[:])
}

func normalizeHexValue(value string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x")
}

type patternDBIntegrity struct {
	Version          string
	Checksum         string
	Signature        string
	PublicKey        string
	SignatureKeyID   string
	TrustStorePath   string
	TrustedKeys      []policy.SpiderSenseTrustedKeyConfig
	UseTrustStore    bool
	UseLegacyKeyPair bool
}

func requiredIntegrityFields(cfg *policy.SpiderSenseConfig) (patternDBIntegrity, error) {
	version := strings.TrimSpace(cfg.PatternDBVersion)
	checksum := strings.TrimSpace(cfg.PatternDBChecksum)
	signature := strings.TrimSpace(cfg.PatternDBSignature)
	publicKey := strings.TrimSpace(cfg.PatternDBPublicKey)
	signatureKeyID := strings.ToLower(strings.TrimSpace(cfg.PatternDBSignatureKeyID))
	trustStorePath := strings.TrimSpace(cfg.PatternDBTrustStorePath)
	trustedKeys := cfg.PatternDBTrustedKeys
	if version == "" || checksum == "" {
		return patternDBIntegrity{}, fmt.Errorf(
			"spider_sense: pattern_db_version and pattern_db_checksum are required when pattern_db_path is set",
		)
	}
	if (signature == "") != (publicKey == "") && signatureKeyID == "" && trustStorePath == "" && len(trustedKeys) == 0 {
		return patternDBIntegrity{}, fmt.Errorf(
			"spider_sense: pattern_db_signature and pattern_db_public_key must either both be set or both be omitted",
		)
	}
	useTrustStore := signatureKeyID != "" || trustStorePath != "" || len(trustedKeys) > 0
	useLegacy := signature != "" && publicKey != ""
	if useTrustStore && publicKey != "" {
		return patternDBIntegrity{}, fmt.Errorf(
			"spider_sense: pattern_db_public_key cannot be combined with trust-store based verification",
		)
	}
	if useTrustStore {
		if signature == "" {
			return patternDBIntegrity{}, fmt.Errorf(
				"spider_sense: pattern_db_signature is required when trust-store fields are set",
			)
		}
		if signatureKeyID == "" {
			return patternDBIntegrity{}, fmt.Errorf(
				"spider_sense: pattern_db_signature_key_id is required when trust-store fields are set",
			)
		}
	}
	return patternDBIntegrity{
		Version:          version,
		Checksum:         checksum,
		Signature:        signature,
		PublicKey:        publicKey,
		SignatureKeyID:   signatureKeyID,
		TrustStorePath:   trustStorePath,
		TrustedKeys:      trustedKeys,
		UseTrustStore:    useTrustStore,
		UseLegacyKeyPair: useLegacy,
	}, nil
}

func verifyPatternDBIntegrity(data []byte, integrity patternDBIntegrity) (string, error) {
	sum := sha256.Sum256(data)
	actualChecksum := strings.ToLower(hex.EncodeToString(sum[:]))
	normalizedExpected := strings.TrimPrefix(strings.ToLower(integrity.Checksum), "0x")
	if actualChecksum != normalizedExpected {
		return "", fmt.Errorf("spider_sense: pattern DB checksum mismatch: expected %s, got %s", normalizedExpected, actualChecksum)
	}

	if integrity.UseLegacyKeyPair {
		pk, err := sdkcrypto.PublicKeyFromHex(integrity.PublicKey)
		if err != nil {
			return "", fmt.Errorf("spider_sense: invalid pattern DB public key: %w", err)
		}
		sig, err := sdkcrypto.SignatureFromHex(integrity.Signature)
		if err != nil {
			return "", fmt.Errorf("spider_sense: invalid pattern DB signature: %w", err)
		}

		message := []byte(fmt.Sprintf("spider_sense_db:v1:%s:%s", integrity.Version, normalizedExpected))
		if !pk.Verify(message, &sig) {
			return "", fmt.Errorf("spider_sense: pattern DB signature verification failed")
		}
		return "", nil
	}

	if integrity.UseTrustStore {
		store, err := loadSpiderSenseTrustStore(integrity.TrustStorePath, integrity.TrustedKeys)
		if err != nil {
			return "", fmt.Errorf("spider_sense: load trust store: %w", err)
		}
		key, err := store.SelectKey(integrity.SignatureKeyID, time.Now())
		if err != nil {
			return "", fmt.Errorf("spider_sense: %w", err)
		}
		pk, err := sdkcrypto.PublicKeyFromHex(key.PublicKey)
		if err != nil {
			return "", fmt.Errorf("spider_sense: invalid trusted key material for key_id %q: %w", key.KeyID, err)
		}
		sig, err := sdkcrypto.SignatureFromHex(integrity.Signature)
		if err != nil {
			return "", fmt.Errorf("spider_sense: invalid pattern DB signature: %w", err)
		}
		message := []byte(fmt.Sprintf("spider_sense_db:v1:%s:%s", integrity.Version, normalizedExpected))
		if !pk.Verify(message, &sig) {
			return "", fmt.Errorf("spider_sense: pattern DB signature verification failed for key_id %q", key.KeyID)
		}
		return key.KeyID, nil
	}

	if integrity.Signature != "" || integrity.PublicKey != "" {
		return "", fmt.Errorf(
			"spider_sense: pattern_db_signature and pattern_db_public_key must either both be set or both be omitted",
		)
	}
	return "", nil
}

func loadSpiderSenseTrustStore(path string, inline []policy.SpiderSenseTrustedKeyConfig) (spiderSenseTrustStore, error) {
	store := spiderSenseTrustStore{Keys: make(map[string]spiderSenseTrustedKey)}
	add := func(entries []policy.SpiderSenseTrustedKeyConfig) error {
		for _, entry := range entries {
			normalized, err := normalizeSpiderSenseTrustedKey(entry)
			if err != nil {
				return err
			}
			store.Keys[normalized.KeyID] = normalized
		}
		return nil
	}

	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return store, fmt.Errorf("read trust store %q: %w", path, err)
		}
		entries, err := parseSpiderSenseTrustStoreFile(raw)
		if err != nil {
			return store, err
		}
		if err := add(entries); err != nil {
			return store, err
		}
	}

	if err := add(inline); err != nil {
		return store, err
	}
	if len(store.Keys) == 0 {
		return store, fmt.Errorf("trust store is empty")
	}
	return store, nil
}

func parseSpiderSenseTrustStoreFile(raw []byte) ([]policy.SpiderSenseTrustedKeyConfig, error) {
	var list []policy.SpiderSenseTrustedKeyConfig
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}

	var wrapped struct {
		Keys []policy.SpiderSenseTrustedKeyConfig `json:"keys"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil {
		return wrapped.Keys, nil
	}
	return nil, fmt.Errorf("trust store must be a JSON array or object with keys[]")
}

func normalizeSpiderSenseTrustedKey(entry policy.SpiderSenseTrustedKeyConfig) (spiderSenseTrustedKey, error) {
	publicKey := strings.TrimSpace(entry.PublicKey)
	if publicKey == "" {
		return spiderSenseTrustedKey{}, fmt.Errorf("trust store entry is missing public_key")
	}
	publicKey = strings.TrimPrefix(strings.ToLower(publicKey), "0x")
	if _, err := sdkcrypto.PublicKeyFromHex(publicKey); err != nil {
		return spiderSenseTrustedKey{}, fmt.Errorf("invalid trusted public_key: %w", err)
	}
	derivedKeyID := deriveSpiderSenseKeyID(publicKey)
	keyID := strings.ToLower(strings.TrimSpace(entry.KeyID))
	if keyID == "" {
		keyID = derivedKeyID
	} else if keyID != derivedKeyID {
		return spiderSenseTrustedKey{}, fmt.Errorf(
			"trusted key_id %q does not match derived key_id %q",
			keyID, derivedKeyID,
		)
	}

	status := spiderSenseKeyActive
	switch strings.ToLower(strings.TrimSpace(entry.Status)) {
	case "", "active":
		status = spiderSenseKeyActive
	case "deprecated":
		status = spiderSenseKeyDeprecated
	case "revoked":
		status = spiderSenseKeyRevoked
	default:
		return spiderSenseTrustedKey{}, fmt.Errorf("unsupported trusted key status %q", entry.Status)
	}

	normalized := spiderSenseTrustedKey{
		KeyID:     keyID,
		PublicKey: publicKey,
		Status:    status,
	}
	if trimmed := strings.TrimSpace(entry.NotBefore); trimmed != "" {
		parsed, err := time.Parse(time.RFC3339, trimmed)
		if err != nil {
			return spiderSenseTrustedKey{}, fmt.Errorf("invalid not_before for key_id %q: %w", keyID, err)
		}
		normalized.NotBefore = parsed
		normalized.HasNotBefore = true
	}
	if trimmed := strings.TrimSpace(entry.NotAfter); trimmed != "" {
		parsed, err := time.Parse(time.RFC3339, trimmed)
		if err != nil {
			return spiderSenseTrustedKey{}, fmt.Errorf("invalid not_after for key_id %q: %w", keyID, err)
		}
		normalized.NotAfter = parsed
		normalized.HasNotAfter = true
	}
	if normalized.HasNotBefore && normalized.HasNotAfter && normalized.NotAfter.Before(normalized.NotBefore) {
		return spiderSenseTrustedKey{}, fmt.Errorf("invalid trusted key window for key_id %q", keyID)
	}
	return normalized, nil
}

func (s spiderSenseTrustStore) SelectKey(keyID string, now time.Time) (spiderSenseTrustedKey, error) {
	normalizedID := strings.ToLower(strings.TrimSpace(keyID))
	key, ok := s.Keys[normalizedID]
	if !ok {
		return spiderSenseTrustedKey{}, fmt.Errorf("pattern DB signature key_id %q not found in trust store", normalizedID)
	}
	if key.Status == spiderSenseKeyRevoked {
		return spiderSenseTrustedKey{}, fmt.Errorf("pattern DB signature key_id %q is revoked", normalizedID)
	}
	if key.HasNotBefore && now.Before(key.NotBefore) {
		return spiderSenseTrustedKey{}, fmt.Errorf("pattern DB signature key_id %q is not yet valid", normalizedID)
	}
	if key.HasNotAfter && now.After(key.NotAfter) {
		return spiderSenseTrustedKey{}, fmt.Errorf("pattern DB signature key_id %q is expired", normalizedID)
	}
	return key, nil
}

func deriveSpiderSenseKeyID(publicKeyHex string) string {
	normalized := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(publicKeyHex)), "0x")
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])[:16]
}
