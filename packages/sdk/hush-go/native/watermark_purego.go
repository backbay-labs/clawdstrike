//go:build !cgo

package native

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/backbay-labs/clawdstrike-go/canonical"
	"github.com/backbay-labs/clawdstrike-go/crypto"
)

const (
	metaPrefix                     = "<!--hushclaw.watermark:v1:"
	metaSuffix                     = "-->"
	pureWatermarkerCacheMaxEntries = 256
)

type watermarkConfig struct {
	Encoding         string
	PrivateKeyHex    string
	GenerateKeypair  bool
	IncludeTimestamp bool
	IncludeSequence  bool
	CustomMetadata   map[string]string
}

type watermarkVerifierConfig struct {
	TrustedPublicKeys []string
	AllowUnverified   bool
}

type pureWatermarker struct {
	cfg     watermarkConfig
	keypair *crypto.Keypair
	seq     atomic.Uint32
}

var (
	watermarkerMu       sync.Mutex
	watermarkerCache    = map[string]*pureWatermarker{}
	watermarkerCacheSeq []string
)

// WatermarkPublicKey returns the watermark public key.
func WatermarkPublicKey(configJSON string) (string, error) {
	wm, err := getOrCreatePureWatermarker(configJSON)
	if err != nil {
		return "", err
	}
	return wm.keypair.PublicKey().Hex(), nil
}

// WatermarkPrompt watermarks a prompt and returns JSON.
func WatermarkPrompt(prompt, configJSON, appID, sessionID string) (string, error) {
	if prompt == "" {
		return "", fmt.Errorf("watermark prompt is required")
	}
	if appID == "" {
		appID = "unknown"
	}
	if sessionID == "" {
		sessionID = "unknown"
	}

	wm, err := getOrCreatePureWatermarker(configJSON)
	if err != nil {
		return "", err
	}

	payload := wm.generatePayload(appID, sessionID)
	encodedData, err := encodePayload(payload)
	if err != nil {
		return "", err
	}
	signature, err := wm.keypair.Sign(encodedData)
	if err != nil {
		return "", err
	}

	publicKey := wm.keypair.PublicKey().Hex()
	payloadB64 := base64.RawURLEncoding.EncodeToString(encodedData)
	blob := map[string]interface{}{
		"encoding":  "metadata",
		"payload":   payloadB64,
		"signature": signature.Hex(),
		"publicKey": publicKey,
	}
	blobBytes, err := json.Marshal(blob)
	if err != nil {
		return "", err
	}
	blobB64 := base64.RawURLEncoding.EncodeToString(blobBytes)
	watermarked := metaPrefix + blobB64 + metaSuffix + "\n" + prompt

	result := map[string]interface{}{
		"original":    prompt,
		"watermarked": watermarked,
		"watermark": map[string]interface{}{
			"payload":              payload,
			"encoding":             "metadata",
			"encodedDataBase64Url": payloadB64,
			"signature":            signature.Hex(),
			"publicKey":            publicKey,
			"fingerprint":          crypto.SHA256(encodedData).Hex(),
		},
	}
	out, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ExtractWatermark extracts and verifies watermark metadata from text.
func ExtractWatermark(text, configJSON string) (string, error) {
	cfg, err := parseWatermarkVerifierConfig(configJSON)
	if err != nil {
		return "", err
	}

	extracted, err := extractMetadata(text)
	if err != nil {
		out := map[string]interface{}{
			"found":     false,
			"verified":  false,
			"errors":    []string{err.Error()},
			"watermark": nil,
		}
		raw, _ := json.Marshal(out)
		return string(raw), nil
	}
	if extracted == nil {
		out := map[string]interface{}{
			"found":     false,
			"verified":  false,
			"errors":    []string{},
			"watermark": nil,
		}
		raw, _ := json.Marshal(out)
		return string(raw), nil
	}

	publicKey, err := crypto.PublicKeyFromHex(extracted.PublicKey)
	if err != nil {
		return "", err
	}
	signature, err := crypto.SignatureFromHex(extracted.Signature)
	if err != nil {
		return "", err
	}
	ok := publicKey.Verify(extracted.EncodedData, &signature)
	trusted := len(cfg.TrustedPublicKeys) == 0 || containsTrusted(cfg.TrustedPublicKeys, extracted.PublicKey)
	verified := ok && trusted

	if !verified && !cfg.AllowUnverified {
		out := map[string]interface{}{
			"found":    true,
			"verified": false,
			"errors":   []string{"watermark signature invalid or untrusted"},
			"watermark": map[string]interface{}{
				"payload":              extracted.Payload,
				"encoding":             extracted.Encoding,
				"encodedDataBase64Url": base64.RawURLEncoding.EncodeToString(extracted.EncodedData),
				"signature":            extracted.Signature,
				"publicKey":            extracted.PublicKey,
				"fingerprint":          crypto.SHA256(extracted.EncodedData).Hex(),
			},
		}
		raw, _ := json.Marshal(out)
		return string(raw), nil
	}

	out := map[string]interface{}{
		"found":    true,
		"verified": verified,
		"errors":   []string{},
		"watermark": map[string]interface{}{
			"payload":              extracted.Payload,
			"encoding":             extracted.Encoding,
			"encodedDataBase64Url": base64.RawURLEncoding.EncodeToString(extracted.EncodedData),
			"signature":            extracted.Signature,
			"publicKey":            extracted.PublicKey,
			"fingerprint":          crypto.SHA256(extracted.EncodedData).Hex(),
		},
	}
	raw, _ := json.Marshal(out)
	return string(raw), nil
}

type extractedMetadata struct {
	Payload     map[string]interface{}
	Encoding    string
	EncodedData []byte
	Signature   string
	PublicKey   string
}

func extractMetadata(text string) (*extractedMetadata, error) {
	start := strings.Index(text, metaPrefix)
	if start < 0 {
		return nil, nil
	}
	payloadStart := start + len(metaPrefix)
	end := strings.Index(text[payloadStart:], metaSuffix)
	if end < 0 {
		return nil, fmt.Errorf("watermark metadata missing suffix")
	}
	end += payloadStart

	blobRaw := text[payloadStart:end]
	blobBytes, err := base64.RawURLEncoding.DecodeString(blobRaw)
	if err != nil {
		return nil, fmt.Errorf("watermark base64 decode failed: %w", err)
	}
	var blob map[string]interface{}
	if err := json.Unmarshal(blobBytes, &blob); err != nil {
		return nil, fmt.Errorf("watermark json decode failed: %w", err)
	}

	encoding := fmt.Sprint(blob["encoding"])
	if encoding != "metadata" {
		return nil, fmt.Errorf("unsupported watermark encoding")
	}

	payloadB64 := fmt.Sprint(blob["payload"])
	encodedData, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("watermark payload base64 decode failed: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(encodedData, &payload); err != nil {
		return nil, fmt.Errorf("watermark payload json decode failed: %w", err)
	}

	sig := fmt.Sprint(blob["signature"])
	pk := fmt.Sprint(blob["publicKey"])
	if _, err := hex.DecodeString(strings.TrimPrefix(sig, "0x")); err != nil {
		return nil, fmt.Errorf("invalid watermark signature")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(pk, "0x")); err != nil {
		return nil, fmt.Errorf("invalid watermark public key")
	}

	return &extractedMetadata{
		Payload:     payload,
		Encoding:    encoding,
		EncodedData: encodedData,
		Signature:   strings.TrimPrefix(strings.ToLower(sig), "0x"),
		PublicKey:   strings.TrimPrefix(strings.ToLower(pk), "0x"),
	}, nil
}

func containsTrusted(trusted []string, pub string) bool {
	want := strings.TrimPrefix(strings.ToLower(pub), "0x")
	for _, candidate := range trusted {
		if strings.TrimPrefix(strings.ToLower(candidate), "0x") == want {
			return true
		}
	}
	return false
}

func getOrCreatePureWatermarker(configJSON string) (*pureWatermarker, error) {
	cfg, key, err := parseWatermarkConfig(configJSON)
	if err != nil {
		return nil, err
	}

	watermarkerMu.Lock()
	defer watermarkerMu.Unlock()

	if existing, ok := watermarkerCache[key]; ok {
		return existing, nil
	}

	kp, err := buildKeypair(cfg)
	if err != nil {
		return nil, err
	}
	wm := &pureWatermarker{
		cfg:     cfg,
		keypair: kp,
	}
	if len(watermarkerCacheSeq) >= pureWatermarkerCacheMaxEntries {
		evictedKey := watermarkerCacheSeq[0]
		watermarkerCacheSeq = watermarkerCacheSeq[1:]
		delete(watermarkerCache, evictedKey)
	}
	watermarkerCache[key] = wm
	watermarkerCacheSeq = append(watermarkerCacheSeq, key)
	return wm, nil
}

func resetPureWatermarkerCacheForTest() {
	watermarkerMu.Lock()
	defer watermarkerMu.Unlock()
	watermarkerCache = map[string]*pureWatermarker{}
	watermarkerCacheSeq = nil
}

func pureWatermarkerCacheSizeForTest() int {
	watermarkerMu.Lock()
	defer watermarkerMu.Unlock()
	return len(watermarkerCache)
}

func buildKeypair(cfg watermarkConfig) (*crypto.Keypair, error) {
	if cfg.PrivateKeyHex != "" {
		return crypto.KeypairFromHex(cfg.PrivateKeyHex)
	}
	if !cfg.GenerateKeypair {
		return nil, fmt.Errorf("private_key missing and generate_keypair is false")
	}
	return crypto.GenerateKeypair()
}

func parseWatermarkConfig(configJSON string) (watermarkConfig, string, error) {
	cfg := watermarkConfig{
		Encoding:         "metadata",
		GenerateKeypair:  true,
		IncludeTimestamp: true,
		IncludeSequence:  true,
	}

	configJSON = strings.TrimSpace(configJSON)
	if configJSON == "" {
		return cfg, "{}", nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &raw); err != nil {
		return cfg, "", fmt.Errorf("invalid watermark config JSON: %w", err)
	}

	if v, ok := getString(raw, "encoding"); ok && v != "" {
		cfg.Encoding = strings.ToLower(v)
	}
	if cfg.Encoding != "metadata" {
		return cfg, "", fmt.Errorf("unsupported watermark encoding %q", cfg.Encoding)
	}
	if v, ok := getString(raw, "private_key"); ok {
		cfg.PrivateKeyHex = v
	}
	if v, ok := getString(raw, "privateKeyHex"); ok && v != "" {
		cfg.PrivateKeyHex = v
	}
	if v, ok := getBool(raw, "generate_keypair"); ok {
		cfg.GenerateKeypair = v
	}
	if v, ok := getBool(raw, "generateKeypair"); ok {
		cfg.GenerateKeypair = v
	}
	if v, ok := getBool(raw, "include_timestamp"); ok {
		cfg.IncludeTimestamp = v
	}
	if v, ok := getBool(raw, "includeTimestamp"); ok {
		cfg.IncludeTimestamp = v
	}
	if v, ok := getBool(raw, "include_sequence"); ok {
		cfg.IncludeSequence = v
	}
	if v, ok := getBool(raw, "includeSequence"); ok {
		cfg.IncludeSequence = v
	}

	if md, ok := raw["custom_metadata"].(map[string]interface{}); ok {
		cfg.CustomMetadata = toStringMap(md)
	}
	if md, ok := raw["customMetadata"].(map[string]interface{}); ok {
		cfg.CustomMetadata = toStringMap(md)
	}

	key, err := canonical.Canonicalize(raw)
	if err != nil {
		key = configJSON
	}
	return cfg, key, nil
}

func parseWatermarkVerifierConfig(configJSON string) (watermarkVerifierConfig, error) {
	cfg := watermarkVerifierConfig{
		TrustedPublicKeys: []string{},
		AllowUnverified:   false,
	}
	configJSON = strings.TrimSpace(configJSON)
	if configJSON == "" {
		return cfg, nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &raw); err != nil {
		return cfg, fmt.Errorf("invalid watermark verifier config JSON: %w", err)
	}

	if arr, ok := raw["trusted_public_keys"].([]interface{}); ok {
		cfg.TrustedPublicKeys = toStringSlice(arr)
	}
	if arr, ok := raw["trustedPublicKeys"].([]interface{}); ok {
		cfg.TrustedPublicKeys = toStringSlice(arr)
	}
	if v, ok := getBool(raw, "allow_unverified"); ok {
		cfg.AllowUnverified = v
	}
	if v, ok := getBool(raw, "allowUnverified"); ok {
		cfg.AllowUnverified = v
	}
	return cfg, nil
}

func toStringMap(v map[string]interface{}) map[string]string {
	out := map[string]string{}
	for k, x := range v {
		out[k] = fmt.Sprint(x)
	}
	return out
}

func toStringSlice(v []interface{}) []string {
	out := make([]string, 0, len(v))
	for _, x := range v {
		out = append(out, fmt.Sprint(x))
	}
	return out
}

func getString(m map[string]interface{}, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func getBool(m map[string]interface{}, key string) (bool, bool) {
	v, ok := m[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

func (w *pureWatermarker) generatePayload(appID, sessionID string) map[string]interface{} {
	createdAt := int64(0)
	if w.cfg.IncludeTimestamp {
		createdAt = time.Now().UnixMilli()
	}
	seq := uint32(0)
	if w.cfg.IncludeSequence {
		seq = w.seq.Add(1) - 1
	}

	payload := map[string]interface{}{
		"applicationId":  appID,
		"sessionId":      sessionID,
		"createdAt":      createdAt,
		"sequenceNumber": seq,
	}
	if len(w.cfg.CustomMetadata) > 0 {
		payload["metadata"] = w.cfg.CustomMetadata
	}
	return payload
}

func encodePayload(payload map[string]interface{}) ([]byte, error) {
	s, err := canonical.Canonicalize(payload)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}
