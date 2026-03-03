//go:build !cgo

package native

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestPureGoWatermarkRoundtrip(t *testing.T) {
	resetPureWatermarkerCacheForTest()
	config := `{"generate_keypair":true}`

	pub, err := WatermarkPublicKey(config)
	if err != nil {
		t.Fatalf("WatermarkPublicKey: %v", err)
	}
	if len(pub) != 64 {
		t.Fatalf("expected 64-char public key hex, got %q", pub)
	}

	raw, err := WatermarkPrompt("hello", config, "app", "sid")
	if err != nil {
		t.Fatalf("WatermarkPrompt: %v", err)
	}

	var wmOut map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &wmOut); err != nil {
		t.Fatalf("unmarshal watermark output: %v", err)
	}
	watermarked, _ := wmOut["watermarked"].(string)
	if !strings.Contains(watermarked, "<!--hushclaw.watermark:v1:") {
		t.Fatalf("expected hushclaw watermark prefix, got %q", watermarked)
	}

	extractedRaw, err := ExtractWatermark(watermarked, `{"trusted_public_keys":["`+pub+`"]}`)
	if err != nil {
		t.Fatalf("ExtractWatermark: %v", err)
	}
	var extracted map[string]interface{}
	if err := json.Unmarshal([]byte(extractedRaw), &extracted); err != nil {
		t.Fatalf("unmarshal extracted output: %v", err)
	}
	if found, _ := extracted["found"].(bool); !found {
		t.Fatalf("expected found=true, got %v", extracted["found"])
	}
	if verified, _ := extracted["verified"].(bool); !verified {
		t.Fatalf("expected verified=true, got %v", extracted["verified"])
	}
}

func TestPureGoWatermarkDeterministicPublicKeyFromPrivateKey(t *testing.T) {
	resetPureWatermarkerCacheForTest()
	config := `{"privateKeyHex":"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"}`
	pub1, err := WatermarkPublicKey(config)
	if err != nil {
		t.Fatalf("first public key: %v", err)
	}
	pub2, err := WatermarkPublicKey(config)
	if err != nil {
		t.Fatalf("second public key: %v", err)
	}
	if pub1 != pub2 {
		t.Fatalf("expected deterministic public key, got %q vs %q", pub1, pub2)
	}
}

func TestPureGoWatermarkCacheIsBounded(t *testing.T) {
	resetPureWatermarkerCacheForTest()

	for i := 0; i < pureWatermarkerCacheMaxEntries+32; i++ {
		config := fmt.Sprintf(`{"generate_keypair":true,"custom_metadata":{"id":"%d"}}`, i)
		if _, err := WatermarkPublicKey(config); err != nil {
			t.Fatalf("WatermarkPublicKey(%d): %v", i, err)
		}
	}

	if got := pureWatermarkerCacheSizeForTest(); got != pureWatermarkerCacheMaxEntries {
		t.Fatalf("expected cache size %d, got %d", pureWatermarkerCacheMaxEntries, got)
	}
}
