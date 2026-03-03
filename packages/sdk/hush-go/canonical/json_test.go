package canonical

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustParse(t *testing.T, jsonStr string) interface{} {
	t.Helper()
	var v interface{}
	dec := json.NewDecoder(strings.NewReader(jsonStr))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	return v
}

func TestJCSNumberVector(t *testing.T) {
	input := `{"a":1.0,"b":0.0,"c":-0.0,"d":1e21,"e":1e20,"f":1e-6,"g":1e-7}`
	expected := `{"a":1,"b":0,"c":0,"d":1e+21,"e":100000000000000000000,"f":0.000001,"g":1e-7}`

	result, err := CanonicalizeBytes([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if result != expected {
		t.Errorf("JCS number vector:\ngot:  %s\nwant: %s", result, expected)
	}
}

func TestJCSExponentialMantissaRegression(t *testing.T) {
	input := `{"small":1.5e-7,"large":1.5e21}`
	expected := `{"large":1.5e+21,"small":1.5e-7}`

	result, err := CanonicalizeBytes([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if result != expected {
		t.Errorf("JCS mantissa regression:\ngot:  %s\nwant: %s", result, expected)
	}
}

func TestJCSEscapeShortcuts(t *testing.T) {
	input := map[string]interface{}{
		"b":         "\b",
		"f":         "\f",
		"ctl":       "\x0f",
		"quote":     `"`,
		"backslash": `\`,
	}

	expected := `{"b":"\b","backslash":"\\","ctl":"\u000f","f":"\f","quote":"\""}`

	result, err := Canonicalize(input)
	if err != nil {
		t.Fatal(err)
	}
	if result != expected {
		t.Errorf("JCS escape vector:\ngot:  %s\nwant: %s", result, expected)
	}
}

func TestJCSNumericStringKeys(t *testing.T) {
	input := `{"2":"b","10":"a","a":0}`
	expected := `{"10":"a","2":"b","a":0}`

	result, err := CanonicalizeBytes([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if result != expected {
		t.Errorf("JCS numeric key vector:\ngot:  %s\nwant: %s", result, expected)
	}
}

func TestSortedKeys(t *testing.T) {
	input := `{"z":1,"a":2,"m":3}`
	expected := `{"a":2,"m":3,"z":1}`

	result, err := CanonicalizeBytes([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if result != expected {
		t.Errorf("sorted keys:\ngot:  %s\nwant: %s", result, expected)
	}
}

func TestNestedObjects(t *testing.T) {
	input := `{"outer":{"inner":"value"}}`
	expected := `{"outer":{"inner":"value"}}`

	result, err := CanonicalizeBytes([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if result != expected {
		t.Errorf("nested objects:\ngot:  %s\nwant: %s", result, expected)
	}
}

func TestArrays(t *testing.T) {
	input := `[1,2,3]`
	expected := `[1,2,3]`

	result, err := CanonicalizeBytes([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if result != expected {
		t.Errorf("arrays:\ngot:  %s\nwant: %s", result, expected)
	}
}

func TestBoolNull(t *testing.T) {
	input := `{"a":true,"b":false,"c":null}`
	expected := `{"a":true,"b":false,"c":null}`

	result, err := CanonicalizeBytes([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if result != expected {
		t.Errorf("bool/null:\ngot:  %s\nwant: %s", result, expected)
	}
}

func TestUnicodePassthrough(t *testing.T) {
	// Unicode chars above U+001F should pass through unchanged
	input := map[string]string{"emoji": "\U0001F600"}
	result, err := Canonicalize(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "\U0001F600") {
		t.Error("emoji should pass through unchanged")
	}
}

func TestCanonicalHash(t *testing.T) {
	v1 := map[string]int{"z": 1, "a": 2}
	v2 := map[string]int{"a": 2, "z": 1}

	h1, err := CanonicalHash(v1)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := CanonicalHash(v2)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Error("same content with different key order should produce same hash")
	}
}

func TestDeterministic(t *testing.T) {
	input := `{"x":1,"y":2}`
	r1, err := CanonicalizeBytes([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := CanonicalizeBytes([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if r1 != r2 {
		t.Error("canonicalization should be deterministic")
	}
}

func TestLargeUint64Canonicalization(t *testing.T) {
	// 18446744073709551615 is math.MaxUint64, which exceeds int64 range
	// but fits in uint64. It must be preserved exactly, not converted to float64.
	input := `{"big":18446744073709551615}`
	expected := `{"big":18446744073709551615}`

	result, err := CanonicalizeBytes([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if result != expected {
		t.Errorf("large uint64:\ngot:  %s\nwant: %s", result, expected)
	}
}

func TestLargePositiveIntegerAboveInt64(t *testing.T) {
	// Value just above MaxInt64 (9223372036854775808)
	input := `{"val":9223372036854775808}`
	expected := `{"val":9223372036854775808}`

	result, err := CanonicalizeBytes([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if result != expected {
		t.Errorf("large int above int64:\ngot:  %s\nwant: %s", result, expected)
	}
}

func TestRejectTrailingJSONData(t *testing.T) {
	_, err := CanonicalizeBytes([]byte(`{"a":1}{"b":2}`))
	if err == nil {
		t.Fatal("expected error for trailing JSON data")
	}
}

func TestUTF16KeyOrderingForNonASCII(t *testing.T) {
	input := `{"":1,"𐐷":2}`
	expected := `{"𐐷":2,"":1}`

	result, err := CanonicalizeBytes([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if result != expected {
		t.Errorf("UTF-16 key ordering:\ngot:  %s\nwant: %s", result, expected)
	}
}
