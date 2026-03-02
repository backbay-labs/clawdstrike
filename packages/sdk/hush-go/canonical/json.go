// Package canonical implements RFC 8785 (JCS) canonical JSON serialization.
// This ensures byte-for-byte identical output across Rust/Python/TS/Go.
package canonical

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/backbay/clawdstrike-go/crypto"
)

// Canonicalize serializes a value to canonical JSON per RFC 8785.
// Object keys are sorted lexicographically, no whitespace, numbers follow
// ECMAScript JSON.stringify() semantics.
func Canonicalize(v interface{}) (string, error) {
	// First marshal to get a serde_json::Value equivalent
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("canonical: marshal: %w", err)
	}

	// Parse into raw representation
	var raw interface{}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return "", fmt.Errorf("canonical: decode: %w", err)
	}

	var buf strings.Builder
	if err := canonicalWrite(&buf, raw); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// CanonicalizeBytes is like Canonicalize but accepts raw JSON bytes.
func CanonicalizeBytes(data []byte) (string, error) {
	var raw interface{}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return "", fmt.Errorf("canonical: decode: %w", err)
	}

	var buf strings.Builder
	if err := canonicalWrite(&buf, raw); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// CanonicalHash computes SHA-256 of the canonical JSON form.
func CanonicalHash(v interface{}) (crypto.Hash, error) {
	s, err := Canonicalize(v)
	if err != nil {
		return crypto.Hash{}, err
	}
	return crypto.SHA256([]byte(s)), nil
}

func canonicalWrite(buf *strings.Builder, v interface{}) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		return canonicalWriteNumber(buf, val)
	case string:
		canonicalWriteString(buf, val)
	case []interface{}:
		buf.WriteByte('[')
		for i, elem := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonicalWrite(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			canonicalWriteString(buf, k)
			buf.WriteByte(':')
			if err := canonicalWrite(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical: unsupported type %T", v)
	}
	return nil
}

func canonicalWriteNumber(buf *strings.Builder, n json.Number) error {
	s := n.String()

	// Try integer first
	if i, err := n.Int64(); err == nil {
		// Check that the string representation matches (no decimal point)
		if strconv.FormatInt(i, 10) == s {
			buf.WriteString(s)
			return nil
		}
	}

	// Float
	f, err := n.Float64()
	if err != nil {
		return fmt.Errorf("canonical: invalid number %q: %w", s, err)
	}

	result, err := canonicalizeFloat(f)
	if err != nil {
		return err
	}
	buf.WriteString(result)
	return nil
}

// canonicalizeFloat formats a float per JCS / ECMAScript JSON.stringify() rules.
func canonicalizeFloat(v float64) (string, error) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "", fmt.Errorf("canonical: non-finite numbers are not valid JSON")
	}

	// Normalize -0 to 0
	if v == 0 {
		return "0", nil
	}

	abs := math.Abs(v)
	sign := ""
	if v < 0 {
		sign = "-"
	}

	useExponential := abs < 1e-6 || abs >= 1e21

	// Use strconv.FormatFloat with 'e' for scientific or 'f' for decimal,
	// but we need shortest representation. Use 'g' as a base, then reformat.
	// Actually, ECMAScript uses a specific algorithm. Let's use the ryu-like approach.

	// Get the shortest decimal representation
	digits, exp := shortestDecimal(abs)

	if useExponential {
		mantissa := digits
		if len(mantissa) > 1 {
			mantissa = mantissa[:1] + "." + mantissa[1:]
		}
		expSign := "+"
		if exp < 0 {
			expSign = ""
		}
		return fmt.Sprintf("%s%se%s%d", sign, mantissa, expSign, exp), nil
	}

	rendered := renderDecimal(digits, exp)
	return sign + rendered, nil
}

// shortestDecimal returns the significant digits and the scientific exponent
// such that value = 0.digits * 10^(exp+1)
func shortestDecimal(abs float64) (string, int) {
	// Use Go's strconv with -1 precision for shortest representation
	s := strconv.FormatFloat(abs, 'e', -1, 64)

	// Parse the 'e' format: "1.234e+05" or "1e+00"
	parts := strings.SplitN(s, "e", 2)
	mantissa := parts[0]
	expStr := parts[1]

	exp, _ := strconv.Atoi(expStr)

	// Extract digits from mantissa (remove the dot)
	digits := strings.Replace(mantissa, ".", "", 1)
	// Remove trailing zeros from digits
	digits = strings.TrimRight(digits, "0")
	if digits == "" {
		digits = "0"
	}

	return digits, exp
}

// renderDecimal renders digits with scientific exponent into decimal form.
func renderDecimal(digits string, sciExp int) string {
	digitsLen := len(digits)
	// Number of digits to left of decimal = sciExp + 1
	leftOfDot := sciExp + 1

	if leftOfDot >= digitsLen {
		// All digits are left of dot, may need trailing zeros
		trailing := leftOfDot - digitsLen
		return digits + strings.Repeat("0", trailing)
	}

	if leftOfDot > 0 {
		// Split digits at leftOfDot position
		result := digits[:leftOfDot] + "." + digits[leftOfDot:]
		return trimTrailingDecimalZeros(result)
	}

	// leftOfDot <= 0: need leading "0." with zeros
	leadingZeros := -leftOfDot
	result := "0." + strings.Repeat("0", leadingZeros) + digits
	return trimTrailingDecimalZeros(result)
}

func trimTrailingDecimalZeros(s string) string {
	if !strings.Contains(s, ".") {
		return s
	}
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	return s
}

func canonicalWriteString(buf *strings.Builder, s string) {
	buf.WriteByte('"')
	for _, c := range s {
		switch c {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if c < 0x20 {
				buf.WriteString(fmt.Sprintf(`\u%04x`, c))
			} else {
				buf.WriteRune(c)
			}
		}
	}
	buf.WriteByte('"')
}
