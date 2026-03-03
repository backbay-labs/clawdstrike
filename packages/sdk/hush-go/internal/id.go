package internal

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

const idChars = "0123456789abcdefghijklmnopqrstuvwxyz"

// CreateID generates a unique identifier with the given prefix.
// Format: prefix_timestamp36_random6
func CreateID(prefix string) string {
	ts := strconv.FormatInt(time.Now().UnixMilli(), 36)
	rnd := randomAlphanumeric(6)
	return fmt.Sprintf("%s_%s_%s", prefix, ts, rnd)
}

func randomAlphanumeric(n int) string {
	max := big.NewInt(int64(len(idChars)))
	var sb strings.Builder
	sb.Grow(n)
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			// Fallback: use zero index on error (fail-closed: still produce an ID)
			sb.WriteByte(idChars[0])
			continue
		}
		sb.WriteByte(idChars[idx.Int64()])
	}
	return sb.String()
}
