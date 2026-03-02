// Package internal provides shared utilities for the hush-go SDK.
package internal

import (
	"path/filepath"
	"strings"
)

// DoubleStarMatch matches a path against a glob pattern that supports "**".
// Go's filepath.Match doesn't support "**", so this implements it.
//
// "**" matches zero or more path segments (directories).
// "*" matches any non-separator characters within a single segment.
func DoubleStarMatch(pattern, path string) bool {
	// Normalize separators
	pattern = filepath.ToSlash(pattern)
	path = filepath.ToSlash(path)

	return doubleStarMatch(pattern, path)
}

func doubleStarMatch(pattern, path string) bool {
	// Split pattern on "**"
	parts := strings.SplitN(pattern, "**", 2)
	if len(parts) == 1 {
		// No "**" — fall back to filepath.Match
		ok, _ := filepath.Match(pattern, path)
		return ok
	}

	prefix := parts[0]
	suffix := parts[1]

	// Remove leading separator from suffix (** absorbs it)
	suffix = strings.TrimPrefix(suffix, "/")

	// The prefix must match the beginning of the path
	if prefix != "" {
		prefix = strings.TrimSuffix(prefix, "/")
		if !strings.HasPrefix(path, prefix) {
			// Try glob match on prefix
			pathParts := strings.Split(path, "/")
			prefixParts := strings.Split(prefix, "/")
			if len(prefixParts) > len(pathParts) {
				return false
			}
			for i, pp := range prefixParts {
				ok, _ := filepath.Match(pp, pathParts[i])
				if !ok {
					return false
				}
			}
			// Advance path past prefix
			path = strings.Join(pathParts[len(prefixParts):], "/")
		} else {
			path = strings.TrimPrefix(path, prefix)
			path = strings.TrimPrefix(path, "/")
		}
	}

	// If suffix is empty, "**" matches everything remaining
	if suffix == "" {
		return true
	}

	// Try matching suffix at every possible position in the remaining path
	pathParts := strings.Split(path, "/")
	for i := 0; i <= len(pathParts); i++ {
		remaining := strings.Join(pathParts[i:], "/")
		if doubleStarMatch(suffix, remaining) {
			return true
		}
	}

	return false
}
