package threatintel

import (
	"errors"
	"fmt"
)

// availability.go — the distinction between "asked, and the answer was nothing"
// and "could not ask".
//
// Every provider used to collapse both into a bare `false`. A rate-limited
// VirusTotal call, a DNS blip and a genuinely unknown hash produced identical
// results, and enrichOne then cached that emptiness for 24 hours. Since the free
// VirusTotal tier allows four requests a minute while Enrich fires fifteen
// lookups three at a time, being throttled is the NORMAL case — so indicators
// the system never actually checked were being remembered for a day as though
// they had come back clean. Nothing in the output said otherwise.
//
// Splitting the two states is what lets the cache have two policies and the UI
// tell an analyst which sources were actually consulted.

// errNotApplicable means the source has nothing to say about this indicator
// type, or is not configured. It is not a failure and is never reported.
var errNotApplicable = errors.New("source not applicable")

// sourceError marks a source that could not be consulted. The source name is
// kept so the result can name what is missing rather than saying "some data may
// be absent".
type sourceError struct {
	Source string
	Reason string
}

func (e *sourceError) Error() string { return e.Source + ": " + e.Reason }

func unavailable(source string, err error) error {
	return &sourceError{Source: source, Reason: err.Error()}
}

func unavailableStatus(source string, status int) error {
	reason := fmt.Sprintf("HTTP %d", status)
	switch status {
	case 429:
		reason = "rate limited (HTTP 429)"
	case 401, 403:
		reason = fmt.Sprintf("credentials rejected (HTTP %d)", status)
	case 500, 502, 503, 504:
		reason = fmt.Sprintf("service error (HTTP %d)", status)
	}
	return &sourceError{Source: source, Reason: reason}
}

// asSourceError reports whether err marks an unavailable source, and names it.
func asSourceError(err error) (*sourceError, bool) {
	var se *sourceError
	if errors.As(err, &se) {
		return se, true
	}
	return nil, false
}
