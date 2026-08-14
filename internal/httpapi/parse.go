package httpapi

import (
	"strconv"
	"strings"
)

// sscanInt64 parses a decimal integer, returning a count of items scanned so the
// call site reads like fmt.Sscan without pulling reflection into the hot path.
func sscanInt64(text string, into *int64) (int, error) {
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, err
	}
	*into = value
	return 1, nil
}

// parseUint reads an unsigned query parameter with a default.
func parseUint(text string, fallback uint64) uint64 {
	if text == "" {
		return fallback
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return fallback
	}
	return value
}

// parseInt reads a signed query parameter with a default and a ceiling.
//
// The ceiling exists because every one of these bounds a response size, and an
// unbounded limit parameter is how a phone gets handed fifty thousand rows.
func parseInt(text string, fallback, ceiling int) int {
	if text == "" {
		return fallback
	}
	value, err := strconv.Atoi(text)
	if err != nil || value <= 0 {
		return fallback
	}
	if value > ceiling {
		return ceiling
	}
	return value
}

// htmlEscape escapes the characters that matter when interpolating
// organizer-supplied text into the fallback portal page.
//
// Hand-rolled rather than html/template because there is exactly one
// interpolation into one fixed string, and the event name comes out of a manifest
// somebody else wrote.
func htmlEscape(s string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	).Replace(s)
}
