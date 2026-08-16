//go:build !unix

package main

import "errors"

// diskFree is unavailable off Unix. The box runs on Linux; this stub exists so the
// binary still builds on a developer's Windows machine.
func diskFree(string) (free, total uint64, err error) {
	return 0, 0, errors.New("not supported on this platform")
}
