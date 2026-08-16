// Package logx builds the box's logger.
//
// One decision worth stating: the box logs to stderr and nowhere else. No log
// file, no rotation, no logging framework. The SD card is treated as hostile
// media, and a process that writes a growing log file to it is a process that
// eventually corrupts the card and fills it at the same time. journald or the
// terminal owns the output; the box just writes lines.
package logx

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Options configure the logger.
type Options struct {
	// Level is debug, info, warn or error.
	Level string

	// JSON switches to structured output, which is what the systemd unit uses.
	// The human-readable default is for somebody with a serial cable at 2am.
	JSON bool

	// Out overrides the destination, for tests.
	Out io.Writer
}

// New builds a logger.
func New(opts Options) *slog.Logger {
	out := opts.Out
	if out == nil {
		out = os.Stderr
	}

	handlerOpts := &slog.HandlerOptions{Level: parseLevel(opts.Level)}
	if opts.JSON {
		return slog.New(slog.NewJSONHandler(out, handlerOpts))
	}
	return slog.New(slog.NewTextHandler(out, handlerOpts))
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
