// Package webassets embeds the built progressive web apps into the binary.
//
// The scanner, the attendee wallet and the organizer dashboard are all served from
// the box itself. Nothing is fetched from a CDN, no font is loaded from Google, no
// script comes from anywhere but this file — because at the moment these are
// needed there is no internet, and an app that pauses to fetch a stylesheet is an
// app that shows a blank screen at a gate.
//
// Embedding rather than serving from disk keeps the single-binary promise: one file
// to scp, nothing to keep in step with it.
package webassets

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// dist holds the built apps. The directory is populated by `pnpm build`, and the
// .gitkeep is there so this compiles in a fresh checkout before the web build has
// run: a Go build that fails because somebody has not run a JavaScript build is a
// hostile developer experience.
//
//go:embed all:dist
var dist embed.FS

// Handler serves the built apps, or nil when the binary was built without them.
//
// Nil rather than a stub, so the API can tell the difference and fall back to its
// own minimal portal page. A box serving a broken app is worse than a box serving
// a plain one that works.
func Handler(log *slog.Logger) http.Handler {
	root, err := fs.Sub(dist, "dist")
	if err != nil {
		log.Warn("webassets: no built apps in this binary", "error", err)
		return nil
	}
	if entries, err := fs.ReadDir(root, "."); err != nil || len(entries) == 0 {
		log.Warn("webassets: this binary was built without the web apps; run `pnpm build` first")
		return nil
	}

	files := http.FileServerFS(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")

		// Hashed asset filenames are immutable, so they get a year. Everything
		// else gets nothing, because a stale index.html on a scanner is a scanner
		// running last week's build against this week's API.
		if strings.Contains(path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}

		// Single-page apps own their own routing, so a request for a path inside
		// one that does not exist on disk gets that app's index.html rather than a
		// 404. Without this, reloading the scanner on /scanner/gun shows a 404.
		if app, ok := singlePageApp(path); ok {
			if _, err := fs.Stat(root, path); err != nil {
				r = r.Clone(r.Context())
				r.URL.Path = "/" + app + "/index.html"
			}
		}
		files.ServeHTTP(w, r)
	})
}

// singlePageApp reports which app a path belongs to.
func singlePageApp(path string) (string, bool) {
	for _, app := range []string{"scanner", "attendee", "dashboard"} {
		if path == app || strings.HasPrefix(path, app+"/") {
			return app, true
		}
	}
	return "", false
}

// BuildTime is the modification time reported for embedded files.
//
// embed.FS reports a zero modification time, which makes Go's file server omit
// Last-Modified and skip conditional requests entirely. A fixed non-zero time
// restores caching without pretending the files are newer than they are.
var BuildTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
