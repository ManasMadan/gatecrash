// Package webassets embeds the built progressive web apps into the binary.
//
// The scanner, the attendee wallet and the organizer dashboard are all served from
// the box itself. Nothing is fetched from a CDN, no font is loaded from Google, no
// script comes from anywhere but this file — because at the moment these are needed
// there is no internet, and an app that pauses to fetch a stylesheet is an app that
// shows a blank screen at a gate.
//
// Embedding rather than serving from disk keeps the single-binary promise: one file
// to scp, nothing to keep in step with it.
package webassets

import (
	"embed"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

// dist holds the built apps, populated by `pnpm build`. The .gitkeep inside it is
// what lets this compile in a fresh checkout before the web build has run: a Go
// build that fails because somebody has not run a JavaScript build is a hostile
// developer experience.
//
//go:embed all:dist
var dist embed.FS

// apps are the single-page apps served from their own path prefixes.
var apps = []string{"scanner", "attendee", "dashboard"}

// buildTime is the modification time reported for every embedded file.
//
// embed.FS reports a zero modification time, which makes Go's file server omit
// Last-Modified and skip conditional requests entirely. A fixed non-zero time
// restores caching without pretending the files are newer than they are; the hashed
// filenames are what actually make caching safe.
var buildTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Handler serves the built apps, or nil when the binary was built without them.
//
// Nil rather than a stub, so the API can tell the difference and fall back to its
// own minimal portal page. A box serving a broken app is worse than a box serving a
// plain one that works.
func Handler(log *slog.Logger) http.Handler {
	root, err := fs.Sub(dist, "dist")
	if err != nil {
		log.Warn("webassets: no built apps in this binary", "error", err)
		return nil
	}
	if entries, err := fs.ReadDir(root, "."); err != nil || len(entries) <= 1 {
		// One entry is the committed .gitkeep on its own, which means nothing was
		// built.
		log.Warn("webassets: this binary was built without the web apps; run `pnpm build` first")
		return nil
	}

	// Registered because Go's built-in table does not know it, and a manifest served
	// as text/plain is a manifest the browser ignores — which silently costs the
	// scanner its home-screen install and its fullscreen display mode.
	_ = mime.AddExtensionType(".webmanifest", "application/manifest+json")

	return &handler{root: root, log: log}
}

type handler struct {
	root fs.FS
	log  *slog.Logger
}

// ServeHTTP resolves a request to an embedded file.
//
// Written out rather than delegating to http.FileServerFS, which redirects in two
// places this cannot tolerate: it canonicalises `/scanner/index.html` to `./`, and
// it redirects a directory without a trailing slash. Combined with a single-page-app
// fallback, those turn into a redirect loop — `/scanner/` rewrites to index.html,
// which redirects back to `/scanner/`. Resolving the path here means no redirects at
// all, which is also one less round trip on a network that charges for every one.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// path.Clean resolves any "..", so a request for ../../etc/passwd cannot escape
	// the embedded tree. The tree is read-only and compiled in, but a traversal that
	// reads another app's files is still a bug worth not having.
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")

	// The root sends somebody to their ticket, which is what a person who typed the
	// box's address is looking for.
	if name == "" || name == "." {
		http.Redirect(w, r, "/attendee/", http.StatusFound)
		return
	}

	app, inApp := appOf(name)

	// A bare app prefix is its index.
	if inApp && (name == app || strings.HasSuffix(r.URL.Path, "/")) {
		if name == app {
			name = app + "/index.html"
		} else if !strings.HasSuffix(name, "index.html") {
			name = path.Join(name, "index.html")
		}
	}

	file, info, err := h.open(name)
	if err != nil {
		// Single-page apps own their own routing, so a path inside one that does not
		// exist on disk gets that app's index.html rather than a 404. Without this,
		// reloading the scanner on a deep link shows a 404.
		if inApp {
			if file, info, err = h.open(app + "/index.html"); err != nil {
				http.NotFound(w, r)
				return
			}
			name = app + "/index.html"
		} else {
			http.NotFound(w, r)
			return
		}
	}
	defer func() { _ = file.Close() }()

	// Hashed asset filenames are immutable, so they get a year. Everything else gets
	// nothing, because a stale index.html on a scanner is a scanner running last
	// week's build against this week's API.
	if strings.Contains(name, "/assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	if kind := mime.TypeByExtension(path.Ext(name)); kind != "" {
		w.Header().Set("Content-Type", kind)
	}

	seeker, ok := file.(io.ReadSeeker)
	if !ok {
		// Every file in an embed.FS is seekable; this is belt and braces so a future
		// change of backing store fails loudly rather than serving nothing.
		http.Error(w, "asset is not seekable", http.StatusInternalServerError)
		return
	}
	// ServeContent handles ranges, HEAD and conditional requests, which is the part
	// worth not reimplementing.
	http.ServeContent(w, r, path.Base(name), buildTime, seeker)
	_ = info
}

func (h *handler) open(name string) (fs.File, fs.FileInfo, error) {
	file, err := h.root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil || info.IsDir() {
		_ = file.Close()
		if err == nil {
			err = fs.ErrNotExist
		}
		return nil, nil, err
	}
	return file, info, nil
}

// appOf reports which single-page app a path belongs to.
func appOf(name string) (string, bool) {
	for _, app := range apps {
		if name == app || strings.HasPrefix(name, app+"/") {
			return app, true
		}
	}
	return "", false
}
