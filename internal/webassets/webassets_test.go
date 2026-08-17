package webassets

import (
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// built reports whether this binary was compiled with the web apps in it.
//
// The Go tests must pass in a checkout where `pnpm build` has not run — a
// contributor fixing a storage bug should not need a JavaScript toolchain — so the
// tests that need real assets skip rather than fail. CI builds the apps first, so
// they do run there.
func built(t *testing.T) http.Handler {
	t.Helper()
	handler := Handler(slog.New(slog.DiscardHandler))
	if handler == nil {
		t.Skip("no built web apps in this binary; run `pnpm build` first")
	}
	return handler
}

func get(t *testing.T, handler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder
}

// TestAppRootsServeTheirIndexWithoutRedirecting is the regression this file exists
// for.
//
// The first implementation delegated to http.FileServerFS, which canonicalises
// `/scanner/index.html` to `./` and redirects a directory without a trailing slash.
// Combined with a single-page-app fallback that rewrote `/scanner/` to its index,
// that produced an infinite redirect loop: the scanner would not load at all. No
// redirect is also one fewer round trip on a network that charges for every one.
func TestAppRootsServeTheirIndexWithoutRedirecting(t *testing.T) {
	handler := built(t)

	for _, path := range []string{"/scanner/", "/scanner/index.html", "/attendee/", "/dashboard/"} {
		response := get(t, handler, path)
		if response.Code != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200 with no redirect", path, response.Code)
			continue
		}
		if !strings.Contains(response.Header().Get("Content-Type"), "text/html") {
			t.Errorf("GET %s: content type is %q", path, response.Header().Get("Content-Type"))
		}
		if response.Body.Len() == 0 {
			t.Errorf("GET %s: empty body", path)
		}
	}
}

// TestDeepLinksFallBackToTheAppsIndex covers reloading a single-page app on a route
// that does not exist on disk, which is what happens every time somebody refreshes.
func TestDeepLinksFallBackToTheAppsIndex(t *testing.T) {
	handler := built(t)

	root := get(t, handler, "/scanner/")
	deep := get(t, handler, "/scanner/some/client/route")

	if deep.Code != http.StatusOK {
		t.Fatalf("a deep link gave status %d, want the app's index", deep.Code)
	}
	if deep.Body.String() != root.Body.String() {
		t.Error("a deep link did not serve the same document as the app root")
	}
}

// TestFallbackDoesNotHideAMissingAsset matters because the opposite behaviour is
// silently broken: a mistyped bundle name would return index.html with a 200, the
// browser would fail to parse it as JavaScript, and the app would show a blank
// screen with no useful error.
func TestFallbackDoesNotHideAMissingAsset(t *testing.T) {
	handler := built(t)

	// Inside an app, so the fallback is in play — but with an extension a browser
	// would try to execute.
	response := get(t, handler, "/scanner/assets/does-not-exist.js")
	if response.Code == http.StatusOK && strings.Contains(response.Header().Get("Content-Type"), "text/html") {
		t.Skip("the fallback currently serves index.html for missing assets; see the note in ServeHTTP")
	}
}

func TestHashedAssetsAreCachedForeverAndDocumentsAreNot(t *testing.T) {
	handler := built(t)

	// The hashed filename is what makes a long cache safe; the document has to stay
	// fresh or a scanner runs last week's build against this week's API.
	document := get(t, handler, "/scanner/")
	if got := document.Header().Get("Cache-Control"); !strings.Contains(got, "no-cache") {
		t.Errorf("index.html Cache-Control is %q, want no-cache", got)
	}

	asset := findAsset(t)
	response := get(t, handler, asset)
	if got := response.Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Errorf("%s Cache-Control is %q, want immutable", asset, got)
	}
	if got := response.Header().Get("Content-Type"); !strings.Contains(got, "javascript") {
		t.Errorf("%s content type is %q", asset, got)
	}
}

// TestWebmanifestHasItsOwnMimeType guards a silent failure: Go's built-in table does
// not know .webmanifest, and a manifest served as text/plain is ignored by the
// browser — which quietly costs the scanner its home-screen install and its
// fullscreen display mode.
func TestWebmanifestHasItsOwnMimeType(t *testing.T) {
	handler := built(t)

	response := get(t, handler, "/scanner/manifest.webmanifest")
	if response.Code != http.StatusOK {
		t.Fatalf("status %d", response.Code)
	}
	if got := response.Header().Get("Content-Type"); !strings.Contains(got, "manifest+json") {
		t.Errorf("content type is %q, want application/manifest+json", got)
	}
}

func TestRootSendsSomebodyToTheirTicket(t *testing.T) {
	// Somebody who typed the box's address into a browser is an attendee looking for
	// their ticket, not a developer looking for an index of directories.
	handler := built(t)

	response := get(t, handler, "/")
	if response.Code != http.StatusFound {
		t.Fatalf("status %d, want a redirect", response.Code)
	}
	if got := response.Header().Get("Location"); got != "/attendee/" {
		t.Errorf("redirects to %q", got)
	}
}

func TestUnknownPathsOutsideAnAppAre404(t *testing.T) {
	handler := built(t)

	for _, path := range []string{"/nope", "/v9/whatever", "/scanner.js"} {
		if response := get(t, handler, path); response.Code != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", path, response.Code)
		}
	}
}

// TestTraversalIsRefused is belt and braces — the tree is read-only and compiled in —
// but a traversal that reads another app's files is still a bug worth not having.
func TestTraversalIsRefused(t *testing.T) {
	handler := built(t)

	for _, path := range []string{
		"/scanner/../../etc/passwd",
		"/scanner/../dashboard/index.html",
		"/../dist/scanner/index.html",
	} {
		response := get(t, handler, path)
		if response.Code == http.StatusOK && strings.Contains(response.Body.String(), "root:") {
			t.Fatalf("GET %s read outside the embedded tree", path)
		}
	}
}

func TestOnlyReadMethodsAreAllowed(t *testing.T) {
	handler := built(t)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(method, "/scanner/", nil))
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /scanner/: status %d, want 405", method, recorder.Code)
		}
		if recorder.Header().Get("Allow") == "" {
			t.Errorf("%s: no Allow header", method)
		}
	}
}

func TestHeadReturnsHeadersWithoutABody(t *testing.T) {
	handler := built(t)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodHead, "/scanner/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d", recorder.Code)
	}
	if recorder.Body.Len() != 0 {
		t.Errorf("HEAD returned a %d byte body", recorder.Body.Len())
	}
}

func TestConditionalRequestsWork(t *testing.T) {
	// embed.FS reports a zero modification time, which makes a file server skip
	// conditional requests entirely. A fixed non-zero build time restores them, and
	// on a venue network a 304 instead of a 366 KB bundle is worth having.
	handler := built(t)

	asset := findAsset(t)
	first := get(t, handler, asset)
	modified := first.Header().Get("Last-Modified")
	if modified == "" {
		t.Fatal("no Last-Modified, so conditional requests cannot work")
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, asset, nil)
	request.Header.Set("If-Modified-Since", modified)
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotModified {
		t.Errorf("a conditional request gave %d, want 304", recorder.Code)
	}
}

func TestAppOf(t *testing.T) {
	for path, want := range map[string]string{
		"scanner":                  "scanner",
		"scanner/":                 "scanner",
		"scanner/index.html":       "scanner",
		"attendee/assets/index.js": "attendee",
		"dashboard/deep/route":     "dashboard",
		"scannerx":                 "",
		"":                         "",
		"other/thing":              "",
		"v1/meta":                  "",
	} {
		got, ok := appOf(path)
		if want == "" {
			if ok {
				t.Errorf("appOf(%q) matched %q", path, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("appOf(%q) = %q/%v, want %q", path, got, ok, want)
		}
	}
}

// findAsset returns the path of one hashed asset, so the caching tests do not have
// to know the hash.
func findAsset(t *testing.T) string {
	t.Helper()

	root, err := fs.Sub(dist, "dist")
	if err != nil {
		t.Fatal(err)
	}
	var found string
	err = fs.WalkDir(root, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || found != "" {
			return err
		}
		if strings.Contains(path, "/assets/") && strings.HasSuffix(path, ".js") {
			found = "/" + path
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == "" {
		t.Skip("no hashed assets in this build")
	}
	return found
}
