package portal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newInterceptor(enabled bool) *Interceptor {
	return New(Config{
		PortalURL: "http://10.11.0.1/portal",
		VenueName: "Sundown Sessions",
		Enabled:   enabled,
	})
}

// probe issues a request through the middleware.
func probe(t *testing.T, i *Interceptor, method, host, path string) *httptest.ResponseRecorder {
	t.Helper()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot) // a marker: the request fell through
	})
	req := httptest.NewRequest(method, "http://"+host+path, nil)
	req.Host = host
	rec := httptest.NewRecorder()
	i.Middleware(next).ServeHTTP(rec, req)
	return rec
}

// TestEveryProbeFamilyIsIntercepted is the whole point of the package. Each of
// these hosts belongs to an operating system that will pop a browser sheet if the
// answer is not what it expects, and each fails differently when it is missed.
func TestEveryProbeFamilyIsIntercepted(t *testing.T) {
	i := newInterceptor(true)

	for _, tc := range []struct{ family, host, path string }{
		{"Android", "connectivitycheck.gstatic.com", "/generate_204"},
		{"Android alt", "clients3.google.com", "/generate_204"},
		{"Chrome OS", "connectivitycheck.android.com", "/generate_204"},
		{"iOS", "captive.apple.com", "/hotspot-detect.html"},
		{"macOS", "captive.apple.com", "/library/test/success.html"},
		{"iOS legacy", "www.appleiphonecell.com", "/"},
		{"Windows NCSI", "www.msftconnecttest.com", "/connecttest.txt"},
		{"Windows NCSI legacy", "www.msftncsi.com", "/ncsi.txt"},
		{"Firefox", "detectportal.firefox.com", "/canonical.html"},
		{"Ubuntu", "connectivity-check.ubuntu.com", "/"},
		{"GNOME", "nmcheck.gnome.org", "/"},
	} {
		rec := probe(t, i, http.MethodGet, tc.host, tc.path)
		if rec.Code != http.StatusFound {
			t.Errorf("%s (%s%s): status %d, want 302", tc.family, tc.host, tc.path, rec.Code)
			continue
		}
		if got := rec.Header().Get("Location"); got != "http://10.11.0.1/portal" {
			t.Errorf("%s: Location is %q", tc.family, got)
		}
		// A cached probe response means the device believes it is behind a portal
		// long after leaving the venue, and vice versa.
		if !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
			t.Errorf("%s: probe response is cacheable: %q", tc.family, rec.Header().Get("Cache-Control"))
		}
		// The Link header points a modern OS at the standardised API so it can
		// skip the guesswork entirely.
		if link := rec.Header().Get("Link"); !strings.Contains(link, `rel="captive-portal-api"`) {
			t.Errorf("%s: no captive-portal-api Link header: %q", tc.family, link)
		}
	}
}

func TestProbePathsAreInterceptedEvenWithoutTheHost(t *testing.T) {
	// Happens behind transparent proxies and on devices that probe by IP.
	i := newInterceptor(true)
	for _, path := range ProbePaths {
		rec := probe(t, i, http.MethodGet, "10.11.0.1", path)
		if rec.Code != http.StatusFound {
			t.Errorf("path %s: status %d, want 302", path, rec.Code)
		}
	}
}

func TestNormalTrafficFallsThrough(t *testing.T) {
	i := newInterceptor(true)

	for _, tc := range []struct{ host, path string }{
		{"10.11.0.1", "/"},
		{"go.gate", "/v1/manifest"},
		{"gate.local", "/scanner/"},
		{"gate.local", "/attendee/"},
		// A host that merely resembles a probe host must not be swallowed. A
		// suffix match on "google.com" would eat every Google request on the
		// network, which is both wrong and makes the Wi-Fi look malicious.
		{"www.google.com", "/search"},
		{"mail.google.com", "/"},
		{"notcaptive.apple.com", "/"},
	} {
		rec := probe(t, i, http.MethodGet, tc.host, tc.path)
		if rec.Code != http.StatusTeapot {
			t.Errorf("%s%s was intercepted (status %d), want to fall through", tc.host, tc.path, rec.Code)
		}
	}
}

func TestOnlyGetAndHeadAreIntercepted(t *testing.T) {
	// A POST to a probe path is something else and must not be swallowed.
	i := newInterceptor(true)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rec := probe(t, i, method, "connectivitycheck.gstatic.com", "/generate_204")
		if rec.Code != http.StatusTeapot {
			t.Errorf("%s was intercepted", method)
		}
	}
	// HEAD is intercepted but carries no body.
	rec := probe(t, i, http.MethodHead, "captive.apple.com", "/hotspot-detect.html")
	if rec.Code != http.StatusFound {
		t.Errorf("HEAD status is %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD response carries a %d byte body", rec.Body.Len())
	}
}

// TestDisabledInRouterMode matters ethically as much as technically:
// intercepting probes on somebody else's network is hijacking, and the box has no
// business doing it when the venue's own infrastructure owns the network.
func TestDisabledInRouterMode(t *testing.T) {
	i := newInterceptor(false)
	for _, host := range ProbeHosts {
		rec := probe(t, i, http.MethodGet, host, "/generate_204")
		if rec.Code != http.StatusTeapot {
			t.Errorf("%s was intercepted with interception disabled", host)
		}
	}
}

func TestHostMatchingIgnoresPortAndCaseAndTrailingDot(t *testing.T) {
	i := newInterceptor(true)
	for _, host := range []string{
		"connectivitycheck.gstatic.com",
		"connectivitycheck.gstatic.com:80",
		"CONNECTIVITYCHECK.GSTATIC.COM",
		"connectivitycheck.gstatic.com.",
		"ConnectivityCheck.GStatic.com:8080",
	} {
		rec := probe(t, i, http.MethodGet, host, "/generate_204")
		if rec.Code != http.StatusFound {
			t.Errorf("host %q was not intercepted", host)
		}
	}
}

func TestBodyCarriesAMetaRefreshForStubBrowsers(t *testing.T) {
	// A handful of stub browsers render the redirect target's body rather than
	// following the redirect.
	i := newInterceptor(true)
	rec := probe(t, i, http.MethodGet, "captive.apple.com", "/hotspot-detect.html")
	body := rec.Body.String()

	if !strings.Contains(body, "http-equiv=\"refresh\"") {
		t.Error("no meta refresh in the probe response body")
	}
	if !strings.Contains(body, "http://10.11.0.1/portal") {
		t.Error("the portal URL is missing from the body")
	}
	if !strings.Contains(body, "Sundown Sessions") {
		t.Error("the venue name is missing from the body")
	}
	// Apple's probe expects a body containing exactly "Success". Ours must not,
	// or iOS concludes there is internet and never shows the sheet.
	if strings.Contains(body, "Success") {
		t.Error(`the probe response contains "Success", which tells iOS there is no portal`)
	}
}

func TestVenueNameIsEscaped(t *testing.T) {
	// The venue name comes out of a manifest an organizer wrote, and it lands in
	// an HTML attribute.
	i := New(Config{
		PortalURL: `http://10.11.0.1/portal?a=1&b=2`,
		VenueName: `Ram"s <script>alert(1)</script> Party`,
		Enabled:   true,
	})
	rec := probe(t, i, http.MethodGet, "captive.apple.com", "/hotspot-detect.html")
	body := rec.Body.String()

	if strings.Contains(body, "<script>") {
		t.Fatal("the venue name was interpolated unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("the venue name was not escaped")
	}
	if strings.Contains(body, `?a=1&b=2"`) {
		t.Error("the portal URL's ampersand was not escaped inside the attribute")
	}
}

func TestCaptivePortalAPI(t *testing.T) {
	i := newInterceptor(true)
	rec := httptest.NewRecorder()
	i.APIHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, APIPath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	// The RFC specifies this content type exactly, and at least one iOS version
	// ignores the response without it.
	if got := rec.Header().Get("Content-Type"); got != "application/captive+json" {
		t.Errorf("Content-Type is %q, want application/captive+json", got)
	}

	var body APIResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	// Reported as not captive: by the time a device can reach this endpoint it
	// can reach the box, and the box is the point of the network. Reporting true
	// keeps the "no internet" warning up and keeps nagging.
	if body.Captive {
		t.Error("the API reports the network as captive, which keeps the OS nagging")
	}
	if body.UserPortalURL != "http://10.11.0.1/portal" {
		t.Errorf("user-portal-url is %q", body.UserPortalURL)
	}
	if body.CanExtendSession {
		t.Error("can-extend-session is true, but there is no session to extend")
	}

	// The field names are the RFC's wire names, which do not match Go
	// conventions and must not be renamed by accident.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"captive", "user-portal-url", "venue-info-url", "can-extend-session"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("the API response is missing the %q field", field)
		}
	}
}

func TestIsProbeIsCheapAndDoesNotPanicOnOddRequests(t *testing.T) {
	i := newInterceptor(true)
	for _, host := range []string{"", ":", "[::1]", "[::1]:8443", "....", strings.Repeat("a", 300)} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		_ = i.IsProbe(req)
	}
}

func BenchmarkIsProbeMiss(b *testing.B) {
	i := newInterceptor(true)
	req := httptest.NewRequest(http.MethodGet, "http://go.gate/v1/scan", nil)
	req.Host = "go.gate"

	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		if i.IsProbe(req) {
			b.Fatal("false positive")
		}
	}
}
