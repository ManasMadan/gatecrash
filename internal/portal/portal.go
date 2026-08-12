// Package portal intercepts operating-system connectivity probes so the venue's
// Wi-Fi pops a "sign in to network" sheet on join.
//
// This is the third rung of the discovery ladder and the one that works on
// devices whose owners will never type a URL. Every modern OS, on joining a
// network, fetches a known URL and checks the answer against a known value. If
// the answer is wrong, the OS concludes it is behind a captive portal and pushes
// a browser sheet to the user unprompted. That sheet is the best onboarding this
// product has: the attendee joins the Wi-Fi and their ticket appears.
//
// Getting all four families right is fiddly and undocumented, and each one fails
// differently when you get it wrong:
//
//	Android   GET /generate_204 on connectivitycheck.gstatic.com and friends,
//	          expecting a 204 with an empty body. Anything else means portal.
//	Apple     GET /hotspot-detect.html on captive.apple.com, expecting a body
//	          containing exactly "Success". Anything else means portal.
//	Windows   GET /connecttest.txt on www.msftconnecttest.com, expecting the body
//	          "Microsoft Connect Test", plus an NCSI DNS lookup the dnsd wildcard
//	          covers.
//	Firefox   GET /canonical.html on detectportal.firefox.com, expecting a
//	          specific meta-refresh document.
//
// Alongside the probe interception this serves RFC 8908's Captive Portal API,
// which is the standardised replacement for all of the above. Modern iOS and
// Android read it when DHCP option 114 points at it, and it lets the box say
// "you are behind a portal, here is the URL, you are not time-limited" in one
// JSON object instead of four hacks.
//
// Honest note: this is a portal that informs rather than authenticates. Nothing
// is gated behind it — the venue Wi-Fi is open or WPA3 at the radio layer, and
// the portal exists to hand out a link, not to check credentials. Pretending
// otherwise would be security theatre.
package portal

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// ProbeHosts are the hostnames whose connectivity probes get intercepted.
//
// Kept as a list rather than a suffix match because the box should intercept
// exactly these and nothing else: a suffix match on "google.com" would swallow
// every Google request on the network, which is both wrong and the kind of thing
// that makes an attendee think the venue Wi-Fi is malicious.
var ProbeHosts = []string{
	// Android and Chrome OS.
	"connectivitycheck.gstatic.com",
	"connectivitycheck.android.com",
	"clients3.google.com",
	"clients1.google.com",
	"android.clients.google.com",
	"www.gstatic.com",

	// Apple, iOS and macOS.
	"captive.apple.com",
	"www.appleiphonecell.com",
	"www.itools.info",
	"www.ibook.info",
	"www.airport.us",
	"www.thinkdifferent.us",

	// Windows NCSI.
	"www.msftconnecttest.com",
	"msftconnecttest.com",
	"www.msftncsi.com",
	"msftncsi.com",
	"ipv6.msftconnecttest.com",

	// Firefox.
	"detectportal.firefox.com",

	// Others seen in the wild: Ubuntu, Kindle, some smart TVs.
	"connectivity-check.ubuntu.com",
	"nmcheck.gnome.org",
	"spectrum.s3.amazonaws.com",
}

// ProbePaths are the paths that identify a probe when the Host header is missing
// or rewritten, which happens behind some transparent proxies and on devices that
// probe by IP.
var ProbePaths = []string{
	"/generate_204",
	"/gen_204",
	"/hotspot-detect.html",
	"/library/test/success.html",
	"/connecttest.txt",
	"/ncsi.txt",
	"/canonical.html",
	"/success.txt",
}

// Config configures the interceptor.
type Config struct {
	// PortalURL is where a probed device is sent. Typically the box's raw-IP
	// http:// URL, because a device that has not yet trusted the box's private CA
	// cannot open an https:// one, and a certificate warning at this moment reads
	// as "this network is attacking me".
	PortalURL string

	// VenueName appears in the API response and the fallback page.
	VenueName string

	// Enabled turns interception on. Off in router mode: intercepting probes on
	// somebody else's network is hijacking, and the box has no business doing it
	// when the venue's own infrastructure owns the network.
	Enabled bool

	Logger *slog.Logger
}

// Interceptor is an http.Handler middleware.
type Interceptor struct {
	cfg   Config
	log   *slog.Logger
	hosts map[string]bool
	paths map[string]bool
}

// New builds an interceptor.
func New(cfg Config) *Interceptor {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	hosts := make(map[string]bool, len(ProbeHosts))
	for _, host := range ProbeHosts {
		hosts[host] = true
	}
	paths := make(map[string]bool, len(ProbePaths))
	for _, path := range ProbePaths {
		paths[path] = true
	}
	return &Interceptor{cfg: cfg, log: logger, hosts: hosts, paths: paths}
}

// Middleware wraps a handler, answering probes and passing everything else
// through.
func (i *Interceptor) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if i.cfg.Enabled && i.IsProbe(r) {
			i.answerProbe(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// IsProbe reports whether a request is an operating-system connectivity probe.
func (i *Interceptor) IsProbe(r *http.Request) bool {
	// Probes are always GET or HEAD. A POST to a probe path is something else and
	// must not be swallowed.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if i.hosts[hostOf(r)] {
		return true
	}
	return i.paths[strings.ToLower(r.URL.Path)]
}

// hostOf returns the request's host without a port, lowercased.
func hostOf(r *http.Request) string {
	host := r.Host
	if r.URL != nil && r.URL.Host != "" {
		host = r.URL.Host
	}
	if colon := strings.LastIndex(host, ":"); colon > 0 && !strings.Contains(host[colon:], "]") {
		host = host[:colon]
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// answerProbe responds so the operating system concludes there is a portal.
//
// A 302 to the portal URL is the answer that works across the most devices. Every
// probe family treats a redirect as "not the expected response", and iOS and
// Android both follow it straight into the sheet. Returning a bare 200 with an
// error page also triggers detection but leaves some Android builds showing the
// page inside a stub browser with no address bar and no way to install the CA.
func (i *Interceptor) answerProbe(w http.ResponseWriter, r *http.Request) {
	i.log.Debug("portal: intercepted probe", "host", hostOf(r), "path", r.URL.Path, "agent", r.UserAgent())

	// No caching, ever. A cached probe response means the device believes it is
	// behind a portal long after it has left the venue, and vice versa.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	// RFC 8908: point at the API even on the legacy path, so a device that
	// understands it can skip the guesswork.
	w.Header().Set("Link", `<`+i.cfg.PortalURL+APIPath+`>; rel="captive-portal-api"`)
	w.Header().Set("Location", i.cfg.PortalURL)
	w.WriteHeader(http.StatusFound)

	if r.Method == http.MethodHead {
		return
	}
	// A body, because a handful of stub browsers render the redirect target's
	// body rather than following the redirect.
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8">` +
		`<meta http-equiv="refresh" content="0;url=` + htmlEscape(i.cfg.PortalURL) + `">` +
		`<title>` + htmlEscape(i.cfg.VenueName) + `</title>` +
		`<p><a href="` + htmlEscape(i.cfg.PortalURL) + `">Open ` + htmlEscape(i.cfg.VenueName) + `</a>`))
}

// APIPath is the RFC 8908 Captive Portal API endpoint.
const APIPath = "/captive-portal-api"

// APIResponse is the RFC 8908 JSON object.
//
// The field names are the wire names from the RFC, which is why they are hyphen
// separated and do not look like anything else in this codebase.
type APIResponse struct {
	// Captive says whether the device's traffic is being intercepted. False here
	// once the box is reachable, because nothing is actually gated: the portal
	// hands out a link, it does not authorise.
	Captive bool `json:"captive"`

	// UserPortalURL is where to send the user.
	UserPortalURL string `json:"user-portal-url,omitempty"`

	// VenueInfoURL is where to send them for information about the venue, which
	// for Gatecrash is the same page.
	VenueInfoURL string `json:"venue-info-url,omitempty"`

	// CanExtendSession tells the OS whether re-opening the portal can extend
	// access. Always false: there is no session to extend.
	CanExtendSession bool `json:"can-extend-session"`
}

// APIHandler serves the RFC 8908 endpoint.
//
// Captive is reported as false because by the time a device can reach this
// endpoint it can reach the box, and the box is the whole point of the network.
// Reporting true would make some operating systems keep the "no internet" warning
// up and keep nagging, which is worse for the attendee than the truth.
func (i *Interceptor) APIHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The RFC specifies this content type exactly, and at least one iOS
		// version ignores the response without it.
		w.Header().Set("Content-Type", "application/captive+json")
		w.Header().Set("Cache-Control", "no-store")

		body := APIResponse{
			Captive:          false,
			UserPortalURL:    i.cfg.PortalURL,
			VenueInfoURL:     i.cfg.PortalURL,
			CanExtendSession: false,
		}
		if err := json.NewEncoder(w).Encode(body); err != nil {
			i.log.Debug("portal: writing api response", "error", err)
		}
	})
}

// htmlEscape escapes the characters that matter in an attribute or text node.
//
// Hand-rolled rather than html/template because this is one interpolation into a
// fixed string, and pulling in the template machinery for a captive-portal stub
// would be the largest dependency in the file.
func htmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}
