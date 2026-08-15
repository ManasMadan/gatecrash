// Package httpapi is the box's HTTP surface: the scanner API, the attendee API,
// the organizer dashboard API, and the discovery endpoints that make a phone find
// all of it without typing anything.
//
// Three audiences share one server on one port, separated by authentication
// rather than by process. That is deliberate: a second listener would be a second
// certificate, a second port to get through a venue's firewall, and a second thing
// to forget to start. The box is one binary and it serves one port.
//
// The shape of the API is dictated by what happens when the network is bad, which
// at a venue is always. Every write carries a client-generated idempotency key, so
// a retry is free. Every read that a scanner depends on is resumable from a
// sequence, so a reconnect is cheap. Nothing requires more than one round trip on
// the critical path, because the critical path is a person standing at a gate.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/enroll"
	"github.com/ManasMadan/gatecrash/internal/incident"
	"github.com/ManasMadan/gatecrash/internal/manifest"
	"github.com/ManasMadan/gatecrash/internal/pki"
	"github.com/ManasMadan/gatecrash/internal/portal"
	"github.com/ManasMadan/gatecrash/internal/ssehub"
	"github.com/ManasMadan/gatecrash/internal/stats"
	"github.com/ManasMadan/gatecrash/internal/store"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
	"github.com/ManasMadan/gatecrash/internal/version"
)

// Deps are everything the API needs. Assembled by the box's main and passed in
// whole, so the API has no idea how any of it was built and the tests can hand it
// fakes.
type Deps struct {
	Engine   *engine.Engine
	Store    *store.Store
	Venue    *venue.Venue
	Stats    *stats.Tracker
	Board    *incident.Board
	Registry *enroll.Registry
	Hub      *ssehub.Hub
	CA       *pki.Authority
	Portal   *portal.Interceptor

	// Event is the metadata every client displays.
	Event manifest.Event

	// Master is the event master key, used to hand an attendee their own ticket
	// secret once, over TLS, when they claim a rotating ticket.
	Master ticket.MasterKey

	// BoxKey is the box's own signing key, used to sign the post-event attendance
	// report. Distinct from the organizer key: the organizer says who may come in,
	// the box says who actually did, and a settlement dispute needs those to be
	// separately attributable.
	//
	// The zero key is valid and means the export is unsigned, which is fine for a
	// box that is not being asked to settle anything.
	BoxKey ticket.SigningKey

	// AdminToken authenticates the organizer dashboard. Generated at boot and
	// printed on the console, so it exists even when nobody configured one.
	AdminToken string

	// BoxURL is the box's own base URL, embedded in enrollment QRs.
	BoxURL string

	// Assets serves the built PWAs. Nil in tests.
	Assets http.Handler

	// Now is the box's clock.
	Now func() time.Time

	Logger *slog.Logger
}

// API is the assembled HTTP surface.
type API struct {
	deps Deps
	log  *slog.Logger

	// limiter rate-limits per device, so one misbehaving scanner cannot flood the
	// box.
	limiter *limiter

	// announced is the organizer's message feed.
	//
	// In memory and append-only. Announcements are ephemeral by nature — "gate 4
	// is now open" means nothing an hour later — so persisting them would be
	// storing something whose value expires faster than the storage. A box that
	// reboots mid-event loses the feed and the organizer re-sends anything that
	// still matters, which takes one tap.
	announceMu sync.RWMutex
	announced  []Announcement
}

// New builds the API.
func New(deps Deps) (*API, error) {
	switch {
	case deps.Engine == nil:
		return nil, errors.New("httpapi: no engine")
	case deps.Store == nil:
		return nil, errors.New("httpapi: no store")
	case deps.Venue == nil:
		return nil, errors.New("httpapi: no venue")
	case deps.Registry == nil:
		return nil, errors.New("httpapi: no enrollment registry")
	case deps.Hub == nil:
		return nil, errors.New("httpapi: no sse hub")
	case deps.AdminToken == "":
		return nil, errors.New("httpapi: no admin token")
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Logger == nil {
		deps.Logger = slog.New(slog.DiscardHandler)
	}
	if deps.Stats == nil {
		deps.Stats = stats.New(stats.Config{Venue: deps.Venue, Now: deps.Now})
	}
	return &API{deps: deps, log: deps.Logger, limiter: newLimiter(deps.Now)}, nil
}

// Handler returns the routed handler.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	// Discovery and public metadata. No authentication: a device that has not
	// enrolled yet needs to be able to find out what this box is, and none of
	// this says anything an attacker on the venue Wi-Fi does not already know.
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /v1/meta", a.meta)
	mux.HandleFunc("GET /v1/time", a.boxTime)
	mux.HandleFunc("GET /ca.crt", a.caCertificate)
	mux.HandleFunc("GET /v1/venue", a.venuePlan)

	// Enrollment. Unauthenticated by design: the single-use code in the request
	// body *is* the authentication, and it arrived on paper in the hands of the
	// person allowed to grant it.
	mux.HandleFunc("POST /v1/enroll", a.enrollDevice)

	// Scanner API.
	mux.Handle("GET /v1/manifest", a.device(a.scannerManifest))
	mux.Handle("GET /v1/stream", a.device(a.scannerStream))
	mux.Handle("POST /v1/scan", a.device(a.scan))
	mux.Handle("POST /v1/incidents", a.device(a.raiseIncident))
	mux.Handle("GET /v1/incidents", a.device(a.listIncidentsForGate))
	mux.Handle("GET /v1/guidance", a.device(a.guidanceForTicket))

	// Attendee API. Authenticated by knowing a ticket id, which is 128 bits of
	// random and is the only credential an attendee has. Stated plainly in the
	// docs: an attendee who shares their ticket id shares their ticket.
	mux.HandleFunc("GET /v1/ticket/{id}", a.attendeeTicket)
	mux.HandleFunc("POST /v1/ticket/{id}/claim", a.claimTicket)
	mux.HandleFunc("GET /v1/ticket/{id}/nearby", a.attendeeNearby)
	mux.HandleFunc("GET /v1/announcements", a.announcements)

	// Organizer dashboard.
	mux.Handle("GET /v1/admin/stats", a.admin(a.adminStats))
	mux.Handle("GET /v1/admin/stream", a.admin(a.adminStream))
	mux.Handle("GET /v1/admin/incidents", a.admin(a.adminIncidents))
	mux.Handle("POST /v1/admin/incidents/{id}", a.admin(a.adminTransitionIncident))
	mux.Handle("POST /v1/admin/invite", a.admin(a.adminInvite))
	mux.Handle("GET /v1/admin/devices", a.admin(a.adminDevices))
	mux.Handle("POST /v1/admin/devices/{id}/revoke", a.admin(a.adminRevokeDevice))
	mux.Handle("POST /v1/admin/tickets/{id}/revoke", a.admin(a.adminRevokeTicket))
	mux.Handle("POST /v1/admin/announce", a.admin(a.adminAnnounce))
	mux.Handle("POST /v1/admin/seal", a.admin(a.adminSeal))
	mux.Handle("GET /v1/admin/verify", a.admin(a.adminVerify))
	mux.Handle("GET /v1/admin/attendance/{id}", a.admin(a.adminAttendance))
	mux.Handle("GET /v1/admin/export", a.admin(a.adminExport))
	mux.Handle("GET /v1/admin/flags", a.admin(a.adminFlags))
	mux.Handle("GET /v1/admin/log", a.admin(a.adminLog))

	// The captive portal API and page.
	if a.deps.Portal != nil {
		mux.Handle("GET "+portal.APIPath, a.deps.Portal.APIHandler())
	}
	mux.HandleFunc("GET /portal", a.portalPage)

	// The built PWAs, and the root, last so every API route wins.
	if a.deps.Assets != nil {
		mux.Handle("/", a.deps.Assets)
	} else {
		mux.HandleFunc("/", a.root)
	}

	var handler http.Handler = mux
	// The portal interceptor sits outermost so it sees connectivity probes before
	// routing turns them into 404s.
	if a.deps.Portal != nil {
		handler = a.deps.Portal.Middleware(handler)
	}
	return a.withCommonHeaders(a.withLogging(handler))
}

// withLogging records every request at debug level and slow ones at info.
//
// Slow is defined against the gate's latency budget rather than a round number:
// anything over 150ms on a scan is worth knowing about, because that is the
// published p99 and a queue is forming behind it.
func (a *API) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := a.deps.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)

		elapsed := a.deps.Now().Sub(start)
		attrs := []any{
			"method", r.Method, "path", r.URL.Path,
			"status", recorder.status, "duration", elapsed,
		}
		switch {
		case recorder.status >= 500:
			a.log.Error("http", attrs...)
		case elapsed > 150*time.Millisecond && strings.HasPrefix(r.URL.Path, "/v1/scan"):
			a.log.Warn("http: slow scan", attrs...)
		default:
			a.log.Debug("http", attrs...)
		}
	})
}

// statusRecorder captures the status code for logging.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (s *statusRecorder) WriteHeader(status int) {
	if !s.written {
		s.status = status
		s.written = true
	}
	s.ResponseWriter.WriteHeader(status)
}

// Flush forwards to the wrapped writer so SSE keeps working through the
// middleware. Without this the hub's flushes silently stop happening and every
// stream buffers until it closes.
func (s *statusRecorder) Flush() {
	if flusher, ok := s.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// withCommonHeaders sets the headers every response carries.
func (a *API) withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The box serves its own origins only and has no third-party content, so
		// a restrictive policy costs nothing and closes off script injection
		// through, say, an organizer's event name.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Server", "gatecrash/"+version.APIVersion)

		// The scanner and attendee apps are served from the same origin as the
		// API, so no CORS is needed for them. It is allowed for GET on the public
		// metadata endpoints only, so a developer can poke at a box from a laptop
		// without turning the whole API into a cross-origin target.
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/meta") {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		next.ServeHTTP(w, r)
	})
}

// Serve runs the HTTPS server until the context is cancelled.
func (a *API) Serve(ctx context.Context, addr string) error {
	server := &http.Server{
		Addr:    addr,
		Handler: a.Handler(),
		// No write timeout: SSE streams are long-lived by definition and a write
		// timeout would kill every scanner's delta stream on a schedule.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if a.deps.CA != nil {
		server.TLSConfig = a.deps.CA.ServerTLS()
	}

	errs := make(chan error, 1)
	go func() {
		if server.TLSConfig != nil {
			errs <- server.ListenAndServeTLS("", "")
			return
		}
		errs <- server.ListenAndServe()
	}()

	select {
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		// Ten seconds of grace, which is enough for an in-flight scan to finish
		// and not so long that a restart during doors feels broken.
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}

// ServePlain runs an HTTP server, used for the redirect-and-portal listener on
// port 80.
//
// A separate plain listener exists because a device that has not installed the CA
// cannot open an https:// URL without a warning, and a certificate warning at the
// moment somebody joins the Wi-Fi reads as "this network is attacking me". So port
// 80 serves the portal, the CA download and the probe responses, and everything
// that matters is on 443.
func (a *API) ServePlain(ctx context.Context, addr string) error {
	server := &http.Server{
		Addr:              addr,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errs := make(chan error, 1)
	go func() { errs <- server.ListenAndServe() }()

	select {
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}

// Response helpers.

// writeJSON sends a JSON response.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	// Encoding failures are logged nowhere on purpose: the header is already
	// written, so there is nothing left to say to the client, and every payload
	// here is a struct that cannot fail to encode.
	_ = json.NewEncoder(w).Encode(body)
}

// errorBody is the shape of every error response.
//
// A code as well as a message, because the scanner shows the message to a human
// and switches on the code. A message alone means the client has to match on
// English, which breaks the moment the message is reworded.
type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeError sends a structured error.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Code: code, Message: message})
}

// readJSON decodes a request body with a size limit.
//
// The limit matters: a scan request is a few hundred bytes and a manifest ingest
// is megabytes, so each caller passes its own. Without a limit, any device on the
// venue Wi-Fi can make the box allocate until it dies.
func readJSON(w http.ResponseWriter, r *http.Request, limit int64, into any) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	// Unknown fields are an error rather than ignored, so a scanner talking a
	// newer protocol finds out immediately instead of having half its request
	// silently dropped.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return fmt.Errorf("malformed request body: %w", err)
	}
	return nil
}
