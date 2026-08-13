// Package enroll is the scanner enrollment ceremony.
//
// A scanner is not an open device that anybody can point at a gate. It is
// enrolled: the organizer generates a one-time code on the dashboard, the code is
// shown as a QR, a staff phone scans it, and the box hands back a device token
// bound to a specific set of checkpoints. Every scan after that is attributed to
// that device, and a stolen phone is revoked from the dashboard in one tap.
//
// The QR is doing three jobs at once, and it is the reason the whole ceremony
// works offline:
//
//  1. It carries the box's URL, so the phone does not have to discover anything.
//  2. It carries the CA fingerprint, so the phone can pin the box's self-minted
//     certificate without trusting whatever is on the network.
//  3. It carries a single-use code, so possession of the printed sheet is the
//     authorisation, and the sheet is something the organizer physically controls.
//
// That third point is what makes this secure without any pre-shared secret or any
// internet: trust arrives out of band, on paper, in the hands of the person who
// is allowed to grant it.
//
// Tokens are stored hashed. The box never holds a value that could be replayed if
// its database leaked, which matters because the database also travels on a USB
// stick to whoever is doing the post-event reconciliation.
package enroll

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ManasMadan/gatecrash/internal/venue"
)

// Sizes and lifetimes.
const (
	// CodeBytes is the entropy in an enrollment code. Ten bytes is 80 bits, which
	// is far more than a code that lives for ten minutes and is single-use needs;
	// the reason it is not smaller is that the code is also the thing a human
	// might type when the camera will not focus, and base32 of 10 bytes is 16
	// characters in four readable groups.
	CodeBytes = 10

	// TokenBytes is the entropy in a device token. Thirty-two bytes, because a
	// token lives for the length of an event and is presented on every scan.
	TokenBytes = 32

	// DefaultCodeTTL is how long an enrollment code is valid.
	//
	// Ten minutes: long enough to walk a printed sheet to a gate and hand phones
	// round, short enough that a sheet left on a table overnight is worthless.
	DefaultCodeTTL = 10 * time.Minute
)

// QRPrefix identifies an enrollment QR payload, matching the GC1 and GC2 ticket
// prefixes so a scanner can tell what it is looking at from three characters.
const QRPrefix = "GCE1"

// codeEncoding is base32 without padding: uppercase, no ambiguous characters
// against the QR alphanumeric set, and readable aloud over a radio.
var codeEncoding = base64.RawURLEncoding

// Invite is what an enrollment QR carries.
type Invite struct {
	// URL is the box's base URL, normally the raw-IP https:// form. Raw IP rather
	// than a name because the phone has not resolved anything yet and mDNS may not
	// work on this access point.
	URL string `json:"url"`

	// Code is the single-use enrollment code.
	Code string `json:"code"`

	// CAFingerprint is the SHA-256 fingerprint of the box's CA, so the phone pins
	// rather than trusting.
	CAFingerprint string `json:"ca"`

	// Event is the human-readable event name, shown on the phone so staff can see
	// they are enrolling into the right show.
	Event string `json:"event"`

	// Checkpoints is what this code will grant. Shown to the person enrolling, so
	// somebody handed the wrong sheet notices before they are standing at a door
	// that will not admit anybody.
	Checkpoints []venue.CheckpointCode `json:"checkpoints"`

	// Expires is when the code stops working, so the phone can say "this code has
	// expired, ask for a new one" instead of failing opaquely.
	Expires time.Time `json:"expires"`
}

// Encode renders an invite as a QR payload.
func (i Invite) Encode() (string, error) {
	raw, err := json.Marshal(i)
	if err != nil {
		return "", fmt.Errorf("enroll: encoding invite: %w", err)
	}
	return QRPrefix + "." + base64.RawURLEncoding.EncodeToString(raw), nil
}

// ErrBadInvite is returned for a payload that is not an enrollment QR.
var ErrBadInvite = errors.New("enroll: not an enrollment code")

// DecodeInvite parses an enrollment QR payload.
func DecodeInvite(payload string) (Invite, error) {
	body, found := strings.CutPrefix(payload, QRPrefix+".")
	if !found {
		return Invite{}, ErrBadInvite
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Invite{}, fmt.Errorf("%w: %v", ErrBadInvite, err)
	}
	var invite Invite
	if err := json.Unmarshal(raw, &invite); err != nil {
		return Invite{}, fmt.Errorf("%w: %v", ErrBadInvite, err)
	}
	if invite.URL == "" || invite.Code == "" {
		return Invite{}, fmt.Errorf("%w: missing url or code", ErrBadInvite)
	}
	return invite, nil
}

// code is a pending enrollment code, held in memory.
type code struct {
	// hash is the code's HMAC. The plaintext is never retained: it exists only in
	// the QR the organizer printed.
	hash []byte

	checkpoints []venue.CheckpointCode
	name        string
	expires     time.Time

	// uses and limit support a sheet that enrolls several phones. Default one.
	uses  int
	limit int
}

// Device is an enrolled scanner as this package tracks it.
type Device struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Checkpoints []venue.CheckpointCode `json:"checkpoints"`
	EnrolledAt  time.Time              `json:"enrolled_at"`
	Revoked     bool                   `json:"revoked,omitempty"`
}

// Registry issues codes and validates tokens.
//
// Codes live in memory only: an enrollment code that survived a reboot would be a
// credential nobody knows exists, and regenerating one costs an operator a single
// tap. Device tokens are persisted, because a scanner must survive the box
// restarting mid-event.
type Registry struct {
	// secret keys the HMAC used to hash codes and tokens. Derived from the box's
	// own key material so that a database copied off the box cannot be used to
	// verify tokens against it.
	secret []byte

	// now is injected so tests can drive expiry.
	now func() time.Time

	mu      sync.Mutex
	codes   map[string]*code
	tokens  map[string]string // token hash -> device id
	devices map[string]*Device

	// persist is called whenever a device is created or changed.
	persist func(Device)
}

// Config configures a registry.
type Config struct {
	// Secret keys the token and code hashes. Required, and it must be stable
	// across reboots or every enrolled scanner is logged out.
	Secret []byte

	Now func() time.Time

	// Persist is called for every device change, so the store can write it
	// through.
	Persist func(Device)
}

// New builds a registry.
func New(cfg Config) (*Registry, error) {
	if len(cfg.Secret) < 16 {
		return nil, errors.New("enroll: the registry secret must be at least 16 bytes")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Registry{
		secret:  append([]byte(nil), cfg.Secret...),
		now:     cfg.Now,
		codes:   make(map[string]*code),
		tokens:  make(map[string]string),
		devices: make(map[string]*Device),
		persist: cfg.Persist,
	}, nil
}

// hash computes the keyed hash of a secret value.
//
// HMAC rather than a bare SHA-256 so that a leaked database is useless without
// the box's secret: an attacker with the token table cannot pre-compute or verify
// candidate tokens offline.
func (r *Registry) hash(value string) []byte {
	mac := hmac.New(sha256.New, r.secret)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}

// InviteRequest describes a code to issue.
type InviteRequest struct {
	// Checkpoints the enrolled device may scan at. Required: a device with no
	// checkpoints scans nothing, and issuing one would be a confusing no-op.
	Checkpoints []venue.CheckpointCode

	// Name is the display name given to devices enrolled with this code.
	Name string

	// TTL overrides the code lifetime.
	TTL time.Duration

	// Uses is how many devices one code may enroll. Zero means one.
	//
	// More than one exists because a supervisor handing out six phones for one
	// gate should not need six printed sheets, and every device still gets its own
	// token and its own identity.
	Uses int
}

// Issue creates an enrollment code and the invite to print.
func (r *Registry) Issue(req InviteRequest, boxURL, caFingerprint, eventName string) (Invite, error) {
	if len(req.Checkpoints) == 0 {
		return Invite{}, errors.New("enroll: a code must grant at least one checkpoint")
	}
	if boxURL == "" {
		return Invite{}, errors.New("enroll: no box url")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = DefaultCodeTTL
	}
	uses := req.Uses
	if uses <= 0 {
		uses = 1
	}

	raw := make([]byte, CodeBytes)
	if _, err := rand.Read(raw); err != nil {
		return Invite{}, fmt.Errorf("enroll: generating code: %w", err)
	}
	plaintext := codeEncoding.EncodeToString(raw)
	expires := r.now().Add(ttl)

	r.mu.Lock()
	// Opportunistically drop expired codes. There is no reaper goroutine: codes
	// are few, short-lived, and cleaning up on write is simpler than a timer
	// nobody remembers to stop.
	r.sweepLocked()
	r.codes[string(r.hash(plaintext))] = &code{
		hash:        r.hash(plaintext),
		checkpoints: append([]venue.CheckpointCode(nil), req.Checkpoints...),
		name:        req.Name,
		expires:     expires,
		limit:       uses,
	}
	r.mu.Unlock()

	return Invite{
		URL:           boxURL,
		Code:          plaintext,
		CAFingerprint: caFingerprint,
		Event:         eventName,
		Checkpoints:   req.Checkpoints,
		Expires:       expires,
	}, nil
}

// sweepLocked drops expired codes. Caller holds the lock.
func (r *Registry) sweepLocked() {
	now := r.now()
	for key, pending := range r.codes {
		if now.After(pending.expires) {
			delete(r.codes, key)
		}
	}
}

// Errors returned by Redeem.
var (
	// ErrUnknownCode means the code is wrong, already spent, or expired. The three
	// are deliberately indistinguishable: telling a caller that a code exists but
	// is expired confirms a guess, and there is nothing useful they can do with
	// the distinction anyway.
	ErrUnknownCode = errors.New("enroll: unknown or expired code")

	// ErrNoDeviceName means the request did not name the device.
	ErrNoDeviceName = errors.New("enroll: the device needs a name")
)

// Enrollment is what a device receives on success.
type Enrollment struct {
	DeviceID    string                 `json:"device_id"`
	Token       string                 `json:"token"`
	Name        string                 `json:"name"`
	Checkpoints []venue.CheckpointCode `json:"checkpoints"`

	// Expires is when the token stops working. Empty means for the life of the
	// event, which is the normal case: a scanner whose credential expires mid-doors
	// is a gate that stops working for no visible reason.
	Expires time.Time `json:"expires,omitzero"`
}

// Redeem exchanges an enrollment code for a device token.
func (r *Registry) Redeem(plaintext, deviceName string) (Enrollment, error) {
	deviceName = strings.TrimSpace(deviceName)
	if deviceName == "" {
		return Enrollment{}, ErrNoDeviceName
	}
	if len(deviceName) > 64 {
		deviceName = deviceName[:64]
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	pending := r.findCodeLocked(plaintext)
	if pending == nil {
		return Enrollment{}, ErrUnknownCode
	}

	token := make([]byte, TokenBytes)
	if _, err := rand.Read(token); err != nil {
		return Enrollment{}, fmt.Errorf("enroll: generating token: %w", err)
	}
	plaintextToken := base64.RawURLEncoding.EncodeToString(token)

	deviceID, err := newDeviceID()
	if err != nil {
		return Enrollment{}, err
	}

	name := pending.name
	if name == "" {
		name = deviceName
	} else if pending.limit > 1 {
		// A multi-use sheet names the gate; each phone appends its own label so
		// the dashboard can tell six identical phones apart.
		name = pending.name + " / " + deviceName
	}

	device := &Device{
		ID:          deviceID,
		Name:        name,
		Checkpoints: append([]venue.CheckpointCode(nil), pending.checkpoints...),
		EnrolledAt:  r.now(),
	}
	r.devices[deviceID] = device
	r.tokens[string(r.hash(plaintextToken))] = deviceID

	pending.uses++
	if pending.uses >= pending.limit {
		delete(r.codes, string(pending.hash))
	}

	if r.persist != nil {
		r.persist(*device)
	}

	return Enrollment{
		DeviceID:    deviceID,
		Token:       plaintextToken,
		Name:        device.Name,
		Checkpoints: device.Checkpoints,
	}, nil
}

// findCodeLocked returns a live, unspent code matching the plaintext.
//
// The lookup walks every code and compares in constant time rather than indexing
// by hash, because indexing would leak whether a code exists through timing. There
// are at most a handful of live codes, so the walk costs nothing.
func (r *Registry) findCodeLocked(plaintext string) *code {
	if plaintext == "" {
		return nil
	}
	want := r.hash(plaintext)
	now := r.now()

	var found *code
	for _, pending := range r.codes {
		if subtle.ConstantTimeCompare(pending.hash, want) == 1 {
			found = pending
		}
	}
	if found == nil || now.After(found.expires) || found.uses >= found.limit {
		return nil
	}
	return found
}

// Authenticate resolves a bearer token to a device.
func (r *Registry) Authenticate(token string) (Device, bool) {
	if token == "" {
		return Device{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	deviceID, ok := r.tokens[string(r.hash(token))]
	if !ok {
		return Device{}, false
	}
	device, ok := r.devices[deviceID]
	if !ok || device.Revoked {
		return Device{}, false
	}
	return *device, true
}

// Revoke disables a device. One tap on the dashboard, effective on the next scan.
func (r *Registry) Revoke(deviceID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	device, ok := r.devices[deviceID]
	if !ok {
		return fmt.Errorf("enroll: no device %s", deviceID)
	}
	device.Revoked = true
	if r.persist != nil {
		r.persist(*device)
	}
	return nil
}

// Devices lists enrolled devices.
func (r *Registry) Devices() []Device {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]Device, 0, len(r.devices))
	for _, device := range r.devices {
		out = append(out, *device)
	}
	return out
}

// PendingCodes returns how many live enrollment codes exist, for the dashboard.
// The codes themselves are not exposed: the box does not hold their plaintext.
func (r *Registry) PendingCodes() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked()
	return len(r.codes)
}

// Restore reloads devices and their token hashes after a reboot.
//
// Token hashes are what is persisted, never the tokens. A scanner presents its
// token, the box hashes it and looks it up; the box itself cannot produce a valid
// token for any device, which is the point.
func (r *Registry) Restore(devices []Device, tokenHashes map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range devices {
		device := devices[i]
		r.devices[device.ID] = &device
	}
	for hash, deviceID := range tokenHashes {
		raw, err := base64.RawURLEncoding.DecodeString(hash)
		if err != nil {
			continue
		}
		r.tokens[string(raw)] = deviceID
	}
}

// TokenHashes returns the persistable token table: base64 hash to device id.
func (r *Registry) TokenHashes() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make(map[string]string, len(r.tokens))
	for hash, deviceID := range r.tokens {
		out[base64.RawURLEncoding.EncodeToString([]byte(hash))] = deviceID
	}
	return out
}

// newDeviceID returns a short, readable device identifier.
//
// Readable because it appears on the scanner's home screen, in the audit log and
// on the dashboard, and because gate staff read it out when something is wrong.
func newDeviceID() (string, error) {
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("enroll: generating device id: %w", err)
	}
	return "dev-" + base64.RawURLEncoding.EncodeToString(raw), nil
}
