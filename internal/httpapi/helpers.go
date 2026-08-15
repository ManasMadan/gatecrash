package httpapi

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/ManasMadan/gatecrash/internal/bloom"
	"github.com/ManasMadan/gatecrash/internal/engine"
	"github.com/ManasMadan/gatecrash/internal/enroll"
	"github.com/ManasMadan/gatecrash/internal/hlc"
	"github.com/ManasMadan/gatecrash/internal/ssehub"
	"github.com/ManasMadan/gatecrash/internal/ticket"
	"github.com/ManasMadan/gatecrash/internal/venue"
)

// bloomFalsePositiveRate is the target rate for the scanner's filter.
//
// One in a million. At fifty thousand tickets that is about 175 KB, and a false
// positive costs exactly one round trip to a box that knows the truth — so the
// only thing a tighter rate would buy is a larger download on a network that is
// already the bottleneck.
const bloomFalsePositiveRate = 1e-6

// buildBloom builds the ticket-id filter from the loaded manifest.
//
// Rebuilt per request rather than cached. That sounds wrong and is not: a scanner
// fetches this once at doors, the box has a handful of scanners, and a cache would
// have to be invalidated on every door sale and every revocation. Getting that
// invalidation wrong means a scanner rejecting a ticket that was sold thirty
// seconds ago, which is a refund conversation. Fifty thousand ids is about twenty
// milliseconds of hashing.
func (a *API) buildBloom(r *http.Request) (*bloom.Filter, error) {
	total, _, err := a.deps.Store.TicketCount(r.Context())
	if err != nil {
		return nil, err
	}
	// A filter sized for zero elements is undefined, and a box set up before any
	// tickets are issued still serves a manifest.
	filter, err := bloom.New(max(total, 1), bloomFalsePositiveRate)
	if err != nil {
		return nil, err
	}

	ids, err := a.deps.Store.TicketIDs(r.Context())
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		filter.Add(id[:])
	}
	return filter, nil
}

// issueClientCert mints a client certificate from a base64 DER public key.
func (a *API) issueClientCert(deviceID, encoded string) (string, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("public key is not base64: %w", err)
	}
	// A hard cap before parsing: a hostile enrollment could otherwise hand the box
	// a megabyte of DER to chew on.
	if len(der) > 2048 {
		return "", errors.New("public key is implausibly large")
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", fmt.Errorf("public key does not parse: %w", err)
	}
	pem, err := a.deps.CA.IssueClient(deviceID, key)
	if err != nil {
		return "", err
	}
	return string(pem), nil
}

// engineDevice converts an enrollment into the store's device shape.
func engineDevice(enrolled enroll.Enrollment) engine.Device {
	return engine.Device{
		ID:          enrolled.DeviceID,
		Name:        enrolled.Name,
		Checkpoints: enrolled.Checkpoints,
	}
}

// engineScan converts a request into the engine's scan shape.
func engineScan(scanID ticket.ID, req ScanRequest, checkpoint venue.CheckpointCode,
	device enroll.Device, deviceHLC hlc.Timestamp) engine.Scan {
	return engine.Scan{
		ScanID:          scanID,
		Payload:         req.Payload,
		Checkpoint:      checkpoint,
		Device:          device.ID,
		Direction:       req.Direction,
		DeviceHLC:       deviceHLC,
		OfflineAdmitted: req.OfflineAdmitted,
		ObservedAt:      req.ObservedAt,
	}
}

// publishScan puts a committed admission on the delta stream.
//
// Only admissions. A denial is not state anybody else needs to mirror, and
// broadcasting every rejected screenshot to every scanner in the venue would
// spend bandwidth on nothing. Denials are still in the audit log and on the
// dashboard's own stream, which is where they matter.
func (a *API) publishScan(result engine.Result) {
	if !result.Verdict.Admitted() {
		// The dashboard sees everything, so a wall of forged QRs at one gate is
		// visible to the control room even though the gates do not gossip about it.
		a.deps.Hub.Publish(ssehub.Event{Kind: "denial", Seq: 0, Data: result})
		return
	}
	a.deps.Hub.Publish(ssehub.Event{Kind: "redemption", Seq: result.Seq, Data: result})
}

// guidanceFor computes wayfinding for one ticket.
//
// Shared by the gate's lookup and the attendee's own view, so an usher and the
// person they are directing cannot be told different things — which is the whole
// point of computing it on the box rather than in each app.
func (a *API) guidanceFor(r *http.Request, id ticket.ID, from string, stepFree bool) (venue.Guidance, bool, error) {
	var (
		found   engine.Ticket
		present bool
		history []engine.Redemption
	)
	if err := a.deps.Store.Read(r.Context(), func(tx engine.Tx) error {
		var err error
		if found, present, err = tx.Ticket(id); err != nil || !present {
			return err
		}
		history, err = tx.Redemptions(id)
		return err
	}); err != nil {
		return venue.Guidance{}, false, err
	}
	if !present {
		return venue.Guidance{}, false, nil
	}

	guidance, err := a.deps.Venue.Guidance(venue.GuidanceRequest{
		Tier:     found.Tier,
		Seat:     found.Seat,
		Admitted: a.deps.Engine.InsideZones(history),
		From:     venue.NodeID(from),
		StepFree: stepFree,
		At:       a.deps.Now(),
	})
	if err != nil {
		return venue.Guidance{}, false, err
	}
	return guidance, true, nil
}
