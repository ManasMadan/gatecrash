package ssehub

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// stream connects to a hub's handler and returns a reader over the SSE body.
func stream(t *testing.T, h *Hub, opts HandlerOptions, header http.Header, query string) (*bufio.Reader, func()) {
	t.Helper()
	server := httptest.NewServer(h.Handler(opts))

	url := server.URL
	if query != "" {
		url += "?" + query
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type is %q", got)
	}
	// Without this, an intermediate proxy may buffer the whole stream and the
	// scanner receives nothing until the connection closes.
	if got := resp.Header.Get("X-Accel-Buffering"); got != "no" {
		t.Errorf("X-Accel-Buffering is %q, want no", got)
	}

	return bufio.NewReader(resp.Body), func() {
		resp.Body.Close()
		server.Close()
	}
}

// readEvent reads one SSE event, skipping keepalive comments.
func readEvent(t *testing.T, reader *bufio.Reader) (id, kind, data string) {
	t.Helper()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading the stream: %v", err)
		}
		line = strings.TrimRight(line, "\n")

		switch {
		case line == "":
			if data != "" || kind != "" {
				return id, kind, data
			}
		case strings.HasPrefix(line, ":"):
			// Keepalive comment.
		case strings.HasPrefix(line, "id: "):
			id = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "event: "):
			kind = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		}
	}
}

// waitForSubscribers blocks until the hub reports n connected clients.
func waitForSubscribers(t *testing.T, h *Hub, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.Subscribers() == n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("%d subscribers connected, want %d", h.Subscribers(), n)
}

func TestPublishReachesASubscriber(t *testing.T) {
	h := New(nil)
	defer h.Close()

	reader, done := stream(t, h, HandlerOptions{}, nil, "")
	defer done()
	waitForSubscribers(t, h, 1)

	h.Publish(Event{Kind: "redemption", Seq: 41, Data: map[string]string{"ticket": "abc"}})

	id, kind, data := readEvent(t, reader)
	if id != "41" {
		t.Errorf("id is %q, want 41", id)
	}
	if kind != "redemption" {
		t.Errorf("event name is %q", kind)
	}
	if !strings.Contains(data, `"ticket":"abc"`) {
		t.Errorf("data is %q", data)
	}
}

func TestEveryEventCarriesItsSequenceAsTheSSEID(t *testing.T) {
	// A browser's EventSource sends the last id back as Last-Event-ID on
	// reconnect, so carrying the sequence here is what makes resume work with no
	// application code on the client at all.
	h := New(nil)
	defer h.Close()

	reader, done := stream(t, h, HandlerOptions{}, nil, "")
	defer done()
	waitForSubscribers(t, h, 1)

	for seq := uint64(1); seq <= 5; seq++ {
		h.Publish(Event{Kind: "redemption", Seq: seq, Data: seq})
	}
	for seq := 1; seq <= 5; seq++ {
		id, _, _ := readEvent(t, reader)
		if id != strconv.Itoa(seq) {
			t.Fatalf("event %d carries id %q", seq, id)
		}
	}
}

func TestReplayFromLastEventID(t *testing.T) {
	h := New(nil)
	defer h.Close()

	var askedSince uint64
	opts := HandlerOptions{
		Replay: func(_ context.Context, since uint64) ([]Event, error) {
			askedSince = since
			return []Event{
				{Kind: "redemption", Seq: since + 1, Data: "missed-one"},
				{Kind: "redemption", Seq: since + 2, Data: "missed-two"},
			}, nil
		},
	}

	reader, done := stream(t, h, opts, http.Header{"Last-Event-ID": []string{"100"}}, "")
	defer done()

	if _, _, data := readEvent(t, reader); !strings.Contains(data, "missed-one") {
		t.Fatalf("first replayed event is %q", data)
	}
	if id, _, data := readEvent(t, reader); !strings.Contains(data, "missed-two") || id != "102" {
		t.Fatalf("second replayed event is %q at id %q", data, id)
	}
	if askedSince != 100 {
		t.Errorf("replay was asked for events since %d, want 100", askedSince)
	}
}

func TestReplayFromQueryParameter(t *testing.T) {
	// Native apps manage their own retry and want the resume point explicit,
	// rather than implicit in a header they have to remember to set.
	h := New(nil)
	defer h.Close()

	var askedSince uint64
	opts := HandlerOptions{
		Replay: func(_ context.Context, since uint64) ([]Event, error) {
			askedSince = since
			return []Event{{Kind: "redemption", Seq: since + 1, Data: "resumed"}}, nil
		},
	}
	reader, done := stream(t, h, opts, nil, "from=57")
	defer done()

	if _, _, data := readEvent(t, reader); !strings.Contains(data, "resumed") {
		t.Fatalf("data is %q", data)
	}
	if askedSince != 57 {
		t.Errorf("replay was asked for events since %d, want 57", askedSince)
	}
}

func TestNoReplayWithoutAResumePoint(t *testing.T) {
	// A fresh subscriber gets live events only. Replaying the whole event to a
	// dashboard somebody just opened would send megabytes nobody asked for.
	h := New(nil)
	defer h.Close()

	replayed := false
	opts := HandlerOptions{
		Replay: func(_ context.Context, _ uint64) ([]Event, error) {
			replayed = true
			return nil, nil
		},
	}
	reader, done := stream(t, h, opts, nil, "")
	defer done()
	waitForSubscribers(t, h, 1)

	h.Publish(Event{Kind: "redemption", Seq: 1, Data: "live"})
	if _, _, data := readEvent(t, reader); !strings.Contains(data, "live") {
		t.Fatalf("data is %q", data)
	}
	if replayed {
		t.Error("replay ran for a subscriber that supplied no resume point")
	}
}

// TestFilterKeepsAGateOutOfOtherPeoplesBusiness matters for bandwidth and for
// privacy: a gate scanner does not need the incident feed for the whole venue.
func TestFilterKeepsAGateOutOfOtherPeoplesBusiness(t *testing.T) {
	h := New(nil)
	defer h.Close()

	opts := HandlerOptions{Filter: func(e Event) bool { return e.Kind == "redemption" }}
	reader, done := stream(t, h, opts, nil, "")
	defer done()
	waitForSubscribers(t, h, 1)

	h.Publish(Event{Kind: "incident", Seq: 1, Data: "crush"})
	h.Publish(Event{Kind: "stats", Seq: 2, Data: "numbers"})
	h.Publish(Event{Kind: "redemption", Seq: 3, Data: "admitted"})

	id, kind, data := readEvent(t, reader)
	if kind != "redemption" || !strings.Contains(data, "admitted") || id != "3" {
		t.Fatalf("the filter let through %s/%s", kind, data)
	}
}

func TestFilterAppliesToReplayToo(t *testing.T) {
	h := New(nil)
	defer h.Close()

	opts := HandlerOptions{
		Filter: func(e Event) bool { return e.Kind == "redemption" },
		Replay: func(_ context.Context, since uint64) ([]Event, error) {
			return []Event{
				{Kind: "incident", Seq: since + 1, Data: "not-for-you"},
				{Kind: "redemption", Seq: since + 2, Data: "yours"},
			}, nil
		},
	}
	reader, done := stream(t, h, opts, nil, "from=10")
	defer done()

	_, kind, data := readEvent(t, reader)
	if kind != "redemption" || !strings.Contains(data, "yours") {
		t.Fatalf("replay leaked %s/%s past the filter", kind, data)
	}
}

// TestASlowSubscriberIsDisconnectedRatherThanWaitedFor is the property the whole
// design turns on. Publish runs on the engine's writer goroutine immediately after
// a transaction commits, so anything that blocks there blocks every gate in the
// venue.
func TestASlowSubscriberIsDisconnectedRatherThanWaitedFor(t *testing.T) {
	h := New(nil)
	defer h.Close()

	// Connect but never read.
	server := httptest.NewServer(h.Handler(HandlerOptions{}))
	defer server.Close()
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	waitForSubscribers(t, h, 1)

	// Publish far more than the buffer holds. This must not block.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for seq := uint64(1); seq <= bufferSize*4; seq++ {
			h.Publish(Event{Kind: "redemption", Seq: seq, Data: strings.Repeat("x", 512)})
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Publish blocked on a subscriber that stopped reading, which would stall every gate")
	}

	// And the stuck subscriber is dropped rather than accumulating forever.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.Dropped() > 0 && h.Subscribers() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the stuck subscriber was not dropped: subscribers=%d dropped=%d", h.Subscribers(), h.Dropped())
}

func TestManySubscribersAllReceiveEverything(t *testing.T) {
	h := New(nil)
	defer h.Close()

	const clients = 12
	readers := make([]*bufio.Reader, 0, clients)
	for i := 0; i < clients; i++ {
		reader, done := stream(t, h, HandlerOptions{}, nil, "")
		defer done()
		readers = append(readers, reader)
	}
	waitForSubscribers(t, h, clients)

	h.Publish(Event{Kind: "redemption", Seq: 7, Data: "broadcast"})

	var wg sync.WaitGroup
	for i, reader := range readers {
		wg.Add(1)
		go func(i int, reader *bufio.Reader) {
			defer wg.Done()
			id, _, data := readEvent(t, reader)
			if id != "7" || !strings.Contains(data, "broadcast") {
				t.Errorf("client %d received id=%q data=%q", i, id, data)
			}
		}(i, reader)
	}
	wg.Wait()
}

func TestHeartbeatKeepsTheConnectionAlive(t *testing.T) {
	// Consumer access points idle out silent connections, and a scanner whose
	// stream died silently believes its mirror is current when it is not.
	h := New(nil)
	defer h.Close()

	reader, done := stream(t, h, HandlerOptions{Heartbeat: 20 * time.Millisecond}, nil, "")
	defer done()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, ":") {
			return
		}
	}
	t.Fatal("no keepalive comment arrived")
}

func TestUnsubscribeOnDisconnect(t *testing.T) {
	h := New(nil)
	defer h.Close()

	_, done := stream(t, h, HandlerOptions{}, nil, "")
	waitForSubscribers(t, h, 1)
	done()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.Subscribers() == 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("%d subscribers still registered after a disconnect", h.Subscribers())
}

func TestClosedHubRefusesNewSubscribers(t *testing.T) {
	h := New(nil)
	h.Close()

	server := httptest.NewServer(h.Handler(HandlerOptions{}))
	defer server.Close()
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 while shutting down", resp.StatusCode)
	}
}

func TestCloseDisconnectsEverybody(t *testing.T) {
	h := New(nil)

	server := httptest.NewServer(h.Handler(HandlerOptions{}))
	defer server.Close()
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	waitForSubscribers(t, h, 1)

	h.Close()

	// The body must end rather than hanging.
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 256)
		for {
			if _, err := resp.Body.Read(buf); err != nil {
				return
			}
		}
	}()
	select {
	case <-readDone:
	case <-time.After(3 * time.Second):
		t.Fatal("the stream did not end when the hub closed")
	}
}

func TestUnencodablePayloadDoesNotKillTheStream(t *testing.T) {
	// A payload that will not encode is a bug, not a client problem. Skipping it
	// keeps the stream alive rather than tearing down every gate's connection over
	// one bad row.
	h := New(nil)
	defer h.Close()

	reader, done := stream(t, h, HandlerOptions{}, nil, "")
	defer done()
	waitForSubscribers(t, h, 1)

	h.Publish(Event{Kind: "broken", Seq: 1, Data: make(chan int)})
	h.Publish(Event{Kind: "redemption", Seq: 2, Data: "still-here"})

	if _, kind, data := readEvent(t, reader); kind != "redemption" || !strings.Contains(data, "still-here") {
		t.Fatalf("the stream did not survive an unencodable payload: %s/%s", kind, data)
	}
}

func TestReplayErrorDoesNotBreakTheStream(t *testing.T) {
	h := New(nil)
	defer h.Close()

	opts := HandlerOptions{
		Replay: func(_ context.Context, _ uint64) ([]Event, error) {
			return nil, errors.New("the database is busy")
		},
	}
	reader, done := stream(t, h, opts, nil, "from=5")
	defer done()
	waitForSubscribers(t, h, 1)

	// A failed replay must still leave a working live stream: a scanner that
	// cannot catch up should still see what happens next.
	h.Publish(Event{Kind: "redemption", Seq: 6, Data: "live-anyway"})
	if _, _, data := readEvent(t, reader); !strings.Contains(data, "live-anyway") {
		t.Fatalf("data is %q", data)
	}
}

func BenchmarkPublishToTenSubscribers(b *testing.B) {
	h := New(nil)
	defer h.Close()

	// Subscribe directly rather than over HTTP: this measures the fan-out, which
	// is what runs on the engine's writer goroutine.
	for i := 0; i < 10; i++ {
		if _, _, ok := h.subscribe(nil); !ok {
			b.Fatal("subscribe failed")
		}
	}
	event := Event{Kind: "redemption", Seq: 1, Data: "x"}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		event.Seq = uint64(i + 1)
		h.Publish(event)
	}
}
