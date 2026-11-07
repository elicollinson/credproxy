package proxy

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// T13: each event reaches the caller before the upstream sends the next.
// The upstream waits for the caller to confirm each one, so any buffering
// in the proxy stalls the stream and fails the test.
func TestServerSentEventsAreNotBuffered(t *testing.T) {
	got := make(chan struct{}, 5)
	stalled := make(chan int, 1)
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := range 5 {
			fmt.Fprintf(w, "data: {\"n\":%d}\n\n", i)
			w.(http.Flusher).Flush()
			select {
			case <-got:
			case <-time.After(2 * time.Second):
				stalled <- i
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
	resp := hs.do("POST", "/openrouter/chat/completions", bearer(aliceToken), strings.NewReader("{}"))
	wantStatus(t, resp, 200)
	br := bufio.NewReader(resp.Body)
	for i := range 5 {
		line, err := br.ReadString('\n')
		if err != nil {
			select {
			case n := <-stalled:
				t.Fatalf("event %d never reached the caller", n)
			default:
				t.Fatalf("event %d: %v", i, err)
			}
		}
		if want := fmt.Sprintf("data: {\"n\":%d}\n", i); line != want {
			t.Fatalf("event %d = %q", i, line)
		}
		br.ReadString('\n') // the blank line ending the event
		got <- struct{}{}
	}
}

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// writeFrame writes one final RFC 6455 frame. Clients must mask; servers
// must not.
func writeFrame(w io.Writer, opcode byte, payload []byte, mask bool) error {
	head := []byte{0x80 | opcode, 0}
	switch n := len(payload); {
	case n < 126:
		head[1] = byte(n)
	case n < 1<<16:
		head[1] = 126
		head = binary.BigEndian.AppendUint16(head, uint16(n))
	default:
		head[1] = 127
		head = binary.BigEndian.AppendUint64(head, uint64(n))
	}
	body := payload
	if mask {
		head[1] |= 0x80
		key := make([]byte, 4)
		rand.Read(key)
		head = append(head, key...)
		body = make([]byte, len(payload))
		for i, b := range payload {
			body[i] = b ^ key[i%4]
		}
	}
	_, err := w.Write(append(head, body...))
	return err
}

func readFrame(r io.Reader) (byte, []byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	n := uint64(head[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		io.ReadFull(r, b[:])
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		io.ReadFull(r, b[:])
		n = binary.BigEndian.Uint64(b[:])
	}
	var key [4]byte
	masked := head[1]&0x80 != 0
	if masked {
		io.ReadFull(r, key[:])
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= key[i%4]
		}
	}
	return head[0] & 0x0f, payload, nil
}

// wsUpstream answers one upgrade, echoes the caller's first message, then
// sends the secret and a message ending in the secret's first byte, which
// the proxy must not hold back waiting for more.
func wsUpstream(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "not an upgrade", 400)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsAccept(r.Header.Get("Sec-WebSocket-Key")))
		brw.Flush()
		_, msg, err := readFrame(brw)
		if err != nil {
			return
		}
		writeFrame(conn, 1, append([]byte("echo:"), msg...), false)
		writeFrame(conn, 1, []byte(`{"leak":"`+r.URL.Query().Get("key")+`"}`), false)
		writeFrame(conn, 2, []byte("audio..."+geminiSecret[:1]), false)
		readFrame(brw) // until the caller closes
	}
}

// T14
func TestWebSocketWithQueryInjection(t *testing.T) {
	hs := newHarness(t, wsUpstream(t))
	before := logs.Len()
	conn, err := net.Dial("tcp", hs.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	fmt.Fprintf(conn, "GET /gemini/ws?key=%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n", aliceToken, hs.addr, key)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 || resp.Header.Get("Sec-WebSocket-Accept") != wsAccept(key) {
		t.Fatalf("handshake: %d %v", resp.StatusCode, resp.Header)
	}

	if err := writeFrame(conn, 1, []byte("hello"), true); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		check func(string) bool
		desc  string
	}{
		{func(s string) bool { return s == "echo:hello" }, "the echo"},
		{func(s string) bool {
			return !strings.Contains(s, geminiSecret) && strings.Contains(s, "[redacted]") && len(s) == len(`{"leak":"`+geminiSecret+`"}`)
		}, "the secret, redacted to the same length"},
		{func(s string) bool { return s == "audio..."+geminiSecret[:1] }, "the message ending in a needle's first byte"},
	}
	for _, w := range want {
		_, msg, err := readFrame(br)
		if err != nil {
			t.Fatalf("waiting for %s: %v", w.desc, err)
		}
		if !w.check(string(msg)) {
			t.Fatalf("got %q, want %s", msg, w.desc)
		}
	}
	writeFrame(conn, 8, nil, true)
	conn.Close()

	got := hs.up.last(t)
	if v := got.URL.Query()["key"]; len(v) != 1 || v[0] != geminiSecret {
		t.Errorf("upstream key = %q", v)
	}
	if got.Header.Get("Sec-WebSocket-Extensions") != "" {
		t.Error("Sec-WebSocket-Extensions reached the upstream")
	}
	line := logAfter(t, before, `"status":101`)
	if !strings.Contains(line, `"status":101`) || !strings.Contains(line, "upstream_echoed_secret") {
		t.Errorf("log line: %s", line)
	}
}

func TestWebSocketRefusedOnOtherRoutes(t *testing.T) {
	hs := newHarness(t, wsUpstream(t))
	code := hs.raw("GET /brave/web/search HTTP/1.1", "X-Subscription-Token: "+aliceToken, "Upgrade: websocket", "Connection: Upgrade")
	if code != 400 {
		t.Fatalf("status %d", code)
	}
	hs.wantUntouched()
}
