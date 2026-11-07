package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"sync/atomic"
)

const marker = "[redacted]"

// redactor replaces each needle with a mask of the same length, so
// Content-Length and frame lengths stay correct (R11).
type redactor struct{ needles, masks [][]byte }

// newRedactor covers forms and the escaped forms an upstream might echo
// them in.
func newRedactor(forms []string) *redactor {
	var all []string
	for _, f := range forms {
		b, _ := json.Marshal(f)
		for _, s := range []string{f, string(b[1 : len(b)-1]), strings.ReplaceAll(f, "/", `\/`)} {
			if s != "" && !slices.Contains(all, s) {
				all = append(all, s)
			}
		}
	}
	r := &redactor{}
	for _, s := range all {
		m := bytes.Repeat([]byte("*"), len(s))
		copy(m, marker)
		r.needles, r.masks = append(r.needles, []byte(s)), append(r.masks, m)
	}
	return r
}

// redact masks b in place and reports whether anything matched.
func (r *redactor) redact(b []byte) bool {
	hit := false
	for i, n := range r.needles {
		for at := 0; ; {
			j := bytes.Index(b[at:], n)
			if j < 0 {
				break
			}
			copy(b[at+j:], r.masks[i])
			at += j + len(n)
			hit = true
		}
	}
	return hit
}

// partial is the length of the longest suffix of b that is a proper prefix
// of a needle: bytes that can't be released until the next read says
// whether they complete one.
func (r *redactor) partial(b []byte) int {
	best := 0
	for _, n := range r.needles {
		for k := min(len(n)-1, len(b)); k > best; k-- {
			if b[len(b)-k] == n[0] && bytes.HasSuffix(b, n[:k]) {
				best = k
				break
			}
		}
	}
	return best
}

// scrubber redacts a response body as it streams. It holds back only a tail
// that could begin a needle, so a complete SSE event is never delayed
// waiting for the next one.
type scrubber struct {
	r       io.ReadCloser
	red     *redactor
	onHit   func()
	buf     []byte
	pending []byte // the held-back tail, at the end of buf
	ready   []byte // safe to return
	err     error
}

func newScrubber(r io.ReadCloser, red *redactor, onHit func()) io.ReadCloser {
	if len(red.needles) == 0 {
		return r
	}
	return &scrubber{r: r, red: red, onHit: onHit, buf: make([]byte, 32<<10)}
}

func (s *scrubber) Read(p []byte) (int, error) {
	for len(s.ready) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		k := copy(s.buf, s.pending)
		n, err := s.r.Read(s.buf[k:])
		s.err = err
		data := s.buf[:k+n]
		if s.red.redact(data) {
			s.onHit()
		}
		keep := 0
		if err == nil {
			keep = s.red.partial(data)
		}
		s.ready, s.pending = data[:len(data)-keep], data[len(data)-keep:]
	}
	n := copy(p, s.ready)
	s.ready = s.ready[n:]
	return n, nil
}

func (s *scrubber) Close() error { return s.r.Close() }

// frameScrubber redacts server-to-client WebSocket frames after a 101
// (R13). Each frame is released as soon as it is complete: holding back a
// tail that might begin a needle, as scrubber does, could stall the last
// message of a turn until the server next speaks. Frames are redacted one at
// a time, so a secret split across two fragments of a message isn't caught.
type frameScrubber struct {
	io.ReadWriteCloser
	br    *bufio.Reader
	red   *redactor
	onHit func()
	n     *atomic.Int64 // bytes released, for the log
	frame []byte        // redacted, not yet returned
}

// maxFrame bounds the memory one frame can take.
const maxFrame = 16 << 20

var errFrame = errors.New("websocket frame refused")

func newFrameScrubber(rwc io.ReadWriteCloser, red *redactor, onHit func(), n *atomic.Int64) io.ReadWriteCloser {
	return &frameScrubber{ReadWriteCloser: rwc, br: bufio.NewReader(rwc), red: red, onHit: onHit, n: n}
}

func (f *frameScrubber) Read(p []byte) (int, error) {
	if len(f.frame) == 0 {
		if err := f.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, f.frame)
	f.frame = f.frame[n:]
	f.n.Add(int64(n))
	return n, nil
}

func (f *frameScrubber) next() error {
	head := make([]byte, 2, 10)
	if _, err := io.ReadFull(f.br, head); err != nil {
		return err
	}
	if head[1]&0x80 != 0 {
		return errFrame // servers never mask (RFC 6455 §5.1), and we couldn't search a masked payload
	}
	size := uint64(head[1])
	if ext := map[uint64]int{126: 2, 127: 8}[size]; ext > 0 {
		head = head[:2+ext]
		if _, err := io.ReadFull(f.br, head[2:]); err != nil {
			return err
		}
		size = 0
		for _, b := range head[2:] {
			size = size<<8 | uint64(b)
		}
	}
	if size > maxFrame {
		return errFrame
	}
	frame := append(head, make([]byte, size)...)
	if _, err := io.ReadFull(f.br, frame[len(head):]); err != nil {
		return err
	}
	if f.red.redact(frame[len(head):]) {
		f.onHit()
	}
	f.frame = frame
	return nil
}
