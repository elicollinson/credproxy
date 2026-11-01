package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"strings"
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
