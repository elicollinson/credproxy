package proxy

import (
	"crypto/sha256"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/elicollinson/credproxy/internal/config"
)

type caller struct {
	*config.Caller
	bucket *bucket
}

func newCaller(c *config.Caller, now time.Time) *caller {
	burst := max(1, float64(c.RateLimitPerMin)/6)
	return &caller{c, &bucket{tokens: burst, capacity: burst, perSec: float64(c.RateLimitPerMin) / 60, last: now}}
}

// callerToken reads the caller's token from the route's declared slots
// (R4). It returns a status when there is none, or when two slots disagree.
func callerToken(r *http.Request, query url.Values, slots []config.Slot) (string, int, string) {
	var token string
	for _, s := range slots {
		var vals []string
		switch s.Kind {
		case config.SlotBearer:
			if v, ok := cutScheme(r.Header.Get("Authorization"), "Bearer", "token"); ok {
				vals = []string{v}
			}
		case config.SlotBasicPassword:
			if _, pw, ok := r.BasicAuth(); ok {
				vals = []string{pw}
			}
		case config.SlotHeader:
			vals = r.Header.Values(s.Name)
		case config.SlotQuery:
			vals = query[s.Name]
		}
		for _, v := range vals {
			switch {
			case v == "":
			case token == "":
				token = v
			case v != token:
				return "", http.StatusBadRequest, "conflicting_tokens"
			}
		}
	}
	if token == "" {
		return "", http.StatusUnauthorized, "no_token"
	}
	return token, 0, ""
}

func cutScheme(header string, schemes ...string) (string, bool) {
	scheme, value, ok := strings.Cut(header, " ")
	if !ok {
		return "", false
	}
	for _, s := range schemes {
		if strings.EqualFold(scheme, s) {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

// lookup finds the caller whose hash matches token. Every hash is compared,
// with no early exit, so timing says nothing about which caller or how
// close a guess came (R3).
func (p *Proxy) lookup(token string) *caller {
	sum := sha256.Sum256([]byte(token))
	var found *caller
	for _, c := range p.callers {
		if ctEqual(sum[:], c.Hash[:]) == 1 {
			found = c
		}
	}
	return found
}

// bucket is a token-bucket rate limit, one per caller (R15).
type bucket struct {
	mu                       sync.Mutex
	tokens, capacity, perSec float64
	last                     time.Time
}

func (b *bucket) take(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens = min(b.capacity, b.tokens+now.Sub(b.last).Seconds()*b.perSec)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
