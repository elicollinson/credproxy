package proxy

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHeaderInjection(t *testing.T) {
	hs := newHarness(t, nil)
	h := http.Header{"X-Subscription-Token": {aliceToken}, "Authorization": {"Bearer " + aliceToken}}
	wantStatus(t, hs.do("GET", "/brave/web/search?q=go", h, nil), 200)
	got := hs.up.last(t)
	if v := got.Header.Values("X-Subscription-Token"); len(v) != 1 || v[0] != braveSecret {
		t.Errorf("upstream X-Subscription-Token = %q", v)
	}
	if got.Header.Get("Authorization") != "" || got.URL.Path != "/res/v1/web/search" || got.URL.RawQuery != "q=go" {
		t.Errorf("upstream saw %s?%s, Authorization %q", got.URL.Path, got.URL.RawQuery, got.Header.Get("Authorization"))
	}
}

func TestBasicInjection(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		// Echo the secret back raw and as the base64 header it travelled in.
		_, pw, _ := r.BasicAuth()
		io.WriteString(w, pw+" "+strings.TrimPrefix(r.Header.Get("Authorization"), "Basic "))
	})
	req := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("whoever:"+aliceToken))}}
	resp := hs.do("POST", "/wandb/graphql", req, strings.NewReader("{}"))
	wantStatus(t, resp, 200)
	user, pw, ok := hs.up.last(t).BasicAuth()
	if !ok || user != "api" || pw != wandbSecret {
		t.Errorf("upstream basic auth = %q, ok %v", user, ok)
	}
	b := body(t, resp)
	encoded := base64.StdEncoding.EncodeToString([]byte("api:" + wandbSecret))
	if strings.Contains(b, wandbSecret) || strings.Contains(b, encoded) || strings.Count(b, "[redacted]") != 2 {
		t.Errorf("echo not redacted in both forms: %q", b)
	}
}

func TestQueryInjection(t *testing.T) {
	hs := newHarness(t, nil)
	h := http.Header{"X-Goog-Api-Key": {aliceToken}}
	wantStatus(t, hs.do("POST", "/gemini/v1beta/models/flash:generate?alt=sse&KEY=mine", h, strings.NewReader("{}")), 200)
	q := hs.up.last(t).URL.Query()
	if v := q["key"]; len(v) != 1 || v[0] != geminiSecret {
		t.Errorf("upstream key = %q", v)
	}
	if q.Get("alt") != "sse" || q.Has("KEY") || hs.up.last(t).Header.Get("X-Goog-Api-Key") != "" {
		t.Errorf("upstream query %v, header %q", q, hs.up.last(t).Header.Get("X-Goog-Api-Key"))
	}
	// The caller may also authenticate in the parameter the real key goes in.
	wantStatus(t, hs.do("POST", "/gemini/v1beta/models/flash:generate?key="+aliceToken, nil, strings.NewReader("{}")), 200)
	if v := hs.up.last(t).URL.Query()["key"]; len(v) != 1 || v[0] != geminiSecret {
		t.Errorf("upstream key = %q", v)
	}
}

// tokenServer is a fake oauth2.googleapis.com. It checks every assertion it
// is sent and mints a new access token each time.
type tokenServer struct {
	up     *upstream
	minted atomic.Int64
	fail   atomic.Bool
	mu     sync.Mutex
	errs   []string
}

func newTokenServer(t *testing.T, clock *fakeClock) *tokenServer {
	ts := &tokenServer{}
	ts.up = newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if ts.fail.Load() {
			http.Error(w, "backend error", 500)
			return
		}
		if err := checkAssertion(r, clock.Now()); err != nil {
			ts.mu.Lock()
			ts.errs = append(ts.errs, err.Error())
			ts.mu.Unlock()
			http.Error(w, "invalid_grant", 400)
			return
		}
		n := ts.minted.Add(1)
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprint(accessToken, n), "expires_in": 3600, "token_type": "Bearer",
		})
	})
	return ts
}

func (ts *tokenServer) errors() []string { ts.mu.Lock(); defer ts.mu.Unlock(); return ts.errs }

// checkAssertion verifies a JWT-bearer grant as Google does (RFC 7523).
func checkAssertion(r *http.Request, now time.Time) error {
	if r.Method != "POST" || r.URL.Path != "/token" {
		return fmt.Errorf("%s %s", r.Method, r.URL.Path)
	}
	r.ParseForm()
	if g := r.PostForm.Get("grant_type"); g != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		return fmt.Errorf("grant_type %q", g)
	}
	parts := strings.Split(r.PostForm.Get("assertion"), ".")
	if len(parts) != 3 {
		return fmt.Errorf("assertion has %d parts", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&saKey.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		return fmt.Errorf("signature: %v", err)
	}
	var head struct{ Alg, Typ, Kid string }
	var claims struct {
		Iss, Scope, Aud string
		Iat, Exp        int64
	}
	for i, v := range []any{&head, &claims} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, v); err != nil {
			return err
		}
	}
	switch {
	case head.Alg != "RS256" || head.Typ != "JWT" || head.Kid != "kid-1":
		return fmt.Errorf("header %+v", head)
	case claims.Iss != saEmail || claims.Aud != "https://oauth2.googleapis.com/token":
		return fmt.Errorf("iss %q aud %q", claims.Iss, claims.Aud)
	case claims.Scope != "https://www.googleapis.com/auth/cloud-platform":
		return fmt.Errorf("scope %q", claims.Scope)
	case claims.Iat != now.Unix() || claims.Exp != claims.Iat+3600:
		return fmt.Errorf("iat %d exp %d, now %d", claims.Iat, claims.Exp, now.Unix())
	}
	return nil
}

// concurrently sends n requests at once and returns their statuses.
func (hs *harness) concurrently(n int, path string) []int {
	statuses := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			resp := hs.do("POST", path, bearer(aliceToken), strings.NewReader("{}"))
			io.Copy(io.Discard, resp.Body)
			statuses[i] = resp.StatusCode
		})
	}
	wg.Wait()
	return statuses
}

// T15
func TestGoogleServiceAccount(t *testing.T) {
	hs := newHarness(t, nil)
	wantToken := func(n int64) {
		t.Helper()
		for _, s := range hs.concurrently(8, "/gcp/v1/projects/my-proj/x") {
			if s != 200 {
				t.Fatalf("status %d; token server errors: %v", s, hs.tok.errors())
			}
		}
		if got := hs.tok.minted.Load(); got != n {
			t.Fatalf("token endpoint minted %d times, want %d", got, n)
		}
		if v := hs.up.last(t).Header.Values("Authorization"); len(v) != 1 || v[0] != fmt.Sprint("Bearer ", accessToken, n) {
			t.Fatalf("upstream Authorization = %q", v)
		}
	}
	wantToken(1)
	hs.clock.Advance(54 * time.Minute) // 6 minutes left: still cached
	wantToken(1)
	hs.clock.Advance(2 * time.Minute) // 4 minutes left: one refresh, however many ask
	wantToken(2)
	if errs := hs.tok.errors(); len(errs) != 0 {
		t.Fatalf("token server rejected assertions: %v", errs)
	}
}

func TestServiceAccountTokenEchoRedacted(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("Authorization"))
	})
	resp := hs.do("POST", "/gcp/v1/echo", bearer(aliceToken), strings.NewReader("{}"))
	wantStatus(t, resp, 200)
	if b := body(t, resp); strings.Contains(b, accessToken) || !strings.Contains(b, "[redacted]") {
		t.Errorf("access token reached the caller: %q", b)
	}
}

func TestServiceAccountForeignTokenURIRefused(t *testing.T) {
	hs := newHarness(t, nil)
	resp := hs.do("POST", "/gcp-bad/v1/x", bearer(aliceToken), strings.NewReader("{}"))
	wantStatus(t, resp, 503)
	if b := body(t, resp); !strings.Contains(b, "credential_invalid") {
		t.Errorf("body = %q", b)
	}
	if hs.evil.conns.Load() != 0 || hs.tok.up.hits.Load() != 0 || hs.up.hits.Load() != 0 {
		t.Error("something was contacted with a foreign token_uri")
	}
}

func TestServiceAccountMintFailureIs502(t *testing.T) {
	hs := newHarness(t, nil)
	hs.tok.fail.Store(true)
	for range 3 {
		resp := hs.do("POST", "/gcp/v1/x", bearer(aliceToken), strings.NewReader("{}"))
		wantStatus(t, resp, 502)
		if b := body(t, resp); !strings.Contains(b, "token_mint_failed") {
			t.Errorf("body = %q", b)
		}
	}
	// One attempt per request, never a retry loop.
	if n := hs.tok.up.hits.Load(); n != 3 {
		t.Errorf("token endpoint hit %d times for 3 requests", n)
	}
	if hs.up.hits.Load() != 0 {
		t.Error("upstream contacted without a token")
	}
}
