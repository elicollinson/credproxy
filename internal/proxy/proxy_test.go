package proxy

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

var discardLogger = log.New(io.Discard, "", 0)

// logAfter waits for the log, from offset from, to contain want. The line is
// written after the response has gone out, so a client can see the response
// first.
func logAfter(t *testing.T, from int, want string) string {
	t.Helper()
	for range 100 {
		if got := logs.String()[from:]; strings.Contains(got, want) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	return logs.String()[from:]
}

func TestHappyPathInjectsOnlyTheRealCredential(t *testing.T) {
	hs := newHarness(t, nil)
	resp := hs.do("GET", "/openrouter/models", bearer(aliceToken), nil)
	wantStatus(t, resp, 200)
	got := hs.up.last(t)
	if v := got.Header.Values("Authorization"); len(v) != 1 || v[0] != "Bearer "+openrouterSecret {
		t.Errorf("upstream Authorization = %q", v)
	}
	if got.URL.Path != "/api/v1/models" || got.Host != "up.test" {
		t.Errorf("upstream saw %s %s", got.Host, got.URL.Path)
	}
}

// T1
func TestRouteNotAllowedForCaller(t *testing.T) {
	hs := newHarness(t, nil)
	wantStatus(t, hs.do("GET", "/github-issues/repos/elicollinson/Solenoid-Assistant/issues", bearer(bobToken), nil), 403)
	hs.wantUntouched()
}

func TestUnknownRoute(t *testing.T) {
	hs := newHarness(t, nil)
	wantStatus(t, hs.do("GET", "/nope/models", bearer(aliceToken), nil), 404)
	hs.wantUntouched()
}

// T2
func TestMissingOrWrongToken(t *testing.T) {
	for name, h := range map[string]http.Header{
		"none":            nil,
		"wrong":           bearer(strangerToken),
		"empty bearer":    {"Authorization": {"Bearer "}},
		"undeclared slot": {"X-Subscription-Token": {aliceToken}},
		"basic on bearer": {"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("x:"+aliceToken))}},
	} {
		t.Run(name, func(t *testing.T) {
			hs := newHarness(t, nil)
			wantStatus(t, hs.do("GET", "/openrouter/models", h, nil), 401)
			hs.wantUntouched()
		})
	}
}

// T3
func TestTwoDifferentTokensRejected(t *testing.T) {
	hs := newHarness(t, nil)
	h := bearer(aliceToken)
	h.Set("X-Subscription-Token", bobToken)
	wantStatus(t, hs.do("GET", "/github-issues/repos/elicollinson/Solenoid-Assistant/issues", h, nil), 400)
	hs.wantUntouched()
}

func TestEverySlotAuthenticates(t *testing.T) {
	const issues = "/github-issues/repos/elicollinson/Solenoid-Assistant/issues"
	for name, req := range map[string]struct {
		path string
		h    http.Header
	}{
		"bearer":         {issues, bearer(aliceToken)},
		"token scheme":   {issues, http.Header{"Authorization": {"token " + aliceToken}}},
		"header":         {issues, http.Header{"X-Subscription-Token": {aliceToken}}},
		"query":          {issues + "?key=" + aliceToken, nil},
		"basic password": {issues, http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("api:"+aliceToken))}}},
		"same twice":     {issues, http.Header{"Authorization": {"Bearer " + aliceToken}, "X-Subscription-Token": {aliceToken}}},
	} {
		t.Run(name, func(t *testing.T) {
			hs := newHarness(t, nil)
			wantStatus(t, hs.do("GET", req.path, req.h, nil), 200)
			got := hs.up.last(t)
			if got.URL.RawQuery != "" || got.Header.Get("X-Subscription-Token") != "" {
				t.Errorf("caller token forwarded: query %q", got.URL.RawQuery)
			}
			if got.Header.Get("Authorization") != "Bearer "+githubSecret {
				t.Error("wrong upstream credential")
			}
		})
	}
}

// T4: every configured hash is compared, whichever token arrives.
func TestLookupComparesEveryCaller(t *testing.T) {
	hs := newHarness(t, nil)
	var calls int
	orig := ctEqual
	ctEqual = func(a, b []byte) int { calls++; return orig(a, b) }
	t.Cleanup(func() { ctEqual = orig })
	for _, token := range []string{strangerToken, aliceToken, bobToken} {
		calls = 0
		hs.do("GET", "/openrouter/models", bearer(token), nil)
		if calls != 2 {
			t.Errorf("token %d…: %d comparisons, want 2 (one per caller)", len(token), calls)
		}
	}
}

// T5
func TestNonCanonicalPathsRejected(t *testing.T) {
	const issues = "/github-issues/repos/elicollinson/Solenoid-Assistant/issues"
	for _, p := range []string{
		issues + "/../../../user",
		issues + "/%2e%2e/%2e%2e/%2e%2e/user",
		issues + "/%2E%2e%2fuser",
		issues + "/1%2f..%2f..%2fuser",
		issues + "/1%2F..",
		issues + "/1%5c..%5cuser",
		issues + "\\..\\user",
		issues + "/1%00",
		"/github-issues//repos/elicollinson/Solenoid-Assistant/issues",
		issues + "/.",
		issues + "/1.",
		issues + "/",
		issues + ";x=1",
		"/github-issues/../openrouter/models",
		"/github-issues/./repos/elicollinson/Solenoid-Assistant/issues",
	} {
		t.Run(p, func(t *testing.T) {
			hs := newHarness(t, nil)
			if got := hs.raw("GET "+p+" HTTP/1.1", "Authorization: Bearer "+aliceToken); got != 400 {
				t.Fatalf("status = %d, want 400", got)
			}
			hs.wantUntouched()
		})
	}
}

// T6
func TestAllowlistMethodsAndGlobs(t *testing.T) {
	const issues = "/github-issues/repos/elicollinson/Solenoid-Assistant/issues"
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{"GET", issues, 200},
		{"PATCH", issues + "/12", 200},
		{"DELETE", issues + "/12", 403},
		{"GET", issues + "/12/comments", 403},
		{"GET", "/github-issues/repos/elicollinson/other/issues", 403},
		{"GET", "/github-issues/files/a", 200},
		{"GET", "/github-issues/files/a/b/c", 200},
		{"GET", "/github-issues/files", 403},
		{"GET", "/github-issues", 403},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			hs := newHarness(t, nil)
			wantStatus(t, hs.do(tc.method, tc.path, bearer(aliceToken), nil), tc.want)
			if tc.want == 403 {
				hs.wantUntouched()
			}
		})
	}
}

// T7
func TestClientCredentialsStripped(t *testing.T) {
	hs := newHarness(t, nil)
	h := http.Header{
		"X-Subscription-Token": {aliceToken},
		"Authorization":        {"Bearer sk-callers-own-key"},
		"Proxy-Authorization":  {"Basic eDp5"},
		"Cookie":               {"session=abc"},
		"X-Goog-Api-Key":       {"AIza-callers-own"},
		"X-Api-Key":            {"callers-own"},
		"X-Forwarded-For":      {"10.0.0.1"},
		"X-Forwarded-Host":     {"evil.test"},
		"Forwarded":            {"host=evil.test"},
		"X-Keep":               {"yes"},
	}
	wantStatus(t, hs.do("GET", "/search/web?q=hello", h, nil), 200)
	got := hs.up.last(t)
	if v := got.Header.Values("Authorization"); len(v) != 1 || v[0] != "Bearer "+searchSecret {
		t.Errorf("upstream Authorization = %q", v)
	}
	for _, name := range []string{"Proxy-Authorization", "Cookie", "X-Goog-Api-Key", "X-Api-Key", "X-Subscription-Token", "X-Forwarded-For", "X-Forwarded-Host", "Forwarded"} {
		if v := got.Header.Get(name); v != "" {
			t.Errorf("%s forwarded: %q", name, v)
		}
	}
	if got.Header.Get("X-Keep") != "yes" {
		t.Error("ordinary header dropped")
	}
	if q := got.URL.Query(); q.Get("q") != "hello" || len(q) != 1 {
		t.Errorf("upstream query = %q", got.URL.RawQuery)
	}

	// A route's query slot is stripped in every case variant.
	wantStatus(t, hs.do("GET", "/github-issues/repos/elicollinson/Solenoid-Assistant/issues?state=open&KEY=own&Key=own2",
		http.Header{"X-Subscription-Token": {aliceToken}}, nil), 200)
	if q := hs.up.last(t).URL.RawQuery; q != "state=open" {
		t.Errorf("upstream query = %q", q)
	}
}

// T8
func TestUpstreamComesOnlyFromConfig(t *testing.T) {
	t.Run("Host header", func(t *testing.T) {
		hs := newHarness(t, nil)
		req, _ := http.NewRequest("GET", "http://"+hs.addr+"/openrouter/models", nil)
		req.Host = "evil.test"
		req.Header = bearer(aliceToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		wantStatus(t, resp, 400)
		hs.wantUntouched()
	})
	t.Run("absolute-form URI", func(t *testing.T) {
		hs := newHarness(t, nil)
		if got := hs.raw("GET https://evil.test/openrouter/models HTTP/1.1", "Authorization: Bearer "+aliceToken); got != 400 {
			t.Fatalf("status = %d", got)
		}
		hs.wantUntouched()
	})
	t.Run("CONNECT", func(t *testing.T) {
		hs := newHarness(t, nil)
		if got := hs.raw("CONNECT evil.test:443 HTTP/1.1", "Authorization: Bearer "+aliceToken); got != 400 {
			t.Fatalf("status = %d", got)
		}
		hs.wantUntouched()
	})
	t.Run("forwarding headers", func(t *testing.T) {
		hs := newHarness(t, nil)
		h := bearer(aliceToken)
		h.Set("X-Forwarded-Host", "evil.test")
		h.Set("X-Forwarded-Proto", "http")
		wantStatus(t, hs.do("GET", "/openrouter/models", h, nil), 200)
		if got := hs.up.last(t); got.Host != "up.test" || got.TLS == nil {
			t.Errorf("upstream host = %q", got.Host)
		}
	})
}

func TestEvilHostNeverContacted(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://evil.test/steal")
		w.WriteHeader(302)
	})
	h := bearer(aliceToken)
	h.Set("X-Forwarded-Host", "evil.test")
	hs.do("GET", "/openrouter/redirect/offsite", h, nil)
	hs.raw("GET https://evil.test/openrouter/models HTTP/1.1", "Authorization: Bearer "+aliceToken)
	if n := hs.evil.conns.Load(); n != 0 {
		t.Fatalf("evil.test got %d connections", n)
	}
}

// T9
func TestBrowserAndRebindingRejected(t *testing.T) {
	hs := newHarness(t, nil)
	h := bearer(aliceToken)
	h.Set("Origin", "https://evil.test")
	wantStatus(t, hs.do("GET", "/openrouter/models", h, nil), 400)
	hs.wantUntouched()

	_, port, _ := strings.Cut(hs.addr, ":")
	req, _ := http.NewRequest("GET", "http://"+hs.addr+"/openrouter/models", nil)
	req.Host = "localhost:" + port
	req.Header = bearer(aliceToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	wantStatus(t, resp, 200)
}

// T10
func TestRedirects(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/redirect/offsite":
			w.Header().Set("Location", "https://evil.test/steal")
		case "/api/v1/redirect/outside-base":
			w.Header().Set("Location", "https://up.test/other/place")
		case "/api/v1/redirect/same":
			w.Header().Set("Location", "https://up.test/api/v1/models?page=2")
		case "/api/v1/redirect/relative":
			w.Header().Set("Location", "/api/v1/models")
		}
		w.WriteHeader(http.StatusFound)
	})
	for path, want := range map[string]string{
		"offsite":      "",
		"outside-base": "",
		"same":         "/openrouter/models?page=2",
		"relative":     "/openrouter/models",
	} {
		t.Run(path, func(t *testing.T) {
			resp := hs.do("GET", "/openrouter/redirect/"+path, bearer(aliceToken), nil)
			if want == "" {
				wantStatus(t, resp, 502)
				if loc := resp.Header.Get("Location"); loc != "" {
					t.Errorf("Location leaked: %q", loc)
				}
				return
			}
			wantStatus(t, resp, 302)
			if loc := resp.Header.Get("Location"); loc != want {
				t.Errorf("Location = %q, want %q", loc, want)
			}
		})
	}
	if n := hs.evil.conns.Load(); n != 0 {
		t.Fatalf("redirect followed: evil.test got %d connections", n)
	}
}

// T11
func TestEchoedSecretRedacted(t *testing.T) {
	hs := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch r.URL.Path {
		case "/api/v1/echo/header":
			w.Header().Set("X-Echo", "you sent "+secret)
		case "/api/v1/echo/body":
			io.WriteString(w, `{"raw":"`+secret+`","escaped":"`+strings.ReplaceAll(secret, "-", `-`)+`"}`)
			return
		case "/api/v1/echo/split":
			io.WriteString(w, "a"+secret[:7])
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
			io.WriteString(w, secret[7:]+"z")
			return
		case "/api/v1/echo/length":
			msg := "len " + secret
			w.Header().Set("Content-Length", strconv.Itoa(len(msg)))
			io.WriteString(w, msg)
			return
		}
		io.WriteString(w, "ok")
	})
	for _, path := range []string{"header", "body", "split", "length"} {
		t.Run(path, func(t *testing.T) {
			resp := hs.do("GET", "/openrouter/echo/"+path, bearer(aliceToken), nil)
			wantStatus(t, resp, 200)
			got := body(t, resp) + resp.Header.Get("X-Echo")
			if strings.Contains(got, openrouterSecret) {
				t.Fatalf("secret reached the caller: %q", got)
			}
			if !strings.Contains(got, "[redacted]") {
				t.Fatalf("no redaction marker in %q", got)
			}
		})
	}
	if !strings.Contains(logAfter(t, 0, "upstream_echoed_secret"), "upstream_echoed_secret") {
		t.Error("echo not logged as an alert")
	}
}

func TestScrubberAcrossReadBoundaries(t *testing.T) {
	secret := "SECRET-0123456789"
	in := "x" + secret + "y" + secret[:5] + "-not-it " + secret
	r := newScrubber(io.NopCloser(iotest.OneByteReader(strings.NewReader(in))), newRedactor([]string{secret}), func() {})
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(in) {
		t.Fatalf("length changed: %d → %d", len(in), len(out))
	}
	if strings.Contains(string(out), secret) || strings.Count(string(out), "[redacted]") != 2 {
		t.Fatalf("got %q", out)
	}
	if !strings.Contains(string(out), secret[:5]+"-not-it") {
		t.Fatalf("partial match was mangled: %q", out)
	}
}

func TestScrubberDoesNotHoldBackUnrelatedBytes(t *testing.T) {
	pr, pw := io.Pipe()
	r := newScrubber(pr, newRedactor([]string{"SECRET-0123456789"}), func() {})
	go pw.Write([]byte("data: event one\n\n"))
	buf := make([]byte, 64)
	done := make(chan int)
	go func() { n, _ := io.ReadAtLeast(r, buf, 17); done <- n }()
	select {
	case n := <-done:
		if string(buf[:n]) != "data: event one\n\n" {
			t.Fatalf("got %q", buf[:n])
		}
	case <-time.After(time.Second):
		t.Fatal("scrubber held back a complete event")
	}
	pw.Close()
}

// T12 runs in TestMain over the whole suite; these exercise the error paths
// whose messages would carry a URL, a query or a panic value.
func TestErrorPathsLogNoSecrets(t *testing.T) {
	hs := newHarness(t, nil)
	for path, want := range map[string]int{
		"/dead/x?key=" + canary:      502,
		"/wrongcert/x?key=" + canary: 502,
		"/boom/x?key=" + canary:      500,
	} {
		resp := hs.do("GET", path, bearer(aliceToken), nil)
		wantStatus(t, resp, want)
		if b := body(t, resp); strings.Contains(b, canary) || strings.Contains(b, openrouterSecret) {
			t.Errorf("%s: error body leaks: %q", path, b)
		}
	}
}

func TestMissingCredentialIs503(t *testing.T) {
	hs := newHarness(t, nil)
	delete(hs.store.items, "credproxy/openrouter")
	wantStatus(t, hs.do("GET", "/openrouter/models", bearer(aliceToken), nil), 503)
	if hs.up.hits.Load() != 0 {
		t.Error("upstream contacted without a credential")
	}
}

func TestLogLineShape(t *testing.T) {
	hs := newHarness(t, nil)
	before := logs.Len()
	hs.do("GET", "/github-issues/repos/elicollinson/Solenoid-Assistant/issues/77?state=open", bearer(aliceToken), nil)
	line := logAfter(t, before, `"caller":"alice"`)
	for _, want := range []string{`"caller":"alice"`, `"route":"github-issues"`, `"path_template":"/repos/elicollinson/Solenoid-Assistant/issues/*"`, `"status":200`, `"latency_ms"`, `"bytes_out"`} {
		if !strings.Contains(line, want) {
			t.Errorf("log line lacks %s: %s", want, line)
		}
	}
	if strings.Contains(line, "/77") || strings.Contains(line, "state=") {
		t.Errorf("log line has the real path or query: %s", line)
	}
}

// T16
func TestRateLimitIsPerCaller(t *testing.T) {
	hs := newHarness(t, nil)
	// bob: 6/min, so a burst of 1 and one token every 10 s.
	wantStatus(t, hs.do("GET", "/openrouter/models", bearer(bobToken), nil), 200)
	wantStatus(t, hs.do("GET", "/openrouter/models", bearer(bobToken), nil), 429)
	wantStatus(t, hs.do("GET", "/openrouter/models", bearer(aliceToken), nil), 200)
	hs.clock.Advance(10 * time.Second)
	wantStatus(t, hs.do("GET", "/openrouter/models", bearer(bobToken), nil), 200)
	for range 20 {
		wantStatus(t, hs.do("GET", "/openrouter/models", bearer(strangerToken), nil), 401)
	}
}

// T17
func TestBodyLimit(t *testing.T) {
	hs := newHarness(t, nil)
	wantStatus(t, hs.do("POST", "/openrouter/chat/completions", bearer(aliceToken), strings.NewReader(strings.Repeat("x", 2048))), 413)
	if hs.up.hits.Load() != 0 {
		t.Error("oversized body forwarded")
	}
	chunked := io.MultiReader(strings.NewReader(strings.Repeat("x", 2048))) // no Content-Length
	wantStatus(t, hs.do("POST", "/openrouter/chat/completions", bearer(aliceToken), chunked), 413)
	wantStatus(t, hs.do("POST", "/openrouter/chat/completions", bearer(aliceToken), strings.NewReader("{}")), 200)
}

// T19
func TestTransportAndServerSettings(t *testing.T) {
	hs := newHarness(t, nil)
	tr := newTransport(Options{}, hs.p.routes["openrouter"].cfg)
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 || tr.TLSClientConfig.InsecureSkipVerify {
		t.Errorf("TLS config = %+v", tr.TLSClientConfig)
	}
	if tr.Proxy != nil {
		t.Error("transport honours HTTP_PROXY; a polluted environment could redirect credentials")
	}
	if tr.DialContext == nil || tr.TLSHandshakeTimeout == 0 || !tr.ForceAttemptHTTP2 {
		t.Errorf("transport timeouts or HTTP/2 not set: %+v", tr)
	}
	srv := hs.p.Server("127.0.0.1:0")
	if srv.ReadHeaderTimeout == 0 || srv.WriteTimeout != 0 || srv.MaxHeaderBytes != 64<<10 || srv.ErrorLog == nil {
		t.Errorf("server settings: ReadHeaderTimeout %v, WriteTimeout %v, MaxHeaderBytes %d", srv.ReadHeaderTimeout, srv.WriteTimeout, srv.MaxHeaderBytes)
	}
}

func TestNoInsecureSkipVerifyOutsideTests(t *testing.T) {
	root := filepath.Join("..", "..")
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		if b, _ := os.ReadFile(path); strings.Contains(string(b), "Insecure"+"SkipVerify") {
			t.Errorf("%s mentions InsecureSkipVerify", path)
		}
		return nil
	})
}
