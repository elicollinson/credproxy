package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/elicollinson/credproxy/internal/config"
	"github.com/elicollinson/credproxy/internal/keychain"
)

// Fixture secrets. TestMain fails the run if any of them, or "key=", reaches
// the proxy's log or the process's stderr (R10).
const (
	openrouterSecret = "sk-or-REAL-SECRET-0123456789abcdef"
	githubSecret     = "ghp_REAL_SECRET_abcdefghijklmnop"
	searchSecret     = "BSA-REAL-SECRET-zyxwvutsrqponmlk"
	braveSecret      = "BRAVE-REAL-SECRET-0123456789abcd"
	wandbSecret      = "wandb-REAL/SECRET+0123456789abcdef"
	geminiSecret     = "AIzaREAL-SECRET-0123456789abcdefgh"
	accessToken      = "ya29.REAL-ACCESS-TOKEN-" // the token endpoint appends a serial
	saEmail          = "proxy@my-proj.iam.gserviceaccount.com"
	aliceToken       = "cpx_alice_0000000000000000000000000000000000000"
	bobToken         = "cpx_bob_111111111111111111111111111111111111111"
	strangerToken    = "cpx_stranger_22222222222222222222222222222222222"
	canary           = "CANARY-ffffffffffffffff"
)

var leakNeedles = []string{
	openrouterSecret, githubSecret, searchSecret, braveSecret, wandbSecret, geminiSecret, accessToken,
	aliceToken, bobToken, strangerToken, canary, "key=", "PRIVATE KEY",
}

var (
	logs syncBuffer
	pki  struct {
		pool *x509.CertPool
		leaf tls.Certificate
	}
	// saKey signs the fixture service account's JWTs; saJSON and saBadJSON
	// are the Keychain items, the second with a token_uri we must refuse.
	saKey             *rsa.PrivateKey
	saJSON, saBadJSON string
)

func TestMain(m *testing.M) {
	pki.pool, pki.leaf = testPKI("up.test", "evil.test", "dead.test", "oauth2.googleapis.com")
	saKey, saJSON, saBadJSON = testServiceAccount()

	// Capture fd 2 itself, so the standard logger and runtime output are
	// checked too, not only writes through os.Stderr.
	saved, err := syscall.Dup(2)
	if err != nil {
		panic(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	if err := syscall.Dup2(int(w.Fd()), 2); err != nil {
		panic(err)
	}
	orig := os.NewFile(uintptr(saved), "stderr")
	var stderr bytes.Buffer
	done := make(chan struct{})
	go func() { io.Copy(io.MultiWriter(&stderr, orig), r); close(done) }()

	code := m.Run()

	syscall.Dup2(saved, 2)
	w.Close()
	<-done
	all := logs.String() + stderr.String()
	if logs.Len() == 0 {
		fmt.Fprintln(orig, "R10 check: the proxy logged nothing, so the check proved nothing")
		code = 1
	}
	for _, s := range leakNeedles {
		if strings.Contains(all, s) {
			fmt.Fprintf(orig, "R10 violated: output contains %q\n", s)
			code = 1
		}
	}
	os.Exit(code)
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.String() }
func (b *syncBuffer) Len() int       { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.Len() }

// testPKI makes a CA and a leaf for hosts, so the proxy verifies upstream TLS
// by name exactly as it does in production.
func testPKI(hosts ...string) (*x509.CertPool, tls.Certificate) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "credproxy test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: hosts[0]},
		DNSNames:     hosts,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

// testServiceAccount makes a key and the SA JSON Google issues for it.
func testServiceAccount() (*rsa.PrivateKey, string, string) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	sa := map[string]string{
		"type":           "service_account",
		"project_id":     "my-proj",
		"private_key_id": "kid-1",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   saEmail,
		"token_uri":      "https://oauth2.googleapis.com/token",
	}
	good, _ := json.Marshal(sa)
	sa["token_uri"] = "https://evil.test/token"
	bad, _ := json.Marshal(sa)
	return key, string(good), string(bad)
}

// upstream is a fake API that records what reached it.
type upstream struct {
	srv   *httptest.Server
	hits  atomic.Int64
	conns atomic.Int64
	mu    sync.Mutex
	seen  []*http.Request
}

func newUpstream(t *testing.T, h http.HandlerFunc) *upstream {
	u := &upstream{}
	u.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		u.mu.Lock()
		u.seen = append(u.seen, r.Clone(context.Background()))
		u.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		io.WriteString(w, "ok")
	}))
	u.srv.TLS = &tls.Config{Certificates: []tls.Certificate{pki.leaf}}
	u.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			u.conns.Add(1)
		}
	}
	u.srv.Config.ErrorLog = discardLogger
	u.srv.StartTLS()
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) last(t *testing.T) *http.Request {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.seen) == 0 {
		t.Fatal("upstream never saw a request")
	}
	return u.seen[len(u.seen)-1]
}

// memStore is the fake Keychain. Get on account "boom" panics with a secret
// in the panic value, to prove panics are logged without their value.
type memStore struct {
	items map[string]string
	gets  atomic.Int64
}

func (m *memStore) Get(service, account string) ([]byte, error) {
	m.gets.Add(1)
	if account == "boom" {
		panic("store exploded holding " + openrouterSecret)
	}
	s, ok := m.items[service+"/"+account]
	if !ok {
		return nil, keychain.ErrNotFound
	}
	return []byte(s), nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// testConfig has one route per behaviour under test. LISTEN is replaced with
// the proxy's address once it's bound.
var testConfig = `{
  "listen": ["LISTEN"],
  "routes": {
    "openrouter": {
      "upstream": "https://up.test/api/v1",
      "credential": {"account": "openrouter"},
      "inject": {"type": "bearer"},
      "max_body_bytes": 1024,
      "allow": [
        {"methods": ["POST"], "paths": ["/chat/completions"]},
        {"methods": ["GET"], "paths": ["/models", "/redirect/*", "/echo/*"]}
      ]
    },
    "github-issues": {
      "upstream": "https://up.test",
      "credential": {"account": "github"},
      "inject": {"type": "bearer"},
      "caller_auth": ["bearer", "header:X-Subscription-Token", "query:key", "basic_password"],
      "allow": [{"methods": ["GET", "POST", "PATCH"], "paths": [
        "/repos/elicollinson/Solenoid-Assistant/issues",
        "/repos/elicollinson/Solenoid-Assistant/issues/*",
        "/files/**"
      ]}]
    },
    "search": {
      "upstream": "https://up.test/search",
      "credential": {"account": "search"},
      "inject": {"type": "bearer"},
      "caller_auth": ["header:X-Subscription-Token"],
      "allow": [{"methods": ["GET"], "paths": ["/web"]}]
    },
    "dead": {
      "upstream": "https://dead.test",
      "credential": {"account": "search"},
      "inject": {"type": "bearer"},
      "allow": [{"methods": ["GET"], "paths": ["/x"]}]
    },
    "wrongcert": {
      "upstream": "https://wrongcert.test",
      "credential": {"account": "search"},
      "inject": {"type": "bearer"},
      "allow": [{"methods": ["GET"], "paths": ["/x"]}]
    },
    "boom": {
      "upstream": "https://up.test",
      "credential": {"account": "boom"},
      "inject": {"type": "bearer"},
      "allow": [{"methods": ["GET"], "paths": ["/x"]}]
    },
    "brave": {
      "upstream": "https://up.test/res/v1",
      "credential": {"account": "brave"},
      "inject": {"type": "header", "name": "X-Subscription-Token"},
      "caller_auth": ["header:X-Subscription-Token"],
      "allow": [{"methods": ["GET"], "paths": ["/web/search"]}]
    },
    "wandb": {
      "upstream": "https://up.test",
      "credential": {"account": "wandb"},
      "inject": {"type": "basic", "username": "api"},
      "caller_auth": ["basic_password"],
      "allow": [{"methods": ["POST"], "paths": ["/graphql", "/echo"]}]
    },
    "gemini": {
      "upstream": "https://up.test",
      "credential": {"account": "gemini"},
      "inject": {"type": "query", "name": "key"},
      "caller_auth": ["header:x-goog-api-key", "query:key"],
      "websocket": true,
      "allow": [
        {"methods": ["POST"], "paths": ["/v1beta/models/*"]},
        {"methods": ["GET"], "paths": ["/ws"]}
      ]
    },
    "gcp": {
      "upstream": "https://up.test",
      "credential": {"account": "gcp-sa"},
      "inject": {"type": "google_service_account", "scopes": ["https://www.googleapis.com/auth/cloud-platform"]},
      "allow": [{"methods": ["POST"], "paths": ["/v1/**"]}]
    },
    "gcp-bad": {
      "upstream": "https://up.test",
      "credential": {"account": "gcp-bad"},
      "inject": {"type": "google_service_account", "scopes": ["https://www.googleapis.com/auth/cloud-platform"]},
      "allow": [{"methods": ["POST"], "paths": ["/v1/**"]}]
    }
  },
  "callers": {
    "alice": {"token_sha256": "` + tokenHash(aliceToken) + `", "routes": ["openrouter", "github-issues", "search", "dead", "wrongcert", "boom", "brave", "wandb", "gemini", "gcp", "gcp-bad"]},
    "bob": {"token_sha256": "` + tokenHash(bobToken) + `", "routes": ["openrouter"], "rate_limit_per_min": 6}
  }
}`

type harness struct {
	t     *testing.T
	addr  string // the proxy, host:port
	up    *upstream
	evil  *upstream
	tok   *tokenServer
	store *memStore
	clock *fakeClock
	p     *Proxy
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

func newHarness(t *testing.T, h http.HandlerFunc) *harness {
	t.Helper()
	hs := &harness{
		t:    t,
		up:   newUpstream(t, h),
		evil: newUpstream(t, nil),
		store: &memStore{items: map[string]string{
			"credproxy/openrouter": openrouterSecret,
			"credproxy/github":     githubSecret,
			"credproxy/search":     searchSecret,
			"credproxy/brave":      braveSecret,
			"credproxy/wandb":      wandbSecret,
			"credproxy/gemini":     geminiSecret,
			"credproxy/gcp-sa":     saJSON,
			"credproxy/gcp-bad":    saBadJSON,
		}},
		clock: &fakeClock{now: time.Unix(1_800_000_000, 0)},
	}
	hs.tok = newTokenServer(t, hs.clock)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs.addr = ln.Addr().String()
	cfg, err := config.Parse([]byte(strings.ReplaceAll(testConfig, "LISTEN", hs.addr)))
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{}
	hs.p, err = New(cfg, hs.store, Options{
		Log:     slog.New(slog.NewJSONHandler(&logs, nil)),
		RootCAs: pki.pool,
		Now:     hs.clock.Now,
		// Upstream names resolve to the fakes; anything else, such as
		// dead.test, fails to dial. wrongcert.test reaches a server whose
		// certificate doesn't name it.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			switch addr {
			case "up.test:443", "wrongcert.test:443":
				return dialer.DialContext(ctx, network, hs.up.srv.Listener.Addr().String())
			case "evil.test:443":
				return dialer.DialContext(ctx, network, hs.evil.srv.Listener.Addr().String())
			case "oauth2.googleapis.com:443":
				return dialer.DialContext(ctx, network, hs.tok.up.srv.Listener.Addr().String())
			}
			return nil, fmt.Errorf("dial %s: no such host", addr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := hs.p.Server("")
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return hs
}

// do sends a request through the proxy without following redirects.
func (hs *harness) do(method, path string, header http.Header, body io.Reader) *http.Response {
	hs.t.Helper()
	req, err := http.NewRequest(method, "http://"+hs.addr+path, body)
	if err != nil {
		hs.t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		hs.t.Fatal(err)
	}
	hs.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// raw writes requestLine and headers byte-for-byte, so no client library can
// normalise the path first.
func (hs *harness) raw(requestLine string, headers ...string) int {
	hs.t.Helper()
	conn, err := net.Dial("tcp", hs.addr)
	if err != nil {
		hs.t.Fatal(err)
	}
	defer conn.Close()
	msg := requestLine + "\r\nHost: " + hs.addr + "\r\nConnection: close\r\n"
	for _, h := range headers {
		msg += h + "\r\n"
	}
	if _, err := io.WriteString(conn, msg+"\r\n"); err != nil {
		hs.t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		hs.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func bearer(token string) http.Header { return http.Header{"Authorization": {"Bearer " + token}} }

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func wantStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("status = %d, want %d", resp.StatusCode, want)
	}
}

func (hs *harness) wantUntouched() {
	hs.t.Helper()
	if n := hs.up.hits.Load(); n != 0 {
		hs.t.Errorf("upstream hit %d times", n)
	}
	if n := hs.store.gets.Load(); n != 0 {
		hs.t.Errorf("keychain read %d times", n)
	}
}
