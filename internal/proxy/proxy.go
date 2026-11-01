// Package proxy is the credential-injecting reverse proxy. A request passes,
// in order: target checks (R1, R7), path canonicalisation (R5), caller
// authentication (R3, R4), route and allowlist checks (R2), the rate limit
// (R15) and the body limit (R14). Only then is the credential read and the
// request forwarded with its credentials stripped and the real one injected
// (R6). Responses have redirects contained (R8) and echoed secrets scrubbed
// (R11). DESIGN.md §5 lists the rules.
package proxy

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/elicollinson/credproxy/internal/config"
	"github.com/elicollinson/credproxy/internal/inject"
	"github.com/elicollinson/credproxy/internal/keychain"
)

// Options are the seams tests need. Production leaves them zero.
type Options struct {
	Log         *slog.Logger
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	RootCAs     *x509.CertPool
	Now         func() time.Time
}

// ctEqual compares token hashes; a variable so a test can count calls.
var ctEqual = subtle.ConstantTimeCompare

// Headers that carry credentials or forwarding claims. They are removed from
// every outbound request, alongside each route's own StripHeaders (R6, R7).
var strippedHeaders = []string{
	"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "Api-Key", "X-Goog-Api-Key",
	"Forwarded", "Via", "X-Real-Ip",
	// Compression is negotiated by the transport (HTTP) or not at all
	// (WebSocket), so the response scrubber always sees plain bytes.
	"Accept-Encoding", "Sec-Websocket-Extensions",
}

var errOffsiteRedirect = errors.New("redirect outside the upstream")

type Proxy struct {
	routes  map[string]*route
	callers []*caller
	hosts   map[string]bool
	store   keychain.Store
	log     *slog.Logger
	now     func() time.Time
}

type route struct {
	cfg    *config.Route
	inject inject.Injector
	rp     *httputil.ReverseProxy
}

// state is one request's progress, read by the rewrite and response hooks
// and written to the log at the end.
type state struct {
	method, route, caller, template, reason string
	rest                                    string // the path below the route name
	cred                                    inject.Cred
	red                                     *redactor
	echoed                                  bool
	bytesIn                                 countingReader
}

type stateKey struct{}

func New(cfg *config.Config, store keychain.Store, opts Options) (*Proxy, error) {
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	p := &Proxy{
		routes: map[string]*route{},
		hosts:  map[string]bool{},
		store:  store,
		log:    opts.Log,
		now:    opts.Now,
	}
	for _, addr := range cfg.Listen {
		_, port, _ := net.SplitHostPort(addr)
		p.hosts[strings.ToLower(addr)] = true
		p.hosts["localhost:"+port] = true
	}
	for _, alias := range cfg.HostAliases {
		p.hosts[strings.ToLower(alias)] = true
	}
	for name, rc := range cfg.Routes {
		inj, err := inject.New(rc)
		if err != nil {
			return nil, fmt.Errorf("routes.%s: %w", name, err)
		}
		rt := &route{cfg: rc, inject: inj}
		rt.rp = &httputil.ReverseProxy{
			Rewrite:        rt.rewrite,
			ModifyResponse: rt.modifyResponse,
			ErrorHandler:   p.proxyError,
			ErrorLog:       log.New(io.Discard, "", 0), // R10: no error text in logs
			Transport:      newTransport(opts, rc),
			FlushInterval:  -1,
		}
		p.routes[name] = rt
	}
	for _, c := range cfg.Callers {
		p.callers = append(p.callers, newCaller(c, opts.Now()))
	}
	return p, nil
}

func newTransport(opts Options, r *config.Route) *http.Transport {
	dial := opts.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	return &http.Transport{
		Proxy:                 nil, // never HTTP_PROXY: the environment must not pick where credentials go
		DialContext:           dial,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: opts.RootCAs},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: time.Duration(r.FirstByteTimeoutMS) * time.Millisecond,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
	}
}

// Server returns an http.Server for p. There is no read or write deadline,
// so long streams are never cut off (R12); ReadHeaderTimeout covers
// slowloris. Server errors are logged without their text, which can
// include request details.
func (p *Proxy) Server(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.New(serverErrors{p.log}, "", 0),
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	st := &state{method: logMethod(r.Method)}
	rec := &recorder{ResponseWriter: w}
	defer func() {
		v := recover()
		if v != nil && v != http.ErrAbortHandler {
			st.reason = "panic" // the value may hold anything; it is never logged
			if rec.status == 0 {
				deny(rec, http.StatusInternalServerError, st.reason)
			}
		}
		p.logRequest(st, rec, time.Since(start))
		if v == http.ErrAbortHandler {
			panic(v)
		}
	}()
	if status, reason := p.serve(rec, r, st); status != 0 {
		st.reason = reason
		deny(rec, status, reason)
	}
}

// serve forwards r, or returns the status and reason to refuse it with.
func (p *Proxy) serve(w http.ResponseWriter, r *http.Request, st *state) (int, string) {
	// R1, R7: only origin-form requests from non-browser local callers.
	if r.Method == http.MethodConnect || !strings.HasPrefix(r.RequestURI, "/") {
		return http.StatusBadRequest, "bad_request_target"
	}
	if _, ok := r.Header["Origin"]; ok {
		return http.StatusBadRequest, "browser_origin"
	}
	if !p.hosts[strings.ToLower(r.Host)] {
		return http.StatusBadRequest, "bad_host"
	}
	if !canonicalRequestPath(r.URL) {
		return http.StatusBadRequest, "non_canonical_path"
	}
	name, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	rt := p.routes[name]
	if rt == nil {
		return http.StatusNotFound, "unknown_route"
	}
	st.route = name
	if rest != "" {
		st.rest = "/" + rest
	}
	if r.Header.Get("Upgrade") != "" && !rt.cfg.WebSocket {
		return http.StatusBadRequest, "upgrade_not_allowed"
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return http.StatusBadRequest, "bad_query"
	}

	token, status, reason := callerToken(r, query, rt.cfg.Slots)
	if status != 0 {
		return status, reason
	}
	c := p.lookup(token)
	if c == nil {
		return http.StatusUnauthorized, "bad_token"
	}
	st.caller = c.Name
	if !slices.Contains(c.Routes, name) {
		return http.StatusForbidden, "route_not_allowed"
	}
	tmpl, ok := match(rt.cfg.Allow, r.Method, st.rest)
	if !ok {
		return http.StatusForbidden, "not_allowlisted"
	}
	st.template = tmpl
	if !c.bucket.take(p.now()) {
		return http.StatusTooManyRequests, "rate_limited"
	}
	if r.ContentLength > rt.cfg.MaxBodyBytes {
		return http.StatusRequestEntityTooLarge, "body_too_large"
	}
	if r.ContentLength < 0 {
		// A body of unknown length is read in full first, so an oversized
		// one never reaches the upstream at all (R14).
		b, err := io.ReadAll(io.LimitReader(r.Body, rt.cfg.MaxBodyBytes+1))
		if err != nil {
			return http.StatusBadRequest, "bad_body"
		}
		if int64(len(b)) > rt.cfg.MaxBodyBytes {
			return http.StatusRequestEntityTooLarge, "body_too_large"
		}
		r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(b)), int64(len(b))
	}

	st.cred, err = rt.inject.Acquire(r.Context(), p.store)
	if err != nil {
		return http.StatusServiceUnavailable, keychainReason(err)
	}
	st.red = newRedactor(st.cred.Needles)

	st.bytesIn.r = r.Body
	r.Body = &st.bytesIn
	rt.rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), stateKey{}, st)))
	return 0, ""
}

func stateOf(r *http.Request) *state { return r.Context().Value(stateKey{}).(*state) }

// rewrite builds the outbound request. ReverseProxy has already removed
// hop-by-hop headers and its own X-Forwarded-* headers.
func (rt *route) rewrite(pr *httputil.ProxyRequest) {
	st := stateOf(pr.In)
	out := pr.Out
	base := rt.cfg.Base
	out.URL.Scheme, out.URL.Host = base.Scheme, base.Host
	out.URL.Path, out.URL.RawPath = base.Path+st.rest, ""
	out.Host = ""
	if q := out.URL.Query(); rt.stripParams(q) {
		out.URL.RawQuery = q.Encode()
	}
	for _, h := range slices.Concat(strippedHeaders, rt.cfg.StripHeaders) {
		out.Header.Del(h)
	}
	for k := range out.Header {
		if strings.HasPrefix(k, "X-Forwarded-") {
			delete(out.Header, k)
		}
	}
	st.cred.Apply(out)
	st.cred = inject.Cred{}
}

// stripParams deletes the route's credential parameters from q, in every
// case variant (R6), and reports whether it removed any.
func (rt *route) stripParams(q url.Values) bool {
	removed := false
	for k := range q {
		if slices.Contains(rt.cfg.StripParams, strings.ToLower(k)) {
			delete(q, k)
			removed = true
		}
	}
	return removed
}

func (rt *route) modifyResponse(resp *http.Response) error {
	st := stateOf(resp.Request)
	resp.Header.Del("Set-Cookie")
	if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode/100 == 3 {
		proxied, ok := rt.proxyLocation(resp.Request.URL, loc)
		if !ok {
			return errOffsiteRedirect
		}
		resp.Header.Set("Location", proxied)
	}
	for _, vs := range resp.Header {
		for i, v := range vs {
			if b := []byte(v); st.red.redact(b) {
				vs[i] = string(b)
				st.echoed = true
			}
		}
	}
	// Phase 2 (R13) scrubs upgraded streams too; ReverseProxy needs their
	// body to stay an io.ReadWriteCloser.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Body = newScrubber(resp.Body, st.red, func() { st.echoed = true })
	}
	return nil
}

// proxyLocation maps a redirect on the upstream, under its base path, to the
// same place through the proxy, so the caller comes back through the
// allowlist. Anything else is refused (R8).
func (rt *route) proxyLocation(from *url.URL, loc string) (string, bool) {
	u, err := from.Parse(loc)
	base := rt.cfg.Base
	if err != nil || u.Scheme != base.Scheme || !strings.EqualFold(u.Host, base.Host) {
		return "", false
	}
	rest, ok := strings.CutPrefix(u.Path, base.Path)
	if !ok || (rest != "" && !strings.HasPrefix(rest, "/")) {
		return "", false
	}
	q := u.Query()
	rt.stripParams(q)
	return (&url.URL{Path: "/" + rt.cfg.Name + rest, RawQuery: q.Encode()}).String(), true
}

// proxyError answers a failed forward with a fixed reason. The error text
// is never logged or returned: it describes the upstream connection, and
// nothing here should depend on what it happens to include.
func (p *Proxy) proxyError(w http.ResponseWriter, r *http.Request, err error) {
	st := stateOf(r)
	switch {
	case errors.Is(err, errOffsiteRedirect):
		st.reason = "offsite_redirect"
		deny(w, http.StatusBadGateway, st.reason)
	case r.Context().Err() != nil:
		st.reason = "client_gone"
	default:
		st.reason = "upstream_error"
		deny(w, http.StatusBadGateway, st.reason)
	}
}

func keychainReason(err error) string {
	switch {
	case errors.Is(err, keychain.ErrLocked):
		return "keychain_locked"
	case errors.Is(err, keychain.ErrNotFound):
		return "credential_missing"
	case errors.Is(err, keychain.ErrDenied):
		return "keychain_denied"
	}
	return "keychain_error"
}

// deny writes a fixed error body: reason is always one of our own constants.
func deny(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	io.WriteString(w, `{"error":"`+reason+`"}`+"\n")
}
