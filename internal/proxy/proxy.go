// Package proxy is the credential-injecting reverse proxy.
package proxy

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/elicollinson/credproxy/internal/config"
	"github.com/elicollinson/credproxy/internal/keychain"
)

// Options are the seams tests need. Production leaves them zero.
type Options struct {
	Log         io.Writer
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	RootCAs     *x509.CertPool
	Now         func() time.Time
}

// ctEqual compares token hashes; a variable so a test can count calls.
var ctEqual = subtle.ConstantTimeCompare

// Stub: the proxy lands after the failing tests are committed.
type Proxy struct{ routes map[string]*route }

type route struct{ cfg *config.Route }

func New(cfg *config.Config, store keychain.Store, opts Options) (*Proxy, error) {
	return &Proxy{}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}

func (p *Proxy) Server(addr string) *http.Server { return &http.Server{Addr: addr, Handler: p} }

func newTransport(opts Options, r *config.Route) *http.Transport { return &http.Transport{} }

func newScrubber(body io.ReadCloser, needles []string, onHit func()) io.ReadCloser { return body }
