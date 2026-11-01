// Package inject turns a stored secret into the credential an upstream
// expects.
package inject

import (
	"context"
	"fmt"
	"net/http"

	"github.com/elicollinson/credproxy/internal/config"
	"github.com/elicollinson/credproxy/internal/keychain"
)

// Injector gets one route's credential for one request. Acquire runs before
// forwarding, so it may fail (a missing key, a token endpoint that's down);
// a type that mints tokens keeps its cache behind it. Adding a type means an
// implementation here and a case in config validation.
type Injector interface {
	Acquire(ctx context.Context, store keychain.Store) (Cred, error)
}

// Cred is a credential ready to attach: a header, or a query parameter.
type Cred struct {
	Header, Param, Value string
	// Needles are the forms of the secret the response scrubber looks for.
	Needles []string
}

// Apply sets the credential on out, replacing anything already there.
func (c Cred) Apply(out *http.Request) {
	if c.Header != "" {
		out.Header.Set(c.Header, c.Value)
	}
	if c.Param != "" {
		q := out.URL.Query()
		q.Set(c.Param, c.Value)
		out.URL.RawQuery = q.Encode()
	}
}

// New returns the injector for a route. Phase 1 has bearer only.
func New(r *config.Route) (Injector, error) {
	switch r.Inject.Type {
	case "bearer":
		return bearer{r.Credential}, nil
	}
	return nil, fmt.Errorf("inject type %q is not implemented yet", r.Inject.Type)
}

type bearer struct{ cred config.Credential }

func (b bearer) Acquire(_ context.Context, store keychain.Store) (Cred, error) {
	secret, err := store.Get(b.cred.Service, b.cred.Account)
	if err != nil {
		return Cred{}, err
	}
	s := string(secret)
	clear(secret)
	return Cred{Header: "Authorization", Value: "Bearer " + s, Needles: []string{s}}, nil
}
