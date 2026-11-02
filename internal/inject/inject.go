// Package inject turns a stored secret into the credential an upstream
// expects.
package inject

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

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

// Env is what an injector that mints tokens needs: a client for the token
// endpoint and a clock.
type Env struct {
	Client *http.Client
	Now    func() time.Time
}

var (
	// ErrInvalid means the stored credential can't be used as it is.
	ErrInvalid = errors.New("inject: stored credential is invalid")
	// ErrMint means a token endpoint didn't give us a token.
	ErrMint = errors.New("inject: token endpoint failed")
)

// New returns the injector for a route.
func New(r *config.Route, env Env) (Injector, error) {
	in := r.Inject
	switch in.Type {
	case "bearer":
		return static{r.Credential, func(s string) Cred {
			return Cred{Header: "Authorization", Value: "Bearer " + s}
		}}, nil
	case "header":
		return static{r.Credential, func(s string) Cred { return Cred{Header: in.Name, Value: s} }}, nil
	case "basic":
		return static{r.Credential, func(s string) Cred {
			enc := base64.StdEncoding.EncodeToString([]byte(in.Username + ":" + s))
			return Cred{Header: "Authorization", Value: "Basic " + enc, Needles: []string{enc}}
		}}, nil
	case "query":
		return static{r.Credential, func(s string) Cred {
			return Cred{Param: in.Name, Value: s, Needles: []string{url.QueryEscape(s)}}
		}}, nil
	case "google_service_account":
		return &serviceAccount{cred: r.Credential, scope: strings.Join(in.Scopes, " "), env: env}, nil
	}
	return nil, fmt.Errorf("inject type %q is not implemented", in.Type)
}

// static is a type that sends the stored secret itself, in some form.
type static struct {
	cred config.Credential
	form func(secret string) Cred
}

func (st static) Acquire(_ context.Context, store keychain.Store) (Cred, error) {
	secret, err := store.Get(st.cred.Service, st.cred.Account)
	if err != nil {
		return Cred{}, err
	}
	s := string(secret)
	clear(secret)
	c := st.form(s)
	c.Needles = append(c.Needles, s)
	return c, nil
}
