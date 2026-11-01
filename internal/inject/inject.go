// Package inject attaches an upstream credential to an outbound request.
package inject

import (
	"net/http"

	"github.com/elicollinson/credproxy/internal/config"
)

// Injector puts one kind of credential on a request. Adding a type means a
// new implementation here and a case in config validation.
type Injector interface {
	// Apply attaches secret to out and returns every form of it that may
	// appear on the wire, for the response scrubber.
	Apply(out *http.Request, secret string) []string
	// Header and Param name where the credential goes, so a caller's own
	// copy is stripped first. Empty when unused.
	Header() string
	Param() string
}

// Stub: injection lands after the failing tests are committed.
func New(c config.Inject) (Injector, error) { return bearer{}, nil }

type bearer struct{}

func (bearer) Apply(out *http.Request, secret string) []string { return nil }
func (bearer) Header() string                                  { return "" }
func (bearer) Param() string                                   { return "" }
