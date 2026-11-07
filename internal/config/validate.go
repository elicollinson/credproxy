package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	defaultListen       = "127.0.0.1:8787"
	defaultService      = "credproxy"
	defaultMaxBodyBytes = 32 << 20
	defaultRatePerMin   = 60
	maxRatePerMin       = 10_000
)

// Methods an allowlist rule may name.
var Methods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}

var (
	routeName  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	paramName  = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

	// Headers a route may never read a token from or write a credential to.
	reservedHeaders = []string{
		"Host", "Content-Length", "Transfer-Encoding", "Connection", "Keep-Alive",
		"Te", "Trailer", "Upgrade", "Proxy-Authorization", "Proxy-Connection", "Cookie",
	}
)

type errs []error

func (e *errs) add(field, format string, args ...any) {
	*e = append(*e, fmt.Errorf("%s: %s", field, fmt.Sprintf(format, args...)))
}

func (c *Config) validate() error {
	var e errs
	if len(c.Listen) == 0 {
		c.Listen = []string{defaultListen}
	}
	for i, addr := range c.Listen {
		field := fmt.Sprintf("listen[%d]", i)
		ip, ok := hostPort(addr)
		if !ok || ip == nil {
			e.add(field, "%q must be an IP literal and port", addr)
			continue
		}
		if !ip.IsLoopback() {
			if !c.AllowNonLoopback {
				e.add(field, "%q is not loopback; set allow_non_loopback to accept it", addr)
				continue
			}
			c.Warnings = append(c.Warnings, fmt.Sprintf("listening on non-loopback address %s", addr))
		}
	}
	for i, alias := range c.HostAliases {
		if _, ok := hostPort(alias); !ok {
			e.add(fmt.Sprintf("host_aliases[%d]", i), "%q must be host:port", alias)
		}
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = defaultMaxBodyBytes
	} else if c.MaxBodyBytes < 0 {
		e.add("max_body_bytes", "must be positive")
	}

	if len(c.Routes) == 0 {
		e.add("routes", "at least one route is required")
	}
	for name, r := range c.Routes {
		field := "routes." + name
		if !routeName.MatchString(name) {
			e.add(field, "route names must match %s", routeName)
			continue
		}
		if r == nil {
			e.add(field, "must be an object")
			continue
		}
		r.Name = name
		r.validate(field, c.MaxBodyBytes, &e)
	}

	if len(c.Callers) == 0 {
		e.add("callers", "at least one caller is required")
	}
	used := map[string]bool{}
	hashes := map[string]string{}
	for name, k := range c.Callers {
		field := "callers." + name
		if k == nil {
			e.add(field, "must be an object")
			continue
		}
		k.Name = name
		sum, err := hex.DecodeString(k.TokenSHA256)
		if err != nil || len(sum) != 32 || k.TokenSHA256 != strings.ToLower(k.TokenSHA256) {
			e.add(field+".token_sha256", "must be 64 lowercase hex characters")
		} else if other, dup := hashes[k.TokenSHA256]; dup {
			e.add(field+".token_sha256", "same as callers.%s", other)
		} else {
			hashes[k.TokenSHA256] = name
			copy(k.Hash[:], sum)
		}
		if len(k.Routes) == 0 {
			e.add(field+".routes", "at least one route is required")
		}
		for _, rn := range k.Routes {
			if _, ok := c.Routes[rn]; !ok {
				e.add(field+".routes", "unknown route %q", rn)
			}
			used[rn] = true
		}
		switch {
		case k.RateLimitPerMin == 0:
			k.RateLimitPerMin = defaultRatePerMin
		case k.RateLimitPerMin < 0 || k.RateLimitPerMin > maxRatePerMin:
			e.add(field+".rate_limit_per_min", "must be between 1 and %d", maxRatePerMin)
		}
	}
	for name := range c.Routes {
		if !used[name] {
			c.Warnings = append(c.Warnings, fmt.Sprintf("route %s has no callers", name))
		}
	}
	slices.Sort(c.Warnings)
	slices.SortFunc(e, func(a, b error) int { return strings.Compare(a.Error(), b.Error()) })
	return errors.Join(e...)
}

func (r *Route) validate(field string, maxBody int64, e *errs) {
	u, err := url.Parse(r.Upstream)
	switch {
	case err != nil:
		e.add(field+".upstream", "not a URL")
	case u.Scheme != "https":
		e.add(field+".upstream", "must be https")
	case u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "":
		e.add(field+".upstream", "must not have userinfo, a query, a fragment or escaped characters")
	case u.Hostname() == "" || net.ParseIP(u.Hostname()) != nil:
		e.add(field+".upstream", "host must be a DNS name, so TLS is verified by name")
	case u.Path != "" && u.Path != "/" && !CanonicalPath(u.Path):
		e.add(field+".upstream", "path must be canonical, without a trailing slash")
	default:
		u.Path = strings.TrimSuffix(u.Path, "/") // a bare host's "/"
		r.Base = u
	}

	if r.Credential.Service == "" {
		r.Credential.Service = defaultService
	}
	if r.Credential.Account == "" {
		e.add(field+".credential.account", "is required")
	}
	validateInject(field+".inject", r.Inject, e)

	if len(r.CallerAuth) == 0 {
		r.CallerAuth = []string{string(SlotBearer)}
	}
	for _, s := range r.CallerAuth {
		slot, ok := parseSlot(s)
		if !ok {
			e.add(field+".caller_auth", "%q must be bearer, basic_password, header:<name> or query:<name>", s)
			continue
		}
		r.Slots = append(r.Slots, slot)
		switch slot.Kind {
		case SlotHeader:
			r.StripHeaders = append(r.StripHeaders, slot.Name)
		case SlotQuery:
			r.StripParams = append(r.StripParams, strings.ToLower(slot.Name))
		}
	}
	switch r.Inject.Type {
	case "header":
		r.StripHeaders = append(r.StripHeaders, r.Inject.Name)
	case "query":
		r.StripParams = append(r.StripParams, strings.ToLower(r.Inject.Name))
	}

	switch {
	case r.MaxBodyBytes == 0:
		r.MaxBodyBytes = maxBody
	case r.MaxBodyBytes < 0:
		e.add(field+".max_body_bytes", "must be positive")
	}
	if r.FirstByteTimeoutMS < 0 {
		e.add(field+".first_byte_timeout_ms", "must not be negative")
	}

	if len(r.Allow) == 0 {
		e.add(field+".allow", "at least one rule is required")
	}
	for i, rule := range r.Allow {
		rf := fmt.Sprintf("%s.allow[%d]", field, i)
		if len(rule.Methods) == 0 {
			e.add(rf+".methods", "at least one method is required")
		}
		for _, m := range rule.Methods {
			if !slices.Contains(Methods, m) {
				e.add(rf+".methods", "%q must be one of %s", m, strings.Join(Methods, ", "))
			}
		}
		if len(rule.Paths) == 0 {
			e.add(rf+".paths", "at least one path is required")
		}
		for _, p := range rule.Paths {
			if !validPattern(p) {
				e.add(rf+".paths", "%q must be canonical, with * and a final ** only as whole segments", p)
			}
		}
	}
}

// injectFields is the one optional field each inject type uses.
var injectFields = map[string]string{
	"bearer": "", "header": "name", "basic": "username", "query": "name", "google_service_account": "scopes",
}

func validateInject(field string, in Inject, e *errs) {
	uses, ok := injectFields[in.Type]
	if !ok {
		e.add(field+".type", "%q must be bearer, header, basic, query or google_service_account", in.Type)
		return
	}
	for name, set := range map[string]bool{"name": in.Name != "", "username": in.Username != "", "scopes": in.Scopes != nil} {
		if set && name != uses {
			e.add(field, "%s is not used by type %s", name, in.Type)
		}
	}
	switch in.Type {
	case "header":
		if !validHeader(in.Name) {
			e.add(field+".name", "must be a header name other than %s", strings.Join(reservedHeaders, ", "))
		}
	case "basic":
		if in.Username == "" || strings.Contains(in.Username, ":") {
			e.add(field+".username", "is required and must not contain ':'")
		}
	case "query":
		if !paramName.MatchString(in.Name) {
			e.add(field+".name", "must be a query parameter name matching %s", paramName)
		}
	case "google_service_account":
		if len(in.Scopes) == 0 {
			e.add(field+".scopes", "at least one scope is required")
		}
		for _, s := range in.Scopes {
			if !strings.HasPrefix(s, "https://www.googleapis.com/auth/") {
				e.add(field+".scopes", "%q is not a Google OAuth scope", s)
			}
		}
	}
}

func parseSlot(s string) (Slot, bool) {
	switch kind, name, _ := strings.Cut(s, ":"); SlotKind(kind) {
	case SlotBearer, SlotBasicPassword:
		return Slot{Kind: SlotKind(kind)}, name == "" && !strings.Contains(s, ":")
	case SlotHeader:
		return Slot{Kind: SlotHeader, Name: name}, validHeader(name)
	case SlotQuery:
		return Slot{Kind: SlotQuery, Name: name}, paramName.MatchString(name)
	}
	return Slot{}, false
}

func validHeader(name string) bool {
	return headerName.MatchString(name) && !slices.ContainsFunc(reservedHeaders, func(h string) bool {
		return strings.EqualFold(h, name)
	})
}

// validPattern accepts a canonical path whose segments may be * (exactly one
// segment) or, last, ** (one or more).
func validPattern(p string) bool {
	if !CanonicalPath(p) {
		return false
	}
	segs := strings.Split(p[1:], "/")
	for i, s := range segs {
		if s == "**" && i == len(segs)-1 {
			continue
		}
		if s != "*" && strings.Contains(s, "*") {
			return false
		}
	}
	return true
}

// CanonicalPath reports whether p is already in canonical form: absolute,
// unchanged by path.Clean (so no empty, "." or ".." segments and no trailing
// slash), with no segment ending in "." and no "\" or ";", which some
// servers treat as separators.
func CanonicalPath(p string) bool {
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.ContainsAny(p, `\;`) {
		return false
	}
	for _, s := range strings.Split(p[1:], "/") {
		if strings.HasSuffix(s, ".") {
			return false
		}
	}
	return true
}

// hostPort splits a host:port with a numeric port, returning the host as an
// IP when it is one.
func hostPort(addr string) (net.IP, bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return nil, false
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, false
	}
	return net.ParseIP(host), true
}
