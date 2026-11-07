package proxy

import (
	"net/url"
	"slices"
	"strings"

	"github.com/elicollinson/credproxy/internal/config"
)

// canonicalRequestPath rejects any path that is not already canonical
// (R5). Encoded separators and dots are refused on the raw form, before
// decoding could hide them; the decoded path must then pass the same check
// config paths do. The proxy forwards exactly the decoded path it matched.
func canonicalRequestPath(u *url.URL) bool {
	raw := strings.ToLower(u.EscapedPath())
	for _, bad := range []string{"%2e", "%2f", "%5c", "%00"} {
		if strings.Contains(raw, bad) {
			return false
		}
	}
	return config.CanonicalPath(u.Path)
}

// match returns the allowlist pattern that admits method and rest, the path
// below the route name.
func match(rules []config.Rule, method, rest string) (string, bool) {
	if rest == "" {
		rest = "/"
	}
	for _, rule := range rules {
		if !slices.Contains(rule.Methods, method) {
			continue
		}
		for _, p := range rule.Paths {
			if globMatch(p, rest) {
				return p, true
			}
		}
	}
	return "", false
}

// globMatch matches canonical paths segment by segment: * is exactly one
// segment, a final ** one or more.
func globMatch(pattern, path string) bool {
	ps := strings.Split(pattern, "/")
	xs := strings.Split(path, "/")
	for i, p := range ps {
		if p == "**" {
			return len(xs) > i
		}
		if i >= len(xs) || (p != "*" && p != xs[i]) || (p == "*" && xs[i] == "") {
			return false
		}
	}
	return len(ps) == len(xs)
}
