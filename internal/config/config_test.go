package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// valid is a minimal good config; each case below breaks one thing in it.
const valid = `{
  "routes": {
    "openrouter": {
      "upstream": "https://openrouter.ai/api/v1",
      "credential": {"account": "openrouter"},
      "inject": {"type": "bearer"},
      "allow": [{"methods": ["POST"], "paths": ["/chat/completions", "/files/*", "/deep/**"]}]
    }
  },
  "callers": {
    "node": {"token_sha256": "` + hashA + `", "routes": ["openrouter"]}
  }
}`

func TestValidConfigGetsDefaults(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Listen; len(got) != 1 || got[0] != "127.0.0.1:8787" {
		t.Errorf("listen default = %v", got)
	}
	if c.MaxBodyBytes != 32<<20 {
		t.Errorf("max_body_bytes default = %d", c.MaxBodyBytes)
	}
	r := c.Routes["openrouter"]
	if r.Credential.Service != "credproxy" {
		t.Errorf("credential.service default = %q", r.Credential.Service)
	}
	if len(r.Slots) != 1 || r.Slots[0].Kind != SlotBearer {
		t.Errorf("caller_auth default = %+v", r.Slots)
	}
	if r.Base.Host != "openrouter.ai" || r.Base.Path != "/api/v1" || r.Name != "openrouter" {
		t.Errorf("base = %v, name = %q", r.Base, r.Name)
	}
	if r.MaxBodyBytes != 32<<20 {
		t.Errorf("route max_body_bytes inherits: got %d", r.MaxBodyBytes)
	}
	k := c.Callers["node"]
	if k.RateLimitPerMin != 60 || k.Name != "node" || k.Hash[0] != 0xaa {
		t.Errorf("caller = %+v", k)
	}
}

// T18: every invalid field is rejected, naming the field.
func TestInvalidConfigRejected(t *testing.T) {
	cases := []struct {
		name, from, to, want string
	}{
		{"unknown top-level field", `"routes": {`, `"extra": 1, "routes": {`, "unknown field"},
		{"unknown route field", `"inject": {"type": "bearer"},`, `"inject": {"type": "bearer"}, "hosts": [],`, "unknown field"},
		{"wildcard listener without opt-in", `"routes": {`, `"listen": ["0.0.0.0:8787"], "routes": {`, "listen"},
		{"listener by name", `"routes": {`, `"listen": ["localhost:8787"], "routes": {`, "listen"},
		{"bad route name", `"openrouter": {`, `"Open_Router": {`, "routes.Open_Router"},
		{"http upstream", `https://openrouter.ai`, `http://openrouter.ai`, "routes.openrouter.upstream"},
		{"upstream with query", `/api/v1"`, `/api/v1?x=1"`, "routes.openrouter.upstream"},
		{"upstream with userinfo", `https://openrouter.ai`, `https://u:p@openrouter.ai`, "routes.openrouter.upstream"},
		{"upstream IP literal", `https://openrouter.ai`, `https://127.0.0.1`, "routes.openrouter.upstream"},
		{"upstream trailing slash", `/api/v1"`, `/api/v1/"`, "routes.openrouter.upstream"},
		{"upstream traversal", `/api/v1"`, `/api/../v1"`, "routes.openrouter.upstream"},
		{"missing account", `{"account": "openrouter"}`, `{}`, "routes.openrouter.credential.account"},
		{"unknown inject type", `{"type": "bearer"}`, `{"type": "sigv4"}`, "routes.openrouter.inject.type"},
		{"header inject without name", `{"type": "bearer"}`, `{"type": "header"}`, "routes.openrouter.inject.name"},
		{"header inject on Host", `{"type": "bearer"}`, `{"type": "header", "name": "Host"}`, "routes.openrouter.inject.name"},
		{"basic without username", `{"type": "bearer"}`, `{"type": "basic"}`, "routes.openrouter.inject.username"},
		{"query without name", `{"type": "bearer"}`, `{"type": "query"}`, "routes.openrouter.inject.name"},
		{"service account without scopes", `{"type": "bearer"}`, `{"type": "google_service_account"}`, "routes.openrouter.inject.scopes"},
		{"service account foreign scope", `{"type": "bearer"}`, `{"type": "google_service_account", "scopes": ["https://evil.example/x"]}`, "routes.openrouter.inject.scopes"},
		{"name on bearer", `{"type": "bearer"}`, `{"type": "bearer", "name": "X"}`, "routes.openrouter.inject"},
		{"unknown caller slot", `"inject": {"type": "bearer"},`, `"inject": {"type": "bearer"}, "caller_auth": ["cookie"],`, "routes.openrouter.caller_auth"},
		{"cookie header slot", `"inject": {"type": "bearer"},`, `"inject": {"type": "bearer"}, "caller_auth": ["header:Cookie"],`, "routes.openrouter.caller_auth"},
		{"empty allow", `"allow": [{"methods": ["POST"], "paths": ["/chat/completions", "/files/*", "/deep/**"]}]`, `"allow": []`, "routes.openrouter.allow"},
		{"lowercase method", `["POST"]`, `["post"]`, "routes.openrouter.allow[0].methods"},
		{"unsupported method", `["POST"]`, `["TRACE"]`, "routes.openrouter.allow[0].methods"},
		{"non-canonical rule path", `"/chat/completions"`, `"/chat/../completions"`, "routes.openrouter.allow[0].paths"},
		{"relative rule path", `"/chat/completions"`, `"chat/completions"`, "routes.openrouter.allow[0].paths"},
		{"partial glob segment", `"/files/*"`, `"/files/a*"`, "routes.openrouter.allow[0].paths"},
		{"double glob not last", `"/deep/**"`, `"/deep/**/x"`, "routes.openrouter.allow[0].paths"},
		{"negative body limit", `"inject": {"type": "bearer"},`, `"inject": {"type": "bearer"}, "max_body_bytes": -1,`, "routes.openrouter.max_body_bytes"},
		{"short token hash", hashA, "abc", "callers.node.token_sha256"},
		{"uppercase token hash", hashA, strings.ToUpper(hashA), "callers.node.token_sha256"},
		{"unknown caller route", `"routes": ["openrouter"]`, `"routes": ["openrouter", "brave"]`, "callers.node.routes"},
		{"no caller routes", `"routes": ["openrouter"]`, `"routes": []`, "callers.node.routes"},
		{"rate limit too high", `"routes": ["openrouter"]}`, `"routes": ["openrouter"], "rate_limit_per_min": 100000}`, "callers.node.rate_limit_per_min"},
		{"duplicate token", `"routes": ["openrouter"]}`, `"routes": ["openrouter"]}, "other": {"token_sha256": "` + hashA + `", "routes": ["openrouter"]}`, "token_sha256"},
		{"trailing data", `}
}`, `}
} {}`, "trailing data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(valid, tc.from) {
				t.Fatalf("test setup: %q not in base config", tc.from)
			}
			_, err := Parse([]byte(strings.Replace(valid, tc.from, tc.to, 1)))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestNonLoopbackListenerNeedsOptInAndWarns(t *testing.T) {
	c, err := Parse([]byte(strings.Replace(valid, `"routes": {`, `"listen": ["0.0.0.0:8787"], "allow_non_loopback": true, "routes": {`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Warnings) == 0 {
		t.Fatal("no warning for a non-loopback listener")
	}
}

func TestUnusedRouteWarns(t *testing.T) {
	cfg := strings.Replace(valid, `"routes": {`, `"routes": {
    "spare": {"upstream": "https://api.github.com", "credential": {"account": "gh"}, "inject": {"type": "bearer"}, "allow": [{"methods": ["GET"], "paths": ["/user"]}]},`, 1)
	c, err := Parse([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "spare") {
		t.Fatalf("warnings = %v", c.Warnings)
	}
}

func TestCallerSlotsParse(t *testing.T) {
	cfg := strings.Replace(valid, `"inject": {"type": "bearer"},`, `"inject": {"type": "bearer"}, "caller_auth": ["bearer", "basic_password", "header:X-Subscription-Token", "query:key"],`, 1)
	c, err := Parse([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	want := []Slot{{SlotBearer, ""}, {SlotBasicPassword, ""}, {SlotHeader, "X-Subscription-Token"}, {SlotQuery, "key"}}
	got := c.Routes["openrouter"].Slots
	if len(got) != len(want) {
		t.Fatalf("slots = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("slot %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestLoadRefusesLooseFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("mode 0644 accepted: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	_, sum, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum) != 64 {
		t.Fatalf("config hash = %q", sum)
	}
}

func TestCanonicalPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/":             true,
		"/a/b":          true,
		"/v1/m:gen":     true,
		"/a/b/":         false,
		"//a":           false,
		"/a/./b":        false,
		"/a/../b":       false,
		"/a/b.":         false,
		"/a/.":          false,
		"/a\\b":         false,
		"/a;b":          false,
		"a/b":           false,
		"":              false,
		"/a/b/../../..": false,
	} {
		if got := CanonicalPath(p); got != want {
			t.Errorf("CanonicalPath(%q) = %v, want %v", p, got, want)
		}
	}
}
