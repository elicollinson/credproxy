// Package config loads credproxy's JSON config and validates it strictly:
// unknown fields, trailing data and any invalid value stop startup.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"syscall"
)

type Config struct {
	Listen []string `json:"listen"`
	// HostAliases are extra Host header values to accept, such as
	// "host.docker.internal:8787" for containers.
	HostAliases      []string           `json:"host_aliases"`
	AllowNonLoopback bool               `json:"allow_non_loopback"`
	MaxBodyBytes     int64              `json:"max_body_bytes"`
	Routes           map[string]*Route  `json:"routes"`
	Callers          map[string]*Caller `json:"callers"`

	// Warnings are problems worth logging that don't stop startup.
	Warnings []string `json:"-"`
}

type Route struct {
	Upstream           string     `json:"upstream"`
	Credential         Credential `json:"credential"`
	Inject             Inject     `json:"inject"`
	CallerAuth         []string   `json:"caller_auth"`
	WebSocket          bool       `json:"websocket"`
	MaxBodyBytes       int64      `json:"max_body_bytes"`
	FirstByteTimeoutMS int        `json:"first_byte_timeout_ms"`
	Allow              []Rule     `json:"allow"`

	// Set by validation.
	Name  string   `json:"-"`
	Base  *url.URL `json:"-"`
	Slots []Slot   `json:"-"`
	// StripHeaders and StripParams are the route's own credential slots,
	// removed from every request on top of the global list (R6). Params are
	// lowercase and matched without case.
	StripHeaders []string `json:"-"`
	StripParams  []string `json:"-"`
}

type Credential struct {
	Service string `json:"service"`
	Account string `json:"account"`
}

type Inject struct {
	Type     string   `json:"type"`
	Name     string   `json:"name"`
	Username string   `json:"username"`
	Scopes   []string `json:"scopes"`
}

type Rule struct {
	Methods []string `json:"methods"`
	Paths   []string `json:"paths"`
}

type Caller struct {
	TokenSHA256     string   `json:"token_sha256"`
	Routes          []string `json:"routes"`
	RateLimitPerMin int      `json:"rate_limit_per_min"`

	// Set by validation.
	Name string   `json:"-"`
	Hash [32]byte `json:"-"`
}

// SlotKind is where a caller may put its token on a route.
type SlotKind string

const (
	SlotBearer        SlotKind = "bearer"
	SlotBasicPassword SlotKind = "basic_password"
	SlotHeader        SlotKind = "header"
	SlotQuery         SlotKind = "query"
)

type Slot struct {
	Kind SlotKind
	Name string // header or query parameter name
}

// Parse decodes and validates a config. The error lists every problem found.
func Parse(data []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("config: trailing data after the top-level object")
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Load reads the config at path, refusing a file that anyone but its owner
// can read or write, or that the current user doesn't own. It also returns
// the file's SHA-256, for the startup log.
func Load(path string) (*Config, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return nil, "", fmt.Errorf("config: %s must be owned by the current user", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, "", fmt.Errorf("config: %s is mode %o; it must be 0600 or stricter", path, info.Mode().Perm())
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, "", err
	}
	c, err := Parse(data)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	return c, hex.EncodeToString(sum[:]), nil
}
