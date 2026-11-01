//go:build keychain_integration

package main

// T20 runs against the real Keychain service, so it is not in the default
// run or in CI. It needs a signing identity:
//
//	make test-keychain SIGN_IDENTITY="credproxy-signing"
//
// Every item goes in a throwaway keychain file, never the login keychain.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const t20Secret = "t20-secret-0123456789abcdef"

// build makes a signed binary with the Makefile's own recipe. buildID
// changes the binary, and so its cdhash, without changing its code.
func build(t *testing.T, out, buildID string) {
	t.Helper()
	cmd := exec.Command("make", "-C", "../..", "build", "BIN="+out, "GOBUILDFLAGS=-ldflags=-buildid="+buildID)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make build: %v\n%s", err, b)
	}
}

func cdhash(t *testing.T, bin string) string {
	t.Helper()
	b, _ := exec.Command("codesign", "-dvvv", bin).CombinedOutput()
	m := regexp.MustCompile(`CDHash=(\w+)`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("no CDHash in codesign output:\n%s", b)
	}
	return string(m[1])
}

func credproxy(t *testing.T, bin, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(stdin)
	b, err := cmd.CombinedOutput()
	return string(b), err
}

func TestKeychainRoundTrip(t *testing.T) {
	if os.Getenv("SIGN_IDENTITY") == "" {
		t.Skip("SIGN_IDENTITY not set")
	}
	dir := t.TempDir()
	kc := filepath.Join(dir, "t20.keychain-db")
	// security(1) only creates and deletes the throwaway keychain; no
	// secret is read through it.
	if b, err := exec.Command("security", "create-keychain", "-p", "t20", kc).CombinedOutput(); err != nil {
		t.Fatalf("create-keychain: %v %s", err, b)
	}
	t.Cleanup(func() { exec.Command("security", "delete-keychain", kc).Run() })
	exec.Command("security", "set-keychain-settings", kc).Run() // no auto-lock mid-test

	cfg := filepath.Join(dir, "config.json")
	os.WriteFile(cfg, []byte(`{"routes": {"t20": {"upstream": "https://example.com", "credential": {"account": "t20"},
	  "inject": {"type": "bearer"}, "allow": [{"methods": ["GET"], "paths": ["/x"]}]}}, "callers": {}}`), 0o600)

	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	build(t, a, "t20-a")
	build(t, b, "t20-b")
	if cdhash(t, a) == cdhash(t, b) {
		t.Fatal("the two builds have the same cdhash, so the rebuild check proves nothing")
	}

	if out, err := credproxy(t, a, "short\n", "key", "set", "-keychain", kc, "t20"); err == nil {
		t.Fatalf("short secret stored: %s", out)
	}
	if out, err := credproxy(t, a, t20Secret+"\n", "key", "set", "-keychain", kc, "t20"); err != nil {
		t.Fatalf("key set: %v %s", err, out)
	}
	out, err := credproxy(t, a, "", "key", "list", "-keychain", kc)
	if err != nil || strings.TrimSpace(out) != "t20" {
		t.Fatalf("key list = %q, %v", out, err)
	}

	// Prompts are off in key check, so a read the ACL or partition list
	// would have asked about fails as keychain_denied instead of passing.
	for _, bin := range []string{a, b} {
		out, err = credproxy(t, bin, "", "key", "check", "-config", cfg, "-keychain", kc)
		if err != nil || !strings.Contains(out, "ok") {
			t.Fatalf("%s key check (rebuilt binary must read with no prompt): %v\n%s", filepath.Base(bin), err, out)
		}
	}
	for _, s := range []string{out} {
		if strings.Contains(s, t20Secret) {
			t.Fatal("key check printed the secret")
		}
	}

	if out, err := credproxy(t, b, "", "key", "rm", "-keychain", kc, "t20"); err != nil {
		t.Fatalf("key rm: %v %s", err, out)
	}
	out, _ = credproxy(t, a, "", "key", "check", "-config", cfg, "-keychain", kc)
	if !strings.Contains(out, "credential_missing") {
		t.Fatalf("after rm, key check = %s", out)
	}
}
