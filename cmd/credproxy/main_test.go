package main

import (
	"os"
	"strings"
	"testing"
)

func pipeWith(t *testing.T, s string) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() { w.WriteString(s); w.Close() }()
	t.Cleanup(func() { r.Close() })
	return r
}

// A piped secret, such as an SA JSON file, is read whole, minus the final
// newline.
func TestReadSecretFromPipe(t *testing.T) {
	got, err := readSecret(pipeWith(t, "{\n  \"type\": \"service_account\"\n}\n"), "")
	if err != nil || string(got) != "{\n  \"type\": \"service_account\"\n}" {
		t.Fatalf("readSecret = %q, %v", got, err)
	}
}

func TestShortSecretRefused(t *testing.T) {
	_, err := readSecret(pipeWith(t, "short\n"), "")
	if err == nil || !strings.Contains(err.Error(), "16") {
		t.Fatalf("short secret accepted: %v", err)
	}
}
