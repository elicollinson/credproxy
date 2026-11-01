package keychain

import (
	"strings"
	"testing"
)

// R18: the test binary is only ad-hoc signed by the linker, so key set
// would pin items to a throwaway cdhash. CheckSigned must say no.
func TestCheckSignedRefusesAdHoc(t *testing.T) {
	err := CheckSigned()
	if err == nil || !strings.Contains(err.Error(), "make") {
		t.Fatalf("CheckSigned() = %v", err)
	}
}

func TestReasonIsFixed(t *testing.T) {
	for err, want := range map[error]string{ErrLocked: "keychain_locked", ErrNotFound: "credential_missing", ErrDenied: "keychain_denied"} {
		if got := Reason(err); got != want {
			t.Errorf("Reason(%v) = %q", err, got)
		}
	}
	if got := Reason(errSentinel("OSStatus -1 with detail")); got != "keychain_error" {
		t.Errorf("unknown error reason = %q", got)
	}
}

type errSentinel string

func (e errSentinel) Error() string { return string(e) }
