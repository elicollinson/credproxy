// Package keychain reads and writes upstream credentials in the macOS
// Keychain. The Store interface lets tests use an in-memory one.
package keychain

import "errors"

var (
	ErrNotFound = errors.New("keychain: item not found")
	ErrLocked   = errors.New("keychain: keychain is locked")
	ErrDenied   = errors.New("keychain: access denied")
)

// Store returns the secret stored under service and account. The caller
// owns the returned slice and should clear it after use.
type Store interface {
	Get(service, account string) ([]byte, error)
}

// Reason names a Get failure for responses, logs and key check. It is one
// of a fixed set, so it never carries error text.
func Reason(err error) string {
	switch {
	case errors.Is(err, ErrLocked):
		return "keychain_locked"
	case errors.Is(err, ErrNotFound):
		return "credential_missing"
	case errors.Is(err, ErrDenied):
		return "keychain_denied"
	}
	return "keychain_error"
}
