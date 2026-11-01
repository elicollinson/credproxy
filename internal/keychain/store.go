// Package keychain reads upstream credentials. The interface lets tests use
// an in-memory store; the macOS Keychain implementation lands in Phase 3.
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

// System is the login Keychain.
func System() Store { return unavailable{} }

type unavailable struct{}

func (unavailable) Get(string, string) ([]byte, error) {
	return nil, errors.New("keychain: not implemented until Phase 3")
}
