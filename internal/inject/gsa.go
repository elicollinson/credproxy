package inject

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/elicollinson/credproxy/internal/config"
	"github.com/elicollinson/credproxy/internal/keychain"
)

// tokenURI is the only endpoint we send a signed assertion to (R16). An SA
// JSON naming another one is refused rather than trusted.
const tokenURI = "https://oauth2.googleapis.com/token"

// serviceAccount exchanges a Google service account key for an access
// token, and caches the token until 5 minutes before it expires. The SA JSON
// is read from the Keychain only when minting.
type serviceAccount struct {
	cred  config.Credential
	scope string
	env   Env

	mu      sync.Mutex // held while minting, so concurrent requests mint once
	token   string
	expires time.Time
}

func (sa *serviceAccount) Acquire(ctx context.Context, store keychain.Store) (Cred, error) {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	if sa.token == "" || !sa.env.Now().Before(sa.expires.Add(-5*time.Minute)) {
		if err := sa.mint(ctx, store); err != nil {
			return Cred{}, err
		}
	}
	return Cred{Header: "Authorization", Value: "Bearer " + sa.token, Needles: []string{sa.token}}, nil
}

func (sa *serviceAccount) mint(ctx context.Context, store keychain.Store) error {
	raw, err := store.Get(sa.cred.Service, sa.cred.Account)
	if err != nil {
		return err
	}
	var key struct {
		ClientEmail  string `json:"client_email"`
		PrivateKey   string `json:"private_key"`
		PrivateKeyID string `json:"private_key_id"`
		TokenURI     string `json:"token_uri"`
	}
	err = json.Unmarshal(raw, &key)
	clear(raw)
	if err != nil || key.TokenURI != tokenURI || key.ClientEmail == "" {
		return ErrInvalid
	}
	block, _ := pem.Decode([]byte(key.PrivateKey))
	if block == nil {
		return ErrInvalid
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if err != nil || !ok {
		return ErrInvalid
	}

	now := sa.env.Now()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signing := enc(map[string]string{"alg": "RS256", "typ": "JWT", "kid": key.PrivateKeyID}) + "." +
		enc(map[string]any{"iss": key.ClientEmail, "scope": sa.scope, "aud": tokenURI, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(nil, rsaKey, crypto.SHA256, sum[:])
	if err != nil {
		return ErrInvalid
	}

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signing + "." + base64.RawURLEncoding.EncodeToString(sig)},
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", tokenURI, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := sa.env.Client.Do(req)
	if err != nil {
		return ErrMint
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrMint, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&tok); err != nil || tok.AccessToken == "" || tok.ExpiresIn <= 0 {
		return ErrMint
	}
	sa.token, sa.expires = tok.AccessToken, now.Add(time.Duration(tok.ExpiresIn)*time.Second)
	return nil
}
