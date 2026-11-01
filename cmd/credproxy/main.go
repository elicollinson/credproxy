// Command credproxy is a local reverse proxy that injects API credentials
// from the macOS Keychain, so the services behind it never hold real keys.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/elicollinson/credproxy/internal/config"
	"github.com/elicollinson/credproxy/internal/keychain"
	"github.com/elicollinson/credproxy/internal/proxy"
)

const usage = `usage:
  credproxy serve [-config path]         run the proxy
  credproxy config check [-config path]  validate the config and exit
  credproxy token new <caller>           make a caller token and print its hash
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "credproxy:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	switch {
	case len(args) >= 1 && args[0] == "serve":
		return serve(args[1:])
	case len(args) >= 2 && args[0] == "config" && args[1] == "check":
		cfg, sum, err := load(args[2:])
		if err != nil {
			return err
		}
		// Building the proxy catches what validation alone can't, such as an
		// inject type this build doesn't implement.
		if _, err := proxy.New(cfg, keychain.System(), proxy.Options{}); err != nil {
			return err
		}
		for _, w := range cfg.Warnings {
			fmt.Println("warning:", w)
		}
		fmt.Printf("ok: %d routes, %d callers, sha256 %s\n", len(cfg.Routes), len(cfg.Callers), sum)
		return nil
	case len(args) == 3 && args[0] == "token" && args[1] == "new":
		newToken(args[2])
		return nil
	}
	fmt.Fprint(os.Stderr, usage)
	return errors.New("unknown command")
}

func load(args []string) (*config.Config, string, error) {
	home, _ := os.UserHomeDir()
	fs := flag.NewFlagSet("credproxy", flag.ContinueOnError)
	path := fs.String("config", filepath.Join(home, ".config", "credproxy", "config.json"), "config file")
	if err := fs.Parse(args); err != nil {
		return nil, "", err
	}
	return config.Load(*path)
}

func serve(args []string) error {
	cfg, sum, err := load(args)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	p, err := proxy.New(cfg, keychain.System(), proxy.Options{Log: logger})
	if err != nil {
		return err
	}
	logger.Info("start", "config_sha256", sum, "listen", cfg.Listen)
	for _, w := range cfg.Warnings {
		logger.Warn("config", "warning", w)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, len(cfg.Listen))
	var servers []*http.Server
	for _, addr := range cfg.Listen {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		srv := p.Server(addr)
		servers = append(servers, srv)
		go func() { errc <- srv.Serve(ln) }()
	}
	select {
	case err = <-errc:
	case <-ctx.Done():
	}
	// Open streams get a moment to finish; launchd kills us soon after anyway.
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		srv.Shutdown(shutdown)
	}
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

// newToken prints a fresh caller token once, with the hash for the config.
// Nothing is stored.
func newToken(caller string) {
	b := make([]byte, 32)
	rand.Read(b)
	token := "cpx_" + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	fmt.Printf("token for %s (shown once; give it to the service):\n  %s\n\n", caller, token)
	fmt.Printf("add to callers.%s in the config:\n  \"token_sha256\": \"%s\"\n", caller, hex.EncodeToString(sum[:]))
}
