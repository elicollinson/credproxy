package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/elicollinson/credproxy/internal/config"
)

// logRequest writes one line per request with only these fields (R10): no
// URL, query, header or body, and the allowlist pattern instead of the path.
func (p *Proxy) logRequest(st *state, rec *recorder, latency time.Duration) {
	if st.upgraded && rec.status == 0 {
		rec.status = http.StatusSwitchingProtocols
	}
	attrs := []slog.Attr{
		slog.String("caller", st.caller),
		slog.String("route", st.route),
		slog.String("method", st.method),
		slog.String("path_template", st.template),
		slog.Int("status", rec.status),
		slog.Int64("latency_ms", latency.Milliseconds()),
		slog.Int64("bytes_in", st.bytesIn.n),
		slog.Int64("bytes_out", rec.bytes+st.upgradedOut.Load()),
	}
	level := slog.LevelInfo
	if st.reason != "" {
		attrs = append(attrs, slog.String("reason", st.reason))
	}
	if st.echoed {
		attrs = append(attrs, slog.String("alert", "upstream_echoed_secret"))
		level = slog.LevelWarn
	}
	p.log.LogAttrs(context.Background(), level, "request", attrs...)
}

// logMethod keeps arbitrary method strings, which the caller controls, out
// of the log.
func logMethod(m string) string {
	if slices.Contains(config.Methods, m) {
		return m
	}
	return "OTHER"
}

// serverErrors logs that net/http hit an error, without its text.
type serverErrors struct{ log *slog.Logger }

func (s serverErrors) Write(b []byte) (int, error) {
	s.log.Warn("server", slog.String("reason", "http_server_error"))
	return len(b), nil
}

// recorder notes the status and size of a response. Unwrap lets
// http.ResponseController reach Flush and Hijack underneath.
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 && (code >= 200 || code == http.StatusSwitchingProtocols) {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

type countingReader struct {
	r io.ReadCloser
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingReader) Close() error { return c.r.Close() }
